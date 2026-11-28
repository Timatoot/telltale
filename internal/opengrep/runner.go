package opengrep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/report"
)

const fixture = "selftest_fixture.py"

// SinkAnalyzer stages its assets under RunDir. Verify callers supply the
// same private run directory used for ingest. An empty RunDir uses TMPDIR.
type SinkAnalyzer struct{ RunDir string }

// FatalError signals an execution failure to the CLI.
type FatalError struct{ cause error }

func (e *FatalError) Error() string { return "opengrep: " + e.cause.Error() }
func (e *FatalError) Unwrap() error { return e.cause }
func (e *FatalError) ExitCode() int { return 2 }

const number = "(0|[1-9][0-9]*)"
const identifier = "(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"

var semver = regexp.MustCompile("^" + number + "\\." + number + "\\." + number + "(?:-(" + identifier + "(?:\\." + identifier + ")*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$")

func supported(version string) bool {
	m := semver.FindStringSubmatch(version)
	return m != nil && m[1] == "2" && (m[2] != "0" || m[3] != "0" || m[4] == "")
}

func (a SinkAnalyzer) Preflight(ctx context.Context) (_ string, err error) {
	stage, err := a.stage()
	if err != nil {
		return "", &FatalError{err}
	}
	defer finishStage(stage, &err)
	data, err := command(ctx, stage, 4096, false, "--version")
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(data))
	if !supported(version) {
		return "", errors.New("expected Opengrep version >= 2.0.0 and < 3.0.0")
	}
	target := filepath.Join(stage, "fixture")
	if err := os.Mkdir(target, 0o700); err != nil {
		return "", err
	}
	contents, err := assets.ReadFile(fixture)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(target, fixture), contents, 0o600); err != nil {
		return "", err
	}
	data, err = scan(ctx, stage, target, false)
	if err != nil {
		return "", err
	}
	result, err := parseScan(data, []string{fixture}, func(path string) (string, bool) {
		return fixture, path == fixture || path == filepath.Join(target, fixture)
	})
	if err != nil {
		return "", err
	}
	if len(result.FilesSkipped) != 0 || len(result.ParseErrors) != 0 {
		return "", errors.New("preflight fixture scan incomplete")
	}
	return version, nil
}

func (a SinkAnalyzer) Analyze(ctx context.Context, snapshot *ingest.Snapshot) (_ Result, err error) {
	stage, err := a.stage()
	if err != nil {
		return Result{}, &FatalError{err}
	}
	defer finishStage(stage, &err)
	data, err := scan(ctx, stage, snapshot.Dir(), true)
	if err != nil {
		return Result{}, err
	}
	return parseScan(data, snapshot.Files, snapshot.RepoRelPath)
}

func finishStage(stage string, err *error) {
	if cause := errors.Join(*err, os.RemoveAll(stage)); cause != nil {
		*err = &FatalError{cause}
	}
}

func (a SinkAnalyzer) stage() (string, error) {
	parent := a.RunDir
	if parent == "" {
		parent = os.TempDir()
	}
	parent, err := filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(parent, "telltale-opengrep-*")
	if err != nil {
		return "", err
	}
	rules, err := fs.Sub(assets, "rules")
	if err == nil {
		err = os.CopyFS(filepath.Join(stage, "rules"), rules)
	}
	if err != nil {
		return "", errors.Join(err, os.RemoveAll(stage))
	}
	return stage, nil
}

func scan(ctx context.Context, stage, target string, partial bool) ([]byte, error) {
	return command(ctx, stage, 64<<20, partial, "scan", "--config", filepath.Join(stage, "rules"),
		"--json", "--quiet", "--disable-nosem", "--max-target-bytes", "1048576", "--timeout", "30",
		"--project-root", target, target)
}

func command(ctx context.Context, stage string, limit int, partial bool, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "opengrep", args...)
	cmd.Dir = stage
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	stdout := limitedOutput{limit: limit, cancel: cancel}
	var stderr diagnosticTail
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if stdout.overflow {
		return nil, fmt.Errorf("stdout exceeds %d bytes", limit)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var exit *exec.ExitError
	if err != nil && (!partial || !errors.As(err, &exit) || exit.ExitCode() != 3) {
		return nil, fmt.Errorf("run %s: %w (%s)", args[0], err, report.Sanitize(stderr.String(), "", 4096))
	}
	return stdout.buf.Bytes(), nil
}

type limitedOutput struct {
	buf      bytes.Buffer
	limit    int
	cancel   context.CancelFunc
	overflow bool
}

func (o *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > o.limit-o.buf.Len() {
		o.overflow = true
		o.cancel()
		return 0, errors.New("stdout overflow")
	}
	return o.buf.Write(p)
}

// diagnosticTail retains only the last 4 KiB, even for chatty engine failures.
type diagnosticTail struct {
	data       [4096]byte
	next, size int
}

func (t *diagnosticTail) Write(p []byte) (int, error) {
	n := len(p)
	if n >= len(t.data) {
		p = p[n-len(t.data):]
	}
	first := copy(t.data[t.next:], p)
	copy(t.data[:], p[first:])
	t.next = (t.next + len(p)) % len(t.data)
	t.size = min(len(t.data), t.size+len(p))
	return n, nil
}
func (t *diagnosticTail) String() string {
	if t.size < len(t.data) {
		return string(t.data[:t.size])
	}
	return string(t.data[t.next:]) + string(t.data[:t.next])
}
