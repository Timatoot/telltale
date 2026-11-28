package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/Timatoot/telltale/internal/config"
	"github.com/Timatoot/telltale/internal/extract/python"
	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/opengrep"
	"github.com/Timatoot/telltale/internal/report"
	"github.com/Timatoot/telltale/internal/rules"
	"github.com/Timatoot/telltale/internal/sandbox"
	"github.com/Timatoot/telltale/internal/verify"
)

const (
	exitPass       = 0
	exitFatalError = 2
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == guardArg {
		os.Exit(cleanupGuardMain())
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runAudit(args, stdout, stderr, opengrep.SinkAnalyzer{}, verify.Podman{})
}

type sinkAnalyzer interface {
	Preflight(context.Context) (string, error)
	Analyze(context.Context, *ingest.Snapshot) (opengrep.Result, error)
}

func runAudit(args []string, stdout, stderr io.Writer, analyzer sinkAnalyzer, runtime verify.Runtime) int {
	cfg, err := config.Parse(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}

	var output auditOutput
	if cfg.Verify {
		if _, ok := runtime.(verify.Podman); ok {
			runtime = verify.Podman{ContainerRuntime: sandbox.ContainerRuntime{Image: cfg.Image}}
		}
		output, err = prepareVerify(cfg, analyzer, runtime, cfg.NoColor || !terminalOutput(stdout))
	} else {
		output, err = prepareAudit(context.Background(), cfg, analyzer, cfg.NoColor || !terminalOutput(stdout), nil)
	}
	if err == nil {
		err = publish(output.artifacts, func() error {
			_, err := stdout.Write(output.terminal)
			return err
		})
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "telltale: %s\n", report.Sanitize(err.Error(), "", 4096))
		return exitFatalError
	}
	return output.code
}

func prepareVerify(cfg config.Config, analyzer sinkAnalyzer, runtime verify.Runtime, noColor bool) (_ auditOutput, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	abort := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-done:
			return
		}
		select {
		case <-signals:
			close(abort)
		case <-done:
		}
	}()
	guard, err := startCleanupGuard(ctx)
	if err != nil {
		return auditOutput{}, err
	}
	defer func() { err = errors.Join(err, guard.close()) }()
	info, err := runtime.Preflight(ctx)
	if err != nil {
		return auditOutput{}, err
	}
	if _, err := guard.owner.Write([]byte{'A'}); err != nil {
		return auditOutput{}, err
	}
	if _, ok := analyzer.(opengrep.SinkAnalyzer); ok {
		analyzer = opengrep.SinkAnalyzer{RunDir: guard.Dir}
	}
	orchestrator := verify.Orchestrator{Runtime: runtime, Info: info, RunID: guard.ID, RunDir: guard.Dir, Abort: abort}
	return prepareAudit(ctx, cfg, analyzer, noColor, &orchestrator)
}

func terminalOutput(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

type auditOutput struct {
	code      int
	terminal  []byte
	artifacts []artifact
}

// Finish rendering and close the snapshot before publishing any results.
func prepareAudit(ctx context.Context, cfg config.Config, analyzer sinkAnalyzer, noColor bool, orchestrator *verify.Orchestrator) (_ auditOutput, err error) {
	repoName, err := repositoryName(cfg.RepoPath)
	if err != nil {
		return auditOutput{}, err
	}
	version, err := analyzer.Preflight(ctx)
	if err != nil {
		return auditOutput{}, err
	}
	parent := ""
	if orchestrator != nil {
		parent = orchestrator.RunDir
	}
	snap, err := ingest.CreateSnapshot(ctx, cfg.RepoPath, parent)
	if err != nil {
		return auditOutput{}, err
	}
	defer func() { err = errors.Join(err, snap.Close()) }()
	sinks, err := analyzer.Analyze(ctx, snap)
	if err != nil {
		return auditOutput{}, err
	}
	result, err := python.ExtractWithMatches(ctx, snap, sinks.Matches)
	if err != nil {
		return auditOutput{}, err
	}
	eval := rules.Evaluate(result.Tools, result.Matches, cfg.Verify)
	scan := model.ScanReport{
		Target:        model.Target{RepoName: repoName, Mode: "static"},
		SchemaVersion: model.SchemaVersion,
		Tool:          model.Tool{Name: "telltale", Version: "dev", RuntimeBackend: "none", OpengrepVersion: version},
		Inventory:     eval.Inventory, Findings: eval.Findings,
		Coverage: model.Coverage{
			FilesScanned: len(snap.Files) - len(sinks.FilesSkipped), FilesSkipped: slices.Concat(snap.FilesSkipped, sinks.FilesSkipped),
			ToolsDiscovered: len(result.Tools), ParseErrors: slices.Concat(result.ParseErrors, sinks.ParseErrors),
			UnresolvedDescriptions:  result.UnresolvedDescriptions,
			UnresolvedRegistrations: result.UnresolvedRegistrations,
			AnalysisLimits:          model.AnalysisLimits{CrossFileHelperCalls: result.CrossFileHelperCalls},
		},
	}
	token := ""
	if orchestrator != nil {
		scan.Target.Mode = "verify"
		scan.Target.Image = &model.Image{Ref: cfg.Image, ImageID: orchestrator.Info.ImageID()}
		scan.Tool.RuntimeBackend = "podman"
		scan.Tool.RuntimeVersion = &orchestrator.Info.Version
		token, err = orchestrator.Run(ctx, cfg, &scan, eval.Hypotheses)
		if err != nil {
			return auditOutput{}, err
		}
	}
	scan.ApplyPolicy(model.Policy{FailOn: model.Severity(cfg.FailOn), VerifiedOnly: cfg.VerifiedOnly, Strict: cfg.Strict, Verify: cfg.Verify})
	out := auditOutput{code: scan.Summary.AnalysisExitCode}
	out.terminal, err = report.RenderTerminal(&scan, token, noColor)
	if err != nil {
		return auditOutput{}, err
	}
	for _, format := range []struct {
		name, path string
		render     func(*model.ScanReport, string) ([]byte, error)
	}{
		{"json", cfg.JSONPath, report.RenderJSON},
		{"sarif", cfg.SARIFPath, func(r *model.ScanReport, token string) ([]byte, error) {
			return report.RenderSARIF(r, token, snap.Root().FS())
		}},
		{"html", cfg.HTMLPath, report.RenderHTML},
	} {
		if format.path == "" {
			continue
		}
		data, err := format.render(&scan, token)
		if err != nil {
			return auditOutput{}, fmt.Errorf("render %s report: %w", format.name, err)
		}
		out.artifacts = append(out.artifacts, artifact{name: format.name, path: format.path, data: data})
	}
	return out, nil
}

func repositoryName(repoPath string) (string, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", fmt.Errorf("resolve repository directory: %w", err)
	}
	name := filepath.Base(absPath)
	if name == string(filepath.Separator) {
		// A filesystem root has no directory name to expose in a report.
		name = "."
	}
	return name, nil
}

type artifact struct {
	name, path   string
	data         []byte
	temp, backup string
	published    bool
}

func (a *artifact) stage() error {
	f, err := os.CreateTemp(filepath.Dir(a.path), ".telltale-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	a.temp = f.Name()
	if _, err = f.Write(a.data); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func (a *artifact) replace() error {
	// Link the old directory entry itself, including a symlink, without opening
	// its target. Link is exclusive: a colliding backup is never ours to delete.
	info, err := os.Lstat(a.path)
	switch {
	case err == nil && (info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0):
		backup := a.temp + ".bak"
		if err := os.Link(a.path, backup); err != nil {
			return fmt.Errorf("back up destination: %w", err)
		}
		a.backup = backup
	case err == nil && !info.IsDir():
		return errors.New("destination is a special file")
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("inspect destination: %w", err)
	}
	if err := os.Rename(a.temp, a.path); err != nil {
		return fmt.Errorf("publish staged file: %w", err)
	}
	a.temp = ""
	a.published = true
	return nil
}

func (a *artifact) finish(rollback bool) error {
	var err error
	if rollback && a.published {
		if a.backup != "" {
			// On a restore failure retain the original backup for recovery.
			err = os.Rename(a.backup, a.path)
			a.backup = ""
		} else {
			err = os.Remove(a.path)
		}
	}
	if a.backup != "" {
		err = errors.Join(err, os.Remove(a.backup))
	}
	if a.temp != "" {
		err = errors.Join(err, os.Remove(a.temp))
	}
	return err
}

// Serialize cooperating publishers while their backups are needed. Directory
// locks need no persistent lockfiles and are released when the descriptors close.
func publish(files []artifact, writeTerminal func() error) (err error) {
	seen := make(map[string]bool)
	parentOwner := make(map[string]string)
	var parents []string
	var locked []*os.File
	defer func() {
		for _, dir := range locked {
			_ = dir.Close()
		}
	}()
	defer func() {
		rollback := err != nil
		for i := len(files) - 1; i >= 0; i-- {
			err = errors.Join(err, files[i].finish(rollback))
		}
	}()
	for i := range files {
		a := &files[i]
		dir, name := filepath.Split(a.path)
		if name == "" || name == "." || name == ".." {
			return fmt.Errorf("write %s report: expected a file destination", a.name)
		}
		if dir == "" {
			dir = "."
		}
		// Resolve parent aliases before testing whether two flags name the same entry.
		parent, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return fmt.Errorf("write %s report: resolve directory: %w", a.name, err)
		}
		parent, err = filepath.Abs(parent)
		if err != nil {
			return fmt.Errorf("write %s report: resolve directory: %w", a.name, err)
		}
		a.path = filepath.Join(parent, name)
		if seen[a.path] {
			return errors.New("report destinations must be distinct")
		}
		seen[a.path] = true
		if _, exists := parentOwner[parent]; !exists {
			parentOwner[parent] = a.name
			parents = append(parents, parent)
		}
	}
	slices.Sort(parents)
	for _, parent := range parents {
		f, err := os.Open(parent) //nolint:gosec // User-selected output directory, used only for locking.
		if err != nil {
			return fmt.Errorf("write %s report: open directory: %w", parentOwner[parent], err)
		}
		locked = append(locked, f)
		for {
			err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
			if !errors.Is(err, syscall.EINTR) {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("write %s report: lock directory: %w", parentOwner[parent], err)
		}
	}
	for i := range files {
		if err := files[i].stage(); err != nil {
			return fmt.Errorf("write %s report: %w", files[i].name, err)
		}
	}
	for i := range files {
		if err := files[i].replace(); err != nil {
			return fmt.Errorf("write %s report: %w", files[i].name, err)
		}
	}
	return writeTerminal()
}
