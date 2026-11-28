//go:build integration

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/model"
)

func runIDs(t *testing.T, label string) string {
	t.Helper()
	return podman(t, "ps", "-a", "--no-trunc", "--filter", "label=telltale.run="+label, "--format", "{{.ID}}")
}

func until(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestConmonTimeout(t *testing.T) {
	tag, _ := buildFixtures(t)
	spec := realSpec(t, tag, time.Second, "sleep", "120")
	s := createReal(t, spec)
	// Detached start after the production create and inspection. There is no
	// owner, guard or session timer to remove this container during the check.
	start := time.Now()
	podman(t, "start", s.id)
	if podman(t, "inspect", "--format", "{{.State.Status}}", s.id) != "running" {
		t.Fatal("container did not start")
	}
	until(t, "runtime auto-removal", 17*time.Second, func() bool { return runIDs(t, spec.runID) == "" })
	if time.Since(start) < 9*time.Second {
		t.Fatal("container disappeared before its runtime timeout")
	}
}

// Both shims forward the original argv to real binaries. Marker files let
// the parent withhold an operation without adding test hooks to telltale.
const barrierShim = `#!/usr/bin/python3
import os, sys, time
from pathlib import Path
here = Path(__file__).parent
name = Path(__file__).name
args = sys.argv[1:]
phase = None
if name == "opengrep" and args and args[0] == "scan" and Path(args[-1]).name.startswith("telltale-snapshot-"):
    phase = "snapshot"
elif name == "podman" and args[:1] == ["start"]:
    phase = "created"
elif name == "podman" and args[:1] == ["rm"]:
    phase = "removing"
if phase and (here / ("hold-" + phase)).exists():
    (here / phase).touch()
    limit = time.monotonic() + 120
    while not (here / ("release-" + phase)).exists():
        if time.monotonic() >= limit:
            sys.exit(124)
        time.sleep(.025)
real = (here / ("real-" + name)).resolve()
os.execv(real, [str(real)] + args)
`

type auditProcess struct {
	cmd                                 *exec.Cmd
	bin, tmp, report, dir, label, guard string
	repoFile, repoLabel                 string
	done                                chan struct{}
	err                                 error
	stderr                              bytes.Buffer
}

func startAudit(t *testing.T, exe, tag, mode string, timeout time.Duration, holds ...string) *auditProcess {
	t.Helper()
	a := &auditProcess{bin: t.TempDir(), tmp: t.TempDir(), report: filepath.Join(t.TempDir(), "report.json"), done: make(chan struct{})}
	for _, name := range []string{"podman", "opengrep"} {
		real, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(real, filepath.Join(a.bin, "real-"+name)); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(a.bin, name), []byte(barrierShim), 0o700); err != nil { //nolint:gosec // G306: this test-owned shim must be executable.
			t.Fatal(err)
		}
	}
	for _, hold := range append([]string{"snapshot"}, holds...) {
		writeFixture(t, filepath.Join(a.bin, "hold-"+hold), "")
	}
	repo := t.TempDir()
	writeFixture(t, filepath.Join(repo, "server.py"), "# Synthetic empty inventory\n")
	if mode == "tools/call" || mode == "cache" {
		repo = "../../testdata/fixtures/fs_vuln"
	}
	a.repoFile = filepath.Join(repo, "server.py")
	a.repoLabel = selinuxLabel(t, a.repoFile)
	args := []string{"audit", repo, "--verify", "--image", tag, "--json", a.report, "--timeout", timeout.String(), "--fail-on", "critical"}
	if mode == "budget" {
		args = append(args, "--verify-budget", "8s")
		mode = "hold"
	}
	if mode != "cache" {
		args = append(args, "--run-cmd", "python3 /fixture.py "+mode+" {workspace}")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	a.cmd = exec.CommandContext(ctx, exe, args...)
	a.cmd.Env = append(os.Environ(), "TMPDIR="+a.tmp, "PATH="+a.bin+":"+os.Getenv("PATH"))
	a.cmd.Stderr = &a.stderr
	if err := a.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { a.err = a.cmd.Wait(); close(a.done) }()
	t.Cleanup(func() { cancel(); <-a.done })
	a.waitMarker(t, a.bin, "snapshot")
	runs, _ := filepath.Glob(filepath.Join(a.tmp, "telltale-run-*"))
	if len(runs) != 1 {
		t.Fatalf("expected one run tree: %v", runs)
	}
	a.dir = runs[0]
	snap, _ := filepath.Glob(filepath.Join(a.dir, "telltale-snapshot-*"))
	if len(snap) != 1 {
		t.Fatal("missing ingest snapshot at scan barrier")
	}
	parts := strings.Split(filepath.Base(a.dir), "-")
	if len(parts) != 4 {
		t.Fatal("unexpected run directory name")
	}
	a.label = parts[2]
	// The guard re-execs the audit binary with a private subcommand and
	// setsid. Identify that exact child while its parent is parked.
	children, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", a.cmd.Process.Pid))
	for _, file := range children {
		data, err := os.ReadFile(file) //nolint:gosec // G304: kernel task list under the known audit PID.
		if err != nil {
			continue
		}
		for _, pid := range strings.Fields(string(data)) {
			proc := filepath.Join("/proc", pid)
			args, err := os.ReadFile(filepath.Join(proc, "cmdline")) //nolint:gosec // G304: PID from the kernel child list above.
			if err == nil && string(args) == exe+"\x00__cleanup_guard\x00" {
				a.guard = proc
			}
		}
	}
	if a.guard == "" {
		t.Fatal("live cleanup guard not found")
	}
	return a
}

func (a *auditProcess) waitMarker(t *testing.T, dir, marker string) string {
	t.Helper()
	var path string
	until(t, marker, 90*time.Second, func() bool {
		select {
		case <-a.done:
			t.Fatalf("audit exited before %s: %v %s", marker, a.err, a.stderr.String())
		default:
		}
		files, err := filepath.Glob(filepath.Join(dir, marker))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 1 {
			path = files[0]
			return true
		}
		return false
	})
	return path
}

func (a *auditProcess) release(t *testing.T, phase string) {
	t.Helper()
	writeFixture(t, filepath.Join(a.bin, "release-"+phase), "")
}

func (a *auditProcess) signal(t *testing.T, sig os.Signal) {
	t.Helper()
	if err := a.cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
}

func (a *auditProcess) running(t *testing.T) string {
	t.Helper()
	ready := a.waitMarker(t, a.dir, "fixtures-*/workspace-*/ready")
	id := runIDs(t, a.label)
	if !fullID.MatchString(id) || podman(t, "inspect", "--format", "{{.State.Status}}", id) != "running" {
		t.Fatal("expected one running container")
	}
	return filepath.Dir(ready)
}

func (a *auditProcess) finish(t *testing.T, killed bool) model.ScanReport {
	t.Helper()
	select {
	case <-a.done:
	case <-time.After(70 * time.Second):
		t.Fatal("audit failed to terminate")
	}
	if killed {
		var exit *exec.ExitError
		if !errors.As(a.err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("audit exit: %v", a.err)
		}
	} else if a.err != nil {
		t.Fatalf("audit exit: %v %s", a.err, a.stderr.String())
	}
	until(t, "guard exit, run tree and labeled containers removed", 70*time.Second, func() bool {
		_, err := os.Lstat(a.dir)
		if !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		data, err := os.ReadFile(filepath.Join(a.guard, "status"))
		exited := errors.Is(err, fs.ErrNotExist) || bytes.Contains(data, []byte("\nState:\tZ"))
		return exited && runIDs(t, a.label) == ""
	})
	if selinuxLabel(t, a.repoFile) != a.repoLabel {
		t.Fatal("audit changed the repository SELinux label")
	}
	var report model.ScanReport
	if !killed {
		data, err := os.ReadFile(a.report)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
	}
	return report
}

func TestAuditCleanup(t *testing.T) {
	base, hazards := buildFixtures(t)
	exe := filepath.Join(t.TempDir(), "telltale")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", exe, "../../cmd/telltale")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, out)
	}
	t.Run("absent image", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), exe, "audit", t.TempDir(), "--verify", "--image", "localhost/telltale-absent-"+randomHex(12))
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !bytes.Contains(out, []byte("check local image presence")) {
			t.Fatalf("expected missing-image exit 2, got %v %s", err, out)
		}
	})
	for _, phase := range []string{"snapshot", "created", "running"} {
		t.Run("SIGKILL "+phase, func(t *testing.T) {
			a := startAudit(t, exe, base, "hold", 90*time.Second, phase)
			if phase != "snapshot" {
				a.release(t, "snapshot")
			}
			switch phase {
			case "created":
				a.waitMarker(t, a.bin, phase)
				id := runIDs(t, a.label)
				if !fullID.MatchString(id) {
					t.Fatal("missing created container")
				}
				state := podman(t, "inspect", "--format", "{{.State.Status}}", id)
				if state != "configured" && state != "created" {
					t.Fatalf("unexpected pre-start state %s", state)
				}
			case "running":
				a.running(t)
			}
			a.signal(t, syscall.SIGKILL)
			a.finish(t, true)
		})
	}
	for _, name := range []string{"normal", "timeout", "budget", "SIGINT", "double SIGINT", "concurrent"} {
		t.Run(name, func(t *testing.T) {
			timeout := 90 * time.Second
			if name == "timeout" {
				timeout = 8 * time.Second
			}
			var holds []string
			if name == "double SIGINT" {
				holds = []string{"removing"}
			}
			mode := "hold"
			if name == "budget" {
				mode = "budget"
			}
			a := startAudit(t, exe, base, mode, timeout, holds...)
			a.release(t, "snapshot")
			work := a.running(t)
			switch name {
			case "SIGINT", "double SIGINT":
				a.signal(t, os.Interrupt)
				if name == "double SIGINT" {
					a.waitMarker(t, a.bin, "removing")
					a.signal(t, os.Interrupt)
					a.release(t, "removing")
				}
			case "concurrent":
				b := startAudit(t, exe, base, "hold", timeout)
				b.release(t, "snapshot")
				bWork := b.running(t)
				before := runIDs(t, b.label)
				writeFixture(t, filepath.Join(work, "release"), "")
				a.finish(t, false)
				if runIDs(t, b.label) != before {
					t.Fatal("run A removed B's container")
				}
				writeFixture(t, filepath.Join(bWork, "release"), "")
				b.finish(t, false)
				return
			case "normal":
				writeFixture(t, filepath.Join(work, "release"), "")
			}
			r := a.finish(t, false)
			if name == "budget" {
				requireInventoryReason(t, r, model.BudgetExhausted)
			}
			if name == "timeout" {
				requireInventoryReason(t, r, model.Timeout)
			}
			if name == "normal" && len(r.Coverage.ParseErrors) != 0 {
				t.Fatal("normal inventory failed")
			}
		})
	}
	for _, mode := range []string{"startup", "initialize", "tools/list", "tools/call", "cache"} {
		t.Run(mode, func(t *testing.T) {
			tag := base
			if mode == "cache" {
				tag = hazards
			}
			a := startAudit(t, exe, tag, mode, 55*time.Second)
			a.release(t, "snapshot")
			r := a.finish(t, false)
			switch mode {
			case "startup", "initialize", "tools/list":
				requireInventoryReason(t, r, model.ResourceLimit)
			default:
				reason := model.ResourceLimit
				if mode == "cache" {
					reason = model.ServerCrash
				}
				for _, f := range r.Findings {
					if f.ID == "FS-PATH-TRAVERSAL" && f.DynamicStatus == model.Inconclusive && f.DynamicReason != nil && *f.DynamicReason == reason {
						return
					}
				}
				t.Fatalf("missing inconclusive FS session with reason %s", reason)
			}
		})
	}
}

func requireInventoryReason(t *testing.T, r model.ScanReport, reason model.DynamicReason) {
	t.Helper()
	for _, e := range r.Coverage.ParseErrors {
		if e.Engine == "mcp" && e.Reason == string(reason) {
			return
		}
	}
	t.Fatalf("missing MCP inventory outcome %s", reason)
}
