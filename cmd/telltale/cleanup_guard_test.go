package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/sandbox"
	"github.com/Timatoot/telltale/internal/verify"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "__test_delayed_create" {
		time.Sleep(50 * time.Millisecond)
		root, err := os.OpenRoot(os.TempDir())
		if err != nil {
			os.Exit(2)
		}
		if !strings.HasPrefix(os.Args[2], "container-") || filepath.Base(os.Args[2]) != os.Args[2] {
			os.Exit(2)
		}
		if err := root.WriteFile(os.Args[2], []byte("created"), 0o600); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case guardArg:
			reply := os.NewFile(3, "test-readiness")
			err := serveGuard(os.Stdin, reply, func(_ context.Context, id string) error {
				err := os.Remove(filepath.Join(os.TempDir(), "container-"+id))
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}, 500*time.Millisecond)
			if err != nil {
				os.Exit(2)
			}
			os.Exit(0)
		case "__test_session_signals":
			release := make(chan struct{})
			runtime := fixtureRuntime{
				start: func(ctx context.Context, _ sandbox.SessionSpec) (verify.Session, error) {
					return signalFixtureSession{ctx: ctx, release: release}, nil
				},
				cleanup: func(ctx context.Context, _ string) error { close(release); return ctx.Err() },
			}
			os.Exit(runAudit([]string{"audit", ".", "--verify", "--image", "fixture", "--strict"}, io.Discard, os.Stderr, fixtureAnalyzer{}, runtime))
		case "__test_preflight_signal":
			preflight := func(ctx context.Context) (sandbox.RuntimeInfo, error) {
				_, _ = os.Stdout.WriteString("preflight\n")
				<-ctx.Done()
				return sandbox.RuntimeInfo{}, ctx.Err()
			}
			os.Exit(runAudit([]string{"audit", ".", "--verify", "--image", "fixture"}, io.Discard, os.Stderr, fixtureAnalyzer{}, fixtureRuntime{preflight: preflight}))
		case "__test_guard_owner", "__test_guard_owner_create", "__test_guard_owner_started":
			guard, err := startCleanupGuard(context.Background())
			if err != nil {
				os.Exit(1)
			}
			if os.Args[1] != "__test_guard_owner" {
				if _, err := guard.owner.Write([]byte{'A'}); err != nil {
					os.Exit(2)
				}
				f, err := sandbox.NewFixtureManager(guard.Dir)
				if err != nil {
					os.Exit(2)
				}
				if _, err := f.NewWorkspace(); err != nil {
					os.Exit(2)
				}
				marker := filepath.Join(os.TempDir(), "container-"+guard.ID)
				if os.Args[1] == "__test_guard_owner_create" {
					exe, err := os.Executable()
					if err != nil {
						os.Exit(2)
					}
					cmd := exec.CommandContext(context.Background(), exe, "__test_delayed_create", filepath.Base(marker)) //nolint:gosec // Same executable and private synthetic marker.
					cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
					if err := cmd.Start(); err != nil {
						os.Exit(2)
					}
				} else if err := os.WriteFile(marker, []byte("started"), 0o600); err != nil {
					os.Exit(2)
				}
			}
			if err := json.NewEncoder(os.Stdout).Encode(guard.runResources); err != nil {
				os.Exit(1)
			}
			time.Sleep(time.Minute)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func TestGuardOwnerDeathAndConcurrentRun(t *testing.T) {
	for _, helper := range []string{"__test_guard_owner", "__test_guard_owner_create", "__test_guard_owner_started"} {
		t.Run(helper, func(t *testing.T) { testGuardOwnerDeath(t, helper) })
	}
}
func testGuardOwnerDeath(t *testing.T, helper string) {
	t.Setenv("TMPDIR", t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	other, err := startCleanupGuard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.owner.Write([]byte{'A'}); err != nil {
		t.Fatal(err)
	}
	otherMarker := filepath.Join(os.TempDir(), "container-"+other.ID)
	if err := os.WriteFile(otherMarker, []byte("other run"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := other.close(); err != nil {
			t.Error(err)
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, helper) //nolint:gosec // Same test executable and constant helper argument.
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var run runResources
	if err := json.NewDecoder(io.LimitReader(out, 32<<10)).Decode(&run); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(run.Dir)
	if err != nil || info.Mode().Perm() != 0o700 || run.ID == other.ID || run.Dir == other.Dir {
		t.Fatalf("unexpected allocation: %v, %v", info, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := os.Stat(run.Dir)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil || ctx.Err() != nil {
			t.Fatalf("orphan dir: %v, %v", err, ctx.Err())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(os.TempDir(), "container-"+run.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("synthetic container leaked: %v", err)
	}
	if _, err := os.Stat(other.Dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(otherMarker); err != nil {
		t.Fatal("other run container removed", err)
	}
}

func TestGuardContainerReconciliation(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	for _, tc := range []struct {
		name, commands string
		fail           bool
	}{
		{"owner gone before preflight", "", false},
		{"owner gone during create", "A", false},
		{"orderly exit after start", "AD", false},
		{"container removal failed", "AD", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ready bytes.Buffer
			var called bool
			var run runResources
			cleanup := func(ctx context.Context, id string) error {
				called = true
				if err := json.Unmarshal(ready.Bytes(), &run); err != nil {
					t.Fatal(err)
				}
				if ctx.Err() != nil || run.ID != id || filepath.Dir(run.Dir) != scratch {
					t.Fatal("wrong cleanup scope")
				}
				if _, err := os.Stat(run.Dir); err != nil {
					t.Fatal(err)
				}
				if tc.fail {
					return errors.New("removal failed")
				}
				return nil
			}
			err := serveGuard(strings.NewReader(tc.commands), &ready, cleanup, time.Millisecond)
			if (err != nil) != tc.fail || called != strings.HasPrefix(tc.commands, "A") {
				t.Fatalf("cleanup called=%v err=%v", called, err)
			}
			if err := json.Unmarshal(ready.Bytes(), &run); err != nil {
				t.Fatal(err)
			}
			_, err = os.Stat(run.Dir)
			if tc.fail && err != nil || !tc.fail && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("guard directory: %v", err)
			}
		})
	}
}

func TestGuardOwnerGoneBeforeReadiness(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	defer func() { _ = w.Close() }()
	err = serveGuard(strings.NewReader(""), w, nil, 0)
	if err == nil {
		t.Fatal("readiness unexpectedly delivered")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("leftover guard allocations: %v %v", entries, err)
	}
}

func TestSignalDuringVerifyPreflight(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.CommandContext(ctx, exe, "__test_preflight_signal") //nolint:gosec // Same test binary with constant helper argument.
			var diag bytes.Buffer
			cmd.Stderr = &diag
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "preflight\n" {
				t.Fatalf("preflight barrier: %q %v", line, err)
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			var exit *exec.ExitError
			if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != exitFatalError || !strings.Contains(diag.String(), "context canceled") {
				t.Fatalf("exit: %v, stderr: %s", err, &diag)
			}
			entries, err := os.ReadDir(os.TempDir())
			if err != nil || len(entries) != 0 {
				t.Fatalf("cleanup: %v %v", entries, err)
			}
		})
	}
}

type signalFixtureSession struct {
	ctx     context.Context
	release <-chan struct{}
}

func (s signalFixtureSession) Context() context.Context { return s.ctx }
func (s signalFixtureSession) Initialize(context.Context) error {
	_, _ = os.Stdout.WriteString("session\n")
	<-s.ctx.Done()
	return s.ctx.Err()
}
func (signalFixtureSession) ListTools(context.Context) ([]mcpclient.LiveTool, error) { return nil, nil }
func (signalFixtureSession) CallTool(context.Context, string, map[string]any) (mcpclient.CallResult, error) {
	return mcpclient.CallResult{}, nil
}
func (s signalFixtureSession) Close() error {
	_, _ = os.Stdout.WriteString("closing\n")
	<-s.release
	return nil
}

func TestDoubleSignalAbortsSessionWait(t *testing.T) {
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "__test_session_signals") //nolint:gosec // Same test executable and constant helper argument.
	cmd.Dir = t.TempDir()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diag bytes.Buffer
	cmd.Stderr = &diag
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(out)
	for _, barrier := range []string{"session\n", "closing\n"} {
		if line, err := reader.ReadString('\n'); err != nil || line != barrier {
			t.Fatalf("barrier %q: %q %v %s", barrier, line, err, &diag)
		}
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatalf("exit: %v %s", err, &diag)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
}

func TestGuardPermissionRepairAndSymlinkSafety(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "untouched")
	if err := os.WriteFile(secret, []byte("outside"), 0o400); err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(dir, "sealed")
	if err := os.Mkdir(sealed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sealed, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := removeRunTree(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(secret) //nolint:gosec // Private test fixture created above.
	if err != nil || string(data) != "outside" {
		t.Fatal("outside entry changed", err)
	}
}
