package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exceedBytes(t *testing.T, workspace string) {
	t.Helper()
	p := filepath.Join(workspace, "sparse")
	writeFixture(t, p, "")
	if err := os.Truncate(p, maxWorkspaceBytes+1); err != nil {
		t.Fatal(err)
	}
}

func awaitFile(t *testing.T, path, contains string) {
	t.Helper()
	root := fixtureRoot(t, filepath.Dir(path))
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		data, err := root.ReadFile(filepath.Base(path))
		if err == nil && strings.Contains(string(data), contains) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not observe %q in %s", contains, filepath.Base(path))
}

func TestWatchdogBeforeReady(t *testing.T) {
	spec, dir := sessionFixture(t)
	writeFixture(t, filepath.Join(dir, "state"), `{"Status":"created"}`)
	s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.start(t.Context(), dir); done <- err }()
	awaitFile(t, filepath.Join(dir, "commands"), "start --attach")
	exceedBytes(t, spec.workspace)
	select {
	case err := <-done:
		if !errors.Is(err, ErrResourceLimit) {
			t.Fatalf("startup result: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("watchdog did not interrupt startup")
	}
	if !strings.Contains(commands(t, dir), "rm --force") {
		t.Fatal("container survived startup failure")
	}
}

func TestWatchdogDuringSession(t *testing.T) {
	for _, phase := range []string{"initialize", "tools/list", "tools/call", "quiescence", "teardown"} {
		t.Run(phase, func(t *testing.T) {
			spec, dir := sessionFixture(t)
			s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := s.start(t.Context(), dir)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			defer func() { _ = stream.Close() }()
			if phase != "initialize" {
				if err := stream.Initialize(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			switch phase {
			case "initialize":
				writeFixture(t, filepath.Join(dir, "hold-initialize"), "")
				go func() { done <- stream.Initialize(t.Context()) }()
			case "tools/list":
				go func() { _, err := stream.ListTools(t.Context()); done <- err }()
			case "tools/call":
				go func() { _, err := stream.CallTool(t.Context(), "echo", nil); done <- err }()
			case "teardown":
				hold := filepath.Join(dir, "hold-removal")
				writeFixture(t, hold, "")
				go func() { done <- stream.Close() }()
				awaitFile(t, filepath.Join(dir, "commands"), "rm --force")
				exceedBytes(t, spec.workspace)
				// Removal is deliberately parked; prove the watchdog has
				// already signaled, then let teardown join its worker.
				select {
				case <-stream.Context().Done():
				case <-time.After(3 * time.Second):
					t.Fatal("watchdog stopped before removal")
				}
				if err := os.Remove(hold); err != nil {
					t.Fatal(err)
				}
			}
			if phase != "quiescence" && phase != "teardown" {
				awaitFile(t, filepath.Join(dir, "received"), phase)
			}
			if phase != "teardown" {
				exceedBytes(t, spec.workspace)
			}
			select {
			case <-stream.done:
			case <-time.After(6 * time.Second):
				t.Fatal("session not terminated by watchdog")
			}
			if phase != "quiescence" {
				if err := <-done; err == nil {
					t.Fatal("operation succeeded after watchdog limit")
				}
			}
			if err := stream.Close(); !errors.Is(err, ErrResourceLimit) {
				t.Fatalf("session outcome: %v", err)
			}
			if !strings.Contains(commands(t, dir), "rm --force") {
				t.Fatal("container survived watchdog")
			}
		})
	}
}

func TestWatchdogJoin(t *testing.T) {
	dir := t.TempDir()
	ctx, abort := context.WithCancelCause(t.Context())
	defer abort(nil)
	stop := armWatchdog(ctx, dir, abort)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	exceedBytes(t, dir)
	select {
	case <-ctx.Done():
		t.Fatal("joined watchdog sampled again")
	case <-time.After(2 * watchInterval):
	}
}

func TestWatchdogPersistentInaccessibleWorkspace(t *testing.T) {
	spec, dir := sessionFixture(t)
	s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := s.start(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if err := stream.Initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(spec.workspace, "seed")
	if err := os.Chmod(seed, 0); err != nil {
		t.Fatal(err)
	}

	select {
	case <-stream.done:
	case <-time.After(6 * time.Second):
		t.Fatal("session not terminated by persistent inaccessible workspace")
	}
	if err := stream.Close(); !errors.Is(err, ErrUnstableWorkspace) {
		t.Fatalf("expected ErrUnstableWorkspace, got %v", err)
	}
	if !strings.Contains(commands(t, dir), "rm --force") {
		t.Fatal("container survived inaccessible workspace watchdog")
	}
}
