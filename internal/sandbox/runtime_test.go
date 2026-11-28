package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestMain re-execs this binary as podman. The private directory models
// runtime metadata and the host cgroup filesystem, independent of the peer.
func fakeSessionCLI(dir string, args []string) int {
	if len(args) == 0 {
		return 2
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 2
	}
	defer func() { _ = root.Close() }()
	log, err := root.OpenFile("commands", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 2
	}
	_, err = fmt.Fprintln(log, strings.Join(args, " "))
	_ = log.Close()
	if err != nil {
		return 2
	}
	emit := func(name string) int {
		data, err := root.ReadFile(name)
		if err != nil {
			return 2
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			return 2
		}
		return 0
	}
	switch {
	case args[0] == "create":
		if err := root.WriteFile(containerID, []byte("run-1"), 0o600); err != nil {
			return 2
		}
		fmt.Println(containerID)
	case slices.Equal(args, []string{"container", "inspect", "--", containerID}):
		return emit("inspection")
	case slices.Equal(args, []string{"container", "inspect", "--format", "{{json .State}}", "--", containerID}):
		return emit("state")
	case slices.Equal(args, []string{"start", "--attach", "--interactive", "--", containerID}):
		fmt.Fprint(os.Stderr, strings.Repeat(".", 65540)+"tail")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			var msg struct {
				ID     int
				Method string
			}
			if json.Unmarshal(sc.Bytes(), &msg) != nil {
				return 2
			}
			if err := root.WriteFile("received", []byte(msg.Method), 0o600); err != nil {
				return 2
			}
			_, hold := root.Stat("hold-initialize")
			if msg.Method == "initialize" && os.IsNotExist(hold) {
				fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-11-25\"}}\n", msg.ID)
			}
		}
	case slices.Equal(args, []string{"ps", "--all", "--no-trunc", "--filter", "label=telltale.run=run-1", "--format", "{{.ID}}"}):
		for _, id := range []string{containerID, imageID} {
			label, err := root.ReadFile(id)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return 2
			}
			if string(label) == "run-1" {
				fmt.Println(id)
			}
		}
	case slices.Equal(args, []string{"rm", "--force", "--time", "0", "--ignore", "--", containerID}):
		for {
			_, err := root.Stat("hold-removal")
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return 2
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := root.Remove(containerID); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 2
		}
	default:
		return 2
	}
	return 0
}

func writeFixture(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sessionFixture(t *testing.T) (SessionSpec, string) {
	t.Helper()
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "podman")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	manager, err := NewFixtureManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	mounts, err := manager.NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	w, r := mounts.workspace, mounts.restricted
	// Model a rootless actor independently of the UID running the unit tests.
	spec := mounts.SessionSpec(fixtureSpec(t).image, "run-1", 30*time.Second+1, nil)
	spec.uid, spec.gid = 1000, 1001
	data := strings.NewReplacer("/run-fixture/work", w, "/run-fixture/private", r).Replace(inspectJSON)
	writeFixture(t, filepath.Join(dir, "inspection"), data)
	writeFixture(t, filepath.Join(dir, "state"), `{"Status":"running","CgroupPath":"/group"}`)
	if err := os.Mkdir(filepath.Join(dir, "group"), 0o700); err != nil {
		t.Fatal(err)
	}
	for file, value := range map[string]string{"memory.max": "536870912", "pids.max": "64", "cpu.max": "100000 100000"} {
		writeFixture(t, filepath.Join(dir, "group", file), value+"\n")
	}
	return spec, dir
}

func commands(t *testing.T, dir string) string {
	t.Helper()
	data, err := fixtureRoot(t, dir).ReadFile("commands")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestSessionLifecycle(t *testing.T) {
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
	if tail := stream.StderrExcerpt(""); len(tail) != 64<<10 || !strings.HasSuffix(tail, "tail") {
		t.Fatal("incorrect stderr tail")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	log := strings.Split(strings.TrimSpace(commands(t, dir)), "\n")
	if len(log) != 5 || !strings.HasPrefix(log[0], "create ") || log[1] != "container inspect -- "+containerID ||
		!slices.Contains(log[2:4], "start --attach --interactive -- "+containerID) || !strings.HasPrefix(log[4], "rm --force ") {
		t.Fatalf("lifecycle commands: %q", log)
	}
	if _, err := s.start(t.Context(), dir); err == nil {
		t.Fatal("second start succeeded")
	}
}

func TestInspectFailureRemovesBeforeStart(t *testing.T) {
	spec, dir := sessionFixture(t)
	writeFixture(t, filepath.Join(dir, "inspection"), "[]")
	_, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
	requireFatal(t, err)
	log := commands(t, dir)
	if strings.Contains(log, "start --attach") || !strings.Contains(log, "rm --force --time 0 --ignore -- "+containerID) {
		t.Fatal(log)
	}
}

func TestCgroupMismatchesRemove(t *testing.T) {
	for _, file := range []string{"memory.max", "pids.max", "cpu.max"} {
		t.Run(file, func(t *testing.T) {
			spec, dir := sessionFixture(t)
			writeFixture(t, filepath.Join(dir, "group", file), "max")
			s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.start(t.Context(), dir)
			requireFatal(t, err)
			if !strings.Contains(err.Error(), file) || !strings.Contains(commands(t, dir), "rm --force --time 0 --ignore -- "+containerID) {
				t.Fatalf("missing cgroup failure or teardown: %v", err)
			}
		})
	}
}

func TestForceCleanup(t *testing.T) {
	_, dir := sessionFixture(t)
	writeFixture(t, filepath.Join(dir, containerID), "run-1")
	writeFixture(t, filepath.Join(dir, imageID), "run-10")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r := ContainerRuntime{}
	if err := r.ForceCleanup(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.ForceCleanup(ctx, ".*"); err == nil {
		t.Fatal("accepted broad label")
	}
	root := fixtureRoot(t, dir)
	if _, err := root.Stat(containerID); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("run container survived cleanup")
	}
	if _, err := root.Stat(imageID); err != nil {
		t.Fatal("unrelated run was affected")
	}
	if lines := commands(t, dir); lines != "ps --all --no-trunc --filter label=telltale.run=run-1 --format {{.ID}}\nrm --force --time 0 --ignore -- "+containerID+"\n" {
		t.Fatal(lines)
	}
}
