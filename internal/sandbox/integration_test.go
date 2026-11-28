//go:build integration

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func podman(t *testing.T, args ...string) string {
	t.Helper()
	out, err := podmanOutput(t.Context(), args...)
	if err != nil {
		t.Fatalf("local rootless podman %s: %v", args[0], err)
	}
	return strings.TrimSpace(string(out))
}

func buildFixtures(t *testing.T) (base, hazards string) {
	t.Helper()
	info := podman(t, "info", "--format", "json")
	if _, err := checkHost([]byte(info)); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs("../../testdata/fixtures/containers")
	if err != nil {
		t.Fatal(err)
	}
	base = "localhost/telltale-base-" + randomHex(8)
	hazards = "localhost/telltale-hazards-" + randomHex(8)
	for _, im := range []struct{ file, tag string }{{"base", base}, {"hazards", hazards}} {
		args := []string{"build", "--network=none", "--pull=never", "--tag", im.tag}
		if im.file == "hazards" {
			args = append(args, "--build-arg", "BASE="+base)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		cmd := podmanCommand(ctx, append(args, "--file", filepath.Join(dir, "Containerfile."+im.file), dir)...)
		err := cmd.Run()
		cancel()
		if err != nil {
			t.Fatalf("building %s (requires preloaded docker.io/library/python:3.12-alpine): %v", im.file, err)
		}
		t.Cleanup(func() {
			if _, err := podmanOutput(context.Background(), "rmi", "--", im.tag); err != nil {
				t.Errorf("remove test image: %v", err)
			}
		})
	}
	return base, hazards
}

func realSpec(t *testing.T, tag string, timeout time.Duration, argv ...string) SessionSpec {
	t.Helper()
	image, err := (ContainerRuntime{Image: tag}).Preflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewFixtureManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	f, err := manager.NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	spec := f.SessionSpec(image, randomHex(16), timeout, argv)
	t.Cleanup(func() {
		if err := (ContainerRuntime{}).ForceCleanup(context.Background(), spec.runID); err != nil {
			t.Error(err)
		}
	})
	return spec
}

func createReal(t *testing.T, spec SessionSpec) *Session {
	t.Helper()
	s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const isolationProbe = `
import errno, os, socket, subprocess, sys
from pathlib import Path
def check(condition, name):
    if not condition:
        raise ValueError(name)
check(os.geteuid() == int(sys.argv[1]) != 0, "effective UID")
status = Path("/proc/self/status").read_text().splitlines()
check(any(line.split() == ["CapEff:", "0000000000000000"] for line in status), "capabilities")
check(set(os.listdir("/sys/class/net")) == {"lo"}, "network interfaces")
# A documentation-only address in an isolated network namespace.
with socket.socket(type=socket.SOCK_DGRAM) as dns:
    check(dns.connect_ex(("192.0.2.1", 53)) == errno.ENETUNREACH, "outbound DNS route")
with socket.socket() as s:
    s.settimeout(1)
    check(s.connect_ex(("192.0.2.1", 53)) == errno.ENETUNREACH, "outbound TCP route")
try:
    socket.getaddrinfo("telltale-fixture.invalid", 80)
except socket.gaierror:
    pass
else:
    raise ValueError("DNS")
for file, value in {"memory.max":"536870912","pids.max":"64","cpu.max":"100000 100000"}.items():
    check((Path("/sys/fs/cgroup") / file).read_text().strip() == value, file)
check(not os.path.ismount("/sneaky"), "image volume")
cache = subprocess.run([sys.executable, "/cache_probe.py"], capture_output=True, timeout=2)
check(cache.returncode != 0 and b"[Errno 30]" in cache.stderr and
      b"/opt/fixture-probe/cache" in cache.stderr, "cache probe requires writable storage")
for d in ("/workspace", "/tmp"):
    (Path(d) / "write-test").touch()
try:
    Path("/opt/fixture-probe/write-test").touch()
except OSError as e:
    check(e.errno == errno.EROFS, "read-only filesystem")
else:
    raise ValueError("writable root")
# Bounded, non-recursive children. Verify kernel rejection and reap every child.
children = []
try:
    for _ in range(65):
        try:
            children.append(subprocess.Popen(["sleep","10"]))
        except BlockingIOError as e:
            check(e.errno == errno.EAGAIN and children, "pids enforcement")
            events = Path("/sys/fs/cgroup/pids.events").read_text().splitlines()
            check(any(k == "max" and int(v) > 0 for k, v in map(str.split, events)), "pids.events")
            break
    else:
        raise ValueError("pids limit exceeded")
finally:
    for child in children:
        child.terminate()
    for child in children:
        child.wait()
`

// On an SELinux host Podman exposes the assigned private mount label.
// Compare the actual bind-source xattrs with the runtime label.
func selinuxLabel(t *testing.T, path string) string {
	t.Helper()
	var buf [4096]byte
	n, err := syscall.Getxattr(path, "security.selinux", buf[:])
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(buf[:n]), "\x00")
}

func TestRootlessIsolation(t *testing.T) {
	_, tag := buildFixtures(t)
	t.Run("kernel and image isolation", func(t *testing.T) {
		spec := realSpec(t, tag, 30*time.Second, "python3", "/fixture.py")
		s := createReal(t, spec)
		// Read the actual creation arguments because Podman normalizes volume
		// options in .HostConfig.Binds. Production inspection checks the two
		// effective mount sources and destinations independently.
		raw := podman(t, "inspect", "--format", "{{json .Config.CreateCommand}}", s.id)
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		var binds []string
		for i, arg := range args {
			if arg == "--volume" && i+1 < len(args) {
				binds = append(binds, args[i+1])
			}
		}
		if !slices.Equal(binds, []string{spec.workspace + ":/workspace:rw,Z", spec.restricted + ":/restricted:ro,Z"}) {
			t.Fatalf("unexpected relabel sources: %q", binds)
		}
		stream, err := s.Start(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := stream.Close(); err != nil {
				t.Error(err)
			}
		}()
		if label := podman(t, "inspect", "--format", "{{.MountLabel}}", s.id); label != "" {
			for _, path := range []string{spec.workspace, spec.restricted} {
				if selinuxLabel(t, path) != label {
					t.Fatalf("private mount label mismatch on %s", path)
				}
			}
		}
		cmd := podmanCommand(stream.Context(), "exec", s.id, "python3", "-c", isolationProbe, strconv.Itoa(os.Getuid()))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolation probe: %v: %s", err, out)
		}
	})
	t.Run("configuration injections", func(t *testing.T) {
		config := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", config)
		dir := filepath.Join(config, "containers")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		spec := realSpec(t, tag, 30*time.Second)
		s := createReal(t, spec)
		if err := removeSession(t.Context(), s.id); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, setting, want string }{
			{"env_host", "env_host=true", "container environment mismatch"},
			{"default mount", "volumes=[" + strconv.Quote(t.TempDir()+":/injected:ro") + "]", "container mounts mismatch"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				writeFixture(t, filepath.Join(dir, "containers.conf"), "[containers]\n"+tc.setting+"\n")
				s, err := (ContainerRuntime{}).CreateSession(t.Context(), spec)
				var fatal *FatalError
				if s != nil || !errors.As(err, &fatal) || !strings.Contains(fatal.Error(), tc.want) {
					t.Fatalf("expected pre-start %s, got %v", tc.want, err)
				}
				if ids := runIDs(t, spec.runID); ids != "" {
					t.Fatal("rejected container survived")
				}
			})
		}
	})
}
