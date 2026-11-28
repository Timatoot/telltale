package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const hostJSON = `{"version":{"Version":"5.8.0"},"host":{"security":{"rootless":true},"serviceIsRemote":false,"cgroupVersion":"v2","cgroupControllers":["cpu","memory","pids"],"ociRuntime":{"name":"crun"}}}`
const imageID = "abababababababababababababababababababababababababababababababab"
const imageJSON = `[{"Id":"` + imageID + `","Config":{"Env":["PATH=/app","HOME=/original"],"Entrypoint":["python3"],"Cmd":["/app/server.py"]}}]`

// Re-exec the test binary as a local fake CLI to cover the production
// subprocess and JSON paths without initializing Podman storage.
func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) != "podman" {
		os.Exit(m.Run())
	}
	if os.Getenv("XDG_CONFIG_HOME") == os.Getenv("PATH") {
		os.Exit(fakeSessionCLI(os.Getenv("XDG_CONFIG_HOME"), os.Args[1:]))
	}
	var output string
	args := os.Args[1:]
	switch {
	case slices.Equal(args, []string{"info", "--format", "json"}):
		output = hostJSON
	case slices.Equal(args, []string{"image", "exists", "--", "fixture"}):
	case slices.Equal(args, []string{"image", "inspect", "--", "fixture"}):
		output = imageJSON
	case slices.Equal(args, []string{"container", "inspect", "--", containerID}):
		output = inspectJSON
	default:
		os.Exit(2)
	}
	if _, err := os.Stdout.WriteString(output); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestPodmanMetadataCommands(t *testing.T) {
	bin := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(bin, "podman")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	info, err := (ContainerRuntime{Image: "fixture"}).Preflight(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	spec := fixtureSpec(t)
	spec.image = info
	if err := spec.inspectCreated(t.Context(), containerID); err != nil {
		t.Fatal(err)
	}
}

func requireFatal(t *testing.T, err error) {
	t.Helper()
	var fatal *FatalError
	if !errors.As(err, &fatal) || fatal.ExitCode() != 2 {
		t.Fatalf("expected fatal exit 2, got %v", err)
	}
}

func TestPodmanCommand(t *testing.T) {
	want := []string{"LANG=C.UTF-8"}
	for _, key := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		t.Setenv(key, t.TempDir())
		want = append(want, key+"="+os.Getenv(key))
	}
	for _, key := range []string{"CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST", "DOCKER_CONFIG", "AWS_SECRET_ACCESS_KEY", "LANG", "LD_PRELOAD"} {
		t.Setenv(key, "synthetic")
	}
	cmd := podmanCommand(t.Context(), "info", "--format", "json")
	if !slices.Equal(cmd.Env, want) || !slices.Equal(cmd.Args, []string{"podman", "info", "--format", "json"}) {
		t.Fatal("incorrect child environment or arguments")
	}
	if !cmd.SysProcAttr.Setpgid || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL || cmd.Cancel == nil || cmd.WaitDelay <= 0 || cmd.WaitDelay > time.Second {
		t.Fatal("missing subprocess lifetime bounds")
	}
	_, err := (ContainerRuntime{Image: "local-fixture"}).Preflight(t.Context())
	requireFatal(t, err) // empty PATH directory
}

func TestOutputBound(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	o := metadataOutput{cancel: cancel}
	if _, err := o.Write(make([]byte, metadataLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Write([]byte{1}); err == nil || !o.overflow || ctx.Err() == nil || o.buf.Len() != metadataLimit {
		t.Fatal("metadata overflow did not cancel at the bound")
	}
}

func replace(t *testing.T, base, old, newText string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("missing fixture fragment %q", old)
	}
	return strings.Replace(base, old, newText, 1)
}

func fixturePreflight(t *testing.T, host, image string, failAt int) (RuntimeInfo, error) {
	t.Helper()
	commands := [][]string{{"info", "--format", "json"}, {"image", "exists", "--", "fixture"}, {"image", "inspect", "--", "fixture"}}
	step := 0
	return (ContainerRuntime{Image: "fixture"}).preflight(t.Context(), func(ctx context.Context, args ...string) ([]byte, error) {
		if step >= len(commands) || !slices.Equal(args, commands[step]) || ctx != t.Context() {
			t.Fatalf("unexpected preflight step %d", step)
		}
		step++
		if step == failAt {
			return nil, syscall.ENOENT
		}
		outputs := []string{host, "", image}
		return []byte(outputs[step-1]), nil
	})
}

func TestPreflight(t *testing.T) {
	for _, version := range []string{"5.0", "5.0.0", "5.8.0", "10.0.1"} {
		info, err := fixturePreflight(t, replace(t, hostJSON, "5.8.0", version), imageJSON, 0)
		if err != nil || info.Version != version || info.ImageID() != imageID || info.imageEnv["PATH"] != "/app" ||
			!slices.Equal(info.imageArgv, []string{"python3", "/app/server.py"}) {
			t.Fatalf("failed to preflight version %q: %v", version, err)
		}
	}
	for _, version := range []string{"4.99.99", "5", "5.x.1", "5.0.0-rc1", "5.0.1junk", "5.1.1-01", "", "05.1.0"} {
		_, err := fixturePreflight(t, replace(t, hostJSON, "5.8.0", version), imageJSON, 0)
		requireFatal(t, err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"rootful", "true", "false"}, {"remote", "false", "true"},
		{"missing remote flag", `"serviceIsRemote":false,`, ""}, {"v1", "v2", "v1"},
		{"cpu", `"cpu",`, ""}, {"memory", `"memory",`, ""}, {"pids", `,"pids"`, ""},
		{"runtime", "crun", "runc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fixturePreflight(t, replace(t, hostJSON, tc.from, tc.to), imageJSON, 0)
			requireFatal(t, err)
		})
	}
	for _, image := range []string{"{}", "[]", "[{},{}]", "[null]", imageJSON + "{}", replace(t, imageJSON, imageID, "fixture"), replace(t, imageJSON, "PATH=/app", "PATH")} {
		_, err := fixturePreflight(t, hostJSON, image, 0)
		requireFatal(t, err)
	}
	for step := 1; step <= 3; step++ {
		_, err := fixturePreflight(t, hostJSON, imageJSON, step)
		requireFatal(t, err)
		if !errors.Is(err, syscall.ENOENT) {
			t.Fatal("lost runtime error")
		}
	}
}

const containerID = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// Podman reports user bind mounts in Mounts, tmpfs options in HostConfig.Tmpfs,
// and keep-id mappings relative to its rootless parent namespace.
const inspectJSON = `[{
	"Id":"` + containerID + `","Image":"` + imageID + `","OCIRuntime":"crun","UseImageHosts":true,
	"Path":"python3","Args":["/app/server.py"],"EffectiveCaps":[],"BoundingCaps":null,
	"Mounts":[{"Type":"bind","Source":"/run-fixture/work","Destination":"/workspace","RW":true},
	          {"Type":"bind","Source":"/run-fixture/private","Destination":"/restricted","RW":false}],
	"Config":{"User":"1000:1001","Env":["HOME=/tmp","PYTHONDONTWRITEBYTECODE=1","PATH=/app"],
	          "Timeout":41,"OpenStdin":true,"Labels":{"telltale.run":"run-1"}},
	"HostConfig":{"ReadonlyRootfs":true,"Privileged":false,"AutoRemove":true,"LogConfig":{"Type":"none"},
	              "SecurityOpt":["no-new-privileges"],"NetworkMode":"none","UsernsMode":"private",
	              "IDMappings":{"UidMap":["0:1:1000","1000:0:1"],"GidMap":["0:1:1001","1001:0:1"]},
	              "PidsLimit":64,"Memory":536870912,"MemorySwap":536870912,"CpuPeriod":100000,"CpuQuota":100000,
	              "Devices":[],"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=64m,rprivate,tmpcopyup"}}
}]`

func fixtureSpec(t *testing.T) createSpec {
	t.Helper()
	info, err := fixturePreflight(t, hostJSON, imageJSON, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := newCreateSpec(info, "/run-fixture/work", "/run-fixture/private", "run-1", 30*time.Second+1, nil)
	s.uid, s.gid = 1000, 1001
	return s
}

func TestCreateArgs(t *testing.T) {
	s := fixtureSpec(t)
	args, err := s.args()
	want := []string{"create", "--interactive", "--rm", "--pull=never", "--log-driver=none", "--network=none",
		"--no-hosts", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--image-volume=ignore",
		"--pids-limit=64", "--memory=512m", "--memory-swap=512m", "--cpus=1", "--userns=keep-id", "--user=1000:1001",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--volume", "/run-fixture/work:/workspace:rw,Z",
		"--volume", "/run-fixture/private:/restricted:ro,Z", "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
		"--label", "telltale.run=run-1", "--timeout=41", "--unsetenv", "container", "--", imageID}
	if err != nil || !slices.Equal(args, want) {
		t.Fatalf("create argv: %q, %v", args, err)
	}
	delete(s.image.imageEnv, "PATH")
	s.image.imageEnv["container"] = "from-image"
	s.override = []string{"/app/a b", "`literal`", "", "a\"b"}
	args, err = s.args()
	if err != nil || !slices.Equal(args[len(want)-4:], []string{"--unsetenv", "PATH", "--entrypoint", "[\"/app/a b\",\"`literal`\",\"\",\"a\\\"b\"]", "--", imageID}) {
		t.Fatalf("override create argv: %q, %v", args, err)
	}
}

func TestInvalidCreateSpec(t *testing.T) {
	for _, tc := range []func(*createSpec){
		func(s *createSpec) { s.uid = 0 }, func(s *createSpec) { s.timeout = 0 },
		func(s *createSpec) { s.workspace = "" }, func(s *createSpec) { s.workspace = "/root:ro" },
		func(s *createSpec) { s.workspace = s.restricted + "/child" }, func(s *createSpec) { s.restricted = "/" },
		func(s *createSpec) { s.image.imageID = "--latest" }, func(s *createSpec) { s.override = []string{""} },
	} {
		s := fixtureSpec(t)
		tc(&s)
		_, err := s.args()
		requireFatal(t, err)
	}
}

func TestInspection(t *testing.T) {
	s := fixtureSpec(t)
	if err := s.checkInspection(containerID, []byte(inspectJSON)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"env_host", `"PATH=/app"`, `"PATH=/app","XDG_RUNTIME_DIR=/synthetic-secret"`},
		{"different env value", "PATH=/app", "PATH=/synthetic-secret"},
		{"empty env injection", "PATH=/app", "INJECTED="},
		{"explicit env overridden", "HOME=/tmp", "HOME=/original"},
		{"missing explicit env", `"PYTHONDONTWRITEBYTECODE=1",`, ""},
		{"duplicate env", `"PATH=/app"`, `"PATH=/synthetic-secret","PATH=/app"`},
		{"extra default volume", `"Mounts":[`, `"Mounts":[{"Type":"volume","Destination":"/extra"},`},
		{"wrong source", "/run-fixture/private", "/elsewhere"}, {"bind type", `"Type":"bind"`, `"Type":"volume"`},
		{"writable restricted", `"RW":false`, `"RW":true`}, {"missing bind mode", `,"RW":false`, ""},
		{"read-only workspace", `"RW":true`, `"RW":false`},
		{"duplicate destination", `"/restricted"`, `"/workspace"`},
		{"extra tmpfs", `"Tmpfs":{`, `"Tmpfs":{"/extra":"rw",`},
		{"missing tmpfs", `"/tmp":`, `"/scratch":`},
		{"tmpfs size", "size=64m", "size=128m"}, {"conflicting tmpfs", "nodev,", "nodev,dev,"},
		{"root image user", "1000:1001", "0:0"}, {"wrong gid", "1000:1001", "1000:1000"},
		{"user mapping", "1000:0:1", "0:0:1"}, {"gid mapping", "1001:0:1", "1001:1:1"},
		{"capability", `"EffectiveCaps":[]`, `"EffectiveCaps":["CAP_SYS_ADMIN"]`},
		{"missing caps", `"EffectiveCaps":[],`, ""},
		{"bounding capability", `"BoundingCaps":null`, `"BoundingCaps":["CAP_CHOWN"]`},
		{"writable rootfs", `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`},
		{"privileged", `"Privileged":false`, `"Privileged":true`},
		{"use image hosts false", `"UseImageHosts":true`, `"UseImageHosts":false`},
		{"use image hosts missing", `"UseImageHosts":true,`, ""},
		{"no-new-privileges missing", `"no-new-privileges"`, ""},
		{"label disable", `"no-new-privileges"`, `"no-new-privileges","label=disable"`},
		{"seccomp unconfined", `"no-new-privileges"`, `"no-new-privileges","seccomp=unconfined"`},
		{"apparmor unconfined", `"no-new-privileges"`, `"no-new-privileges","apparmor:unconfined"`},
		{"unmask all", `"no-new-privileges"`, `"no-new-privileges","unmask=ALL"`},
		{"no-new-privileges false", `"no-new-privileges"`, `"no-new-privileges","no-new-privileges=false"`},
		{"argv mismatch", "/app/server.py", "/app/other.py"}, {"executable", "python3", "other"},
		{"injected device", `"Devices":[]`, `"Devices":[{"PathOnHost":"/dev/mock"}]`},
		{"missing devices", `"Devices":[],`, ""},
		{"network", `"NetworkMode":"none"`, `"NetworkMode":"bridge"`},
		{"memory", `"Memory":536870912`, `"Memory":0`}, {"swap", `"MemorySwap":536870912`, `"MemorySwap":-1`},
		{"pids", `"PidsLimit":64`, `"PidsLimit":0`}, {"cpu quota", "CpuQuota\":100000", "CpuQuota\":-1"},
		{"cpu period", "CpuPeriod\":100000", "CpuPeriod\":1000"},
		{"container identity", containerID, imageID}, {"image identity", imageID, containerID},
		{"label", "run-1", "another-run"}, {"log", `"Type":"none"`, `"Type":"journald"`},
		{"runtime", "crun", "runc"}, {"timeout", `"Timeout":41`, `"Timeout":0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.checkInspection(containerID, []byte(replace(t, inspectJSON, tc.from, tc.to)))
			requireFatal(t, err)
			if strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("inspection exposed env data")
			}
		})
	}
	for _, data := range []string{"[", "{}", "[]", "[{},{}]", inspectJSON + "{}", strings.Repeat(" ", metadataLimit+1)} {
		requireFatal(t, s.checkInspection(containerID, []byte(data)))
	}
	requireFatal(t, s.inspectCreated(t.Context(), "--latest"))
}

func TestEntrypointInspection(t *testing.T) {
	s := fixtureSpec(t)
	s.override = []string{"python3", "/other.py"}
	requireFatal(t, s.checkInspection(containerID, []byte(inspectJSON)))
	if err := s.checkInspection(containerID, []byte(replace(t, inspectJSON, "/app/server.py", "/other.py"))); err != nil {
		t.Fatal(err)
	}
	s.override = []string{"python3"}
	data := replace(t, inspectJSON, `["/app/server.py"]`, `["python3"]`)
	data = replace(t, data, `"Config":{`, `"Config":{"Entrypoint":["python3"],`)
	if err := s.checkInspection(containerID, []byte(data)); err != nil {
		t.Fatal(err)
	}
	requireFatal(t, s.checkInspection(containerID, []byte(replace(t, data, `"Entrypoint":["python3"]`, `"Entrypoint":["python3","python3"]`))))
}
