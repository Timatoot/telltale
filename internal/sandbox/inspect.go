package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// createSpec is built by the sandbox lifecycle from its own fresh fixture
// directories. Paths for :Z mounts must never come from the audited repo.
type createSpec struct {
	image                        RuntimeInfo
	workspace, restricted, runID string
	timeout                      time.Duration
	override                     []string
	uid, gid                     int
}

func newCreateSpec(info RuntimeInfo, workspace, restricted, runID string, timeout time.Duration, override []string) createSpec {
	return createSpec{image: info, workspace: workspace, restricted: restricted, runID: runID,
		timeout: timeout, override: slices.Clone(override), uid: os.Getuid(), gid: os.Getgid()}
}

func (s createSpec) argv() []string {
	if s.override != nil {
		return s.override
	}
	return s.image.imageArgv
}

func (s createSpec) user() string { return fmt.Sprintf("%d:%d", s.uid, s.gid) }

func (s createSpec) lifetimeSeconds() int64 {
	// Round a fractional session up, without overflowing time.Duration.
	return int64((s.timeout-1)/time.Second) + 1 + 10
}

func (s createSpec) args() ([]string, error) {
	if s.uid <= 0 || s.gid < 0 || s.runID == "" || s.timeout <= 0 || !fullID.MatchString(s.image.imageID) {
		return nil, &FatalError{errors.New("invalid container identity or lifetime")}
	}
	for _, path := range []string{s.workspace, s.restricted} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsAny(path, ":\x00") {
			return nil, &FatalError{errors.New("invalid fixture bind path")}
		}
	}
	if strings.HasPrefix(s.workspace+"/", s.restricted+"/") || strings.HasPrefix(s.restricted+"/", s.workspace+"/") {
		return nil, &FatalError{errors.New("fixture bind paths overlap")}
	}
	argv := s.argv()
	if len(argv) == 0 || argv[0] == "" {
		return nil, &FatalError{errors.New("missing container executable")}
	}

	args := []string{"create", "--interactive", "--rm", "--pull=never", "--log-driver=none",
		"--network=none", "--no-hosts", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--image-volume=ignore", "--pids-limit=64", "--memory=512m", "--memory-swap=512m",
		"--cpus=1", "--userns=keep-id", "--user=" + s.user(),
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--volume", s.workspace + ":/workspace:rw,Z", "--volume", s.restricted + ":/restricted:ro,Z",
		"--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
		"--label", "telltale.run=" + s.runID, "--timeout=" + strconv.FormatInt(s.lifetimeSeconds(), 10)}
	for _, key := range []string{"container", "PATH"} {
		if _, fromImage := s.image.imageEnv[key]; !fromImage {
			args = append(args, "--unsetenv", key)
		}
	}
	if s.override != nil {
		entry, err := json.Marshal(s.override)
		if err != nil {
			return nil, &FatalError{fmt.Errorf("encode entrypoint: %w", err)}
		}
		args = append(args, "--entrypoint", string(entry))
	}
	return append(args, "--", s.image.imageID), nil
}

// inspectCreated only reads metadata. The lifecycle owns removal on every
// failure and may start the container only after this method succeeds.
func (s createSpec) inspectCreated(ctx context.Context, id string) error {
	if !fullID.MatchString(id) {
		return &FatalError{errors.New("invalid created container ID")}
	}
	data, err := podmanOutput(ctx, "container", "inspect", "--", id)
	if err != nil {
		return &FatalError{fmt.Errorf("inspect created container: %w", err)}
	}
	return s.checkInspection(id, data)
}

type bindMount struct {
	Type, Source, Destination string
	RW                        *bool
}

type containerInspection struct {
	ID, Image, Path, OCIRuntime string
	Args                        []string
	EffectiveCaps, BoundingCaps json.RawMessage
	Mounts                      []bindMount
	UseImageHosts               *bool
	Config                      struct {
		User                 string
		Env, Entrypoint, Cmd []string
		Labels               map[string]string
		Timeout              int64
		OpenStdin            bool
	}
	HostConfig struct {
		NetworkMode, UsernsMode                            string
		ReadonlyRootfs, AutoRemove                         bool
		Privileged                                         *bool
		LogConfig                                          struct{ Type string }
		SecurityOpt                                        []string
		Memory, MemorySwap, PidsLimit, CpuPeriod, CpuQuota int64
		Devices                                            []json.RawMessage
		Tmpfs                                              map[string]string
		IDMappings                                         struct{ UIDMap, GIDMap []string }
	}
}

func (s createSpec) checkInspection(id string, data []byte) error {
	var c containerInspection
	if err := decodeInspect(data, &c); err != nil {
		return &FatalError{err}
	}
	h := &c.HostConfig
	switch {
	case !fullID.MatchString(id) || c.ID != id || c.Image != s.image.imageID || c.OCIRuntime != "crun":
		return &FatalError{errors.New("unexpected container, image or runtime")}
	case !h.AutoRemove || !c.Config.OpenStdin || h.LogConfig.Type != "none" || c.Config.Timeout != s.lifetimeSeconds() || c.Config.Labels["telltale.run"] != s.runID:
		return &FatalError{errors.New("container lifecycle settings mismatch")}
	case h.NetworkMode != "none" || !h.ReadonlyRootfs || h.Privileged == nil || *h.Privileged || c.UseImageHosts == nil || !*c.UseImageHosts:
		return &FatalError{errors.New("container isolation settings mismatch")}
	case !emptyCaps(c.EffectiveCaps) || !emptyCaps(c.BoundingCaps) || !securityOptAllowed(h.SecurityOpt):
		return &FatalError{errors.New("container capability or privilege settings mismatch")}
	case s.uid <= 0 || c.Config.User != s.user() || h.UsernsMode != "private" ||
		!slices.Contains(h.IDMappings.UIDMap, strconv.Itoa(s.uid)+":0:1") ||
		!slices.Contains(h.IDMappings.GIDMap, strconv.Itoa(s.gid)+":0:1"):
		// In Podman's rootless parent namespace, ID 0 is the invoking user.
		return &FatalError{errors.New("container user or keep-id mapping mismatch")}
	case h.Memory != 512<<20 || h.MemorySwap != 512<<20 || h.PidsLimit != 64 || h.CpuPeriod != 100000 || h.CpuQuota != 100000:
		return &FatalError{errors.New("container resource limits mismatch")}
	case h.Devices == nil || len(h.Devices) != 0:
		return &FatalError{errors.New("unexpected or missing container device list")}
	case !s.bindsMatch(c.Mounts) || len(h.Tmpfs) != 1 || !scratchOptions(h.Tmpfs["/tmp"]):
		return &FatalError{errors.New("container mounts mismatch")}
	case !s.envMatches(c.Config.Env):
		return &FatalError{errors.New("container environment mismatch")}
	case !c.argvMatches(s.argv()):
		return &FatalError{errors.New("container argv mismatch")}
	}
	return nil
}

func emptyCaps(raw json.RawMessage) bool {
	// Podman serializes an empty capability slice as [] or null. An absent
	// field provides no evidence at all.
	var caps []string
	return len(raw) != 0 && json.Unmarshal(raw, &caps) == nil && len(caps) == 0
}

func securityOptAllowed(opts []string) bool {
	hasNoNewPrivs := false
	for _, opt := range opts {
		switch opt {
		case "no-new-privileges":
			hasNoNewPrivs = true
		case "label=disable", "label:disable",
			"seccomp=unconfined", "seccomp:unconfined",
			"apparmor=unconfined", "apparmor:unconfined",
			"no-new-privileges=false", "no-new-privileges:false":
			return false
		default:
			if strings.HasPrefix(opt, "unmask=") || strings.HasPrefix(opt, "unmask:") {
				return false
			}
		}
	}
	return hasNoNewPrivs
}

func (s createSpec) bindsMatch(mounts []bindMount) bool {
	if len(mounts) != 2 {
		return false
	}
	var workspace, restricted bool
	for _, m := range mounts {
		if m.Type != "bind" || m.RW == nil {
			return false
		}
		switch m.Destination {
		case "/workspace":
			workspace = m.Source == s.workspace && *m.RW
		case "/restricted":
			restricted = m.Source == s.restricted && !*m.RW
		}
	}
	return workspace && restricted
}

func scratchOptions(raw string) bool {
	var required []string
	for opt := range strings.SplitSeq(raw, ",") {
		switch opt {
		case "rw", "noexec", "nosuid", "nodev":
			required = append(required, opt)
		case "size=64m", "size=65536k", "size=67108864":
			required = append(required, "64m")
		case "private", "rprivate", "tmpcopyup":
			// Podman can include its default propagation and copy-up options.
		default:
			return false
		}
	}
	slices.Sort(required)
	return slices.Equal(required, []string{"64m", "nodev", "noexec", "nosuid", "rw"})
}

func (s createSpec) envMatches(entries []string) bool {
	env, err := envMap(entries)
	if err != nil || env["HOME"] != "/tmp" || env["PYTHONDONTWRITEBYTECODE"] != "1" {
		return false
	}
	delete(env, "HOME")
	delete(env, "PYTHONDONTWRITEBYTECODE")
	for key, value := range env {
		if imageValue, exists := s.image.imageEnv[key]; !exists || value != imageValue {
			return false
		}
	}
	return true
}

func (c *containerInspection) argvMatches(want []string) bool {
	if len(want) == 0 || want[0] == "" || want[0] != c.Path || c.Args == nil {
		return false
	}
	// Podman 5 can emit the executable in both Path and Args for a
	// one-word command. Disambiguate that shape using Config as well.
	if len(c.Args) == 1 && c.Args[0] == c.Path {
		configured := slices.Concat(c.Config.Entrypoint, c.Config.Cmd)
		return slices.Equal(configured, want) && (len(want) == 1 || slices.Equal(want[1:], c.Args))
	}
	return slices.Equal(want[1:], c.Args)
}
