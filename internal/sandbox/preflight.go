package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// FatalError marks an unusable runtime or an isolation assertion failure.
type FatalError struct{ cause error }

func (e *FatalError) Error() string { return "sandbox: " + e.cause.Error() }
func (e *FatalError) Unwrap() error { return e.cause }
func (e *FatalError) ExitCode() int { return 2 }

// ContainerRuntime verifies a locally stored image using the Podman CLI.
type ContainerRuntime struct{ Image string }

// RuntimeInfo pins the image inspected at preflight, including the defaults
// needed to verify the effective environment and command before start.
type RuntimeInfo struct {
	Version   string
	imageID   string
	imageEnv  map[string]string
	imageArgv []string
}

func (r ContainerRuntime) Preflight(ctx context.Context) (RuntimeInfo, error) {
	return r.preflight(ctx, podmanOutput)
}

type podmanRunner func(context.Context, ...string) ([]byte, error)

func (r ContainerRuntime) preflight(ctx context.Context, run podmanRunner) (RuntimeInfo, error) {
	if strings.TrimSpace(r.Image) == "" || strings.HasPrefix(r.Image, "-") {
		return RuntimeInfo{}, &FatalError{errors.New("invalid local image reference")}
	}
	data, err := run(ctx, "info", "--format", "json")
	if err != nil {
		return RuntimeInfo{}, &FatalError{fmt.Errorf("query runtime info: %w", err)}
	}
	version, err := checkHost(data)
	if err != nil {
		return RuntimeInfo{}, &FatalError{err}
	}
	if _, err := run(ctx, "image", "exists", "--", r.Image); err != nil {
		return RuntimeInfo{}, &FatalError{fmt.Errorf("check local image presence: %w", err)}
	}
	data, err = run(ctx, "image", "inspect", "--", r.Image)
	if err != nil {
		return RuntimeInfo{}, &FatalError{fmt.Errorf("inspect local image: %w", err)}
	}
	var image struct {
		ID     string
		Config *struct{ Env, Entrypoint, Cmd []string }
	}
	if err := decodeInspect(data, &image); err != nil {
		return RuntimeInfo{}, &FatalError{err}
	}
	id := strings.TrimPrefix(image.ID, "sha256:")
	if !fullID.MatchString(id) || image.Config == nil {
		return RuntimeInfo{}, &FatalError{errors.New("invalid image identity or config")}
	}
	env, err := envMap(image.Config.Env)
	if err != nil {
		return RuntimeInfo{}, &FatalError{err}
	}
	entry := image.Config.Entrypoint
	if len(entry) == 1 && entry[0] == "" {
		entry = nil
	}
	return RuntimeInfo{Version: version, imageID: id, imageEnv: env, imageArgv: append(entry, image.Config.Cmd...)}, nil
}

var fullID = regexp.MustCompile("^[0-9a-f]{64}$")

// Podman reports major.minor.patch. Also accept the documented 5.0 floor.
const numeric = "(0|[1-9][0-9]*)"
const prereleaseID = "(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*)"

var podmanVersion = regexp.MustCompile("^" + numeric + "\\." + numeric + "(?:\\." + numeric + ")?(?:-(" + prereleaseID + "(?:\\." + prereleaseID + ")*))?(?:\\+[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*)?$")

func checkHost(data []byte) (string, error) {
	var info struct {
		Version struct{ Version string }
		Host    struct {
			Security          struct{ Rootless bool }
			ServiceIsRemote   *bool
			CgroupVersion     string
			CgroupControllers []string
			OCIRuntime        struct{ Name string }
		}
	}
	if len(data) > metadataLimit || json.Unmarshal(data, &info) != nil {
		return "", errors.New("invalid Podman info JSON")
	}
	version := info.Version.Version
	v := podmanVersion.FindStringSubmatch(version)
	switch {
	case v == nil, len(v[1]) == 1 && v[1] < "5":
		return "", errors.New("unsupported Podman version (minimum 5.0)")
	case v[1] == "5" && v[2] == "0" && (v[3] == "" || v[3] == "0") && v[4] != "":
		return "", errors.New("unsupported Podman prerelease below 5.0")
	case !info.Host.Security.Rootless:
		return "", errors.New("expected rootless Podman")
	case info.Host.ServiceIsRemote == nil || *info.Host.ServiceIsRemote:
		return "", errors.New("expected local Podman")
	case info.Host.CgroupVersion != "v2":
		return "", errors.New("expected cgroup v2")
	case info.Host.OCIRuntime.Name != "crun":
		return "", errors.New("expected crun OCI runtime")
	}
	for _, controller := range []string{"cpu", "memory", "pids"} {
		if !slices.Contains(info.Host.CgroupControllers, controller) {
			return "", fmt.Errorf("missing cgroup controller %s", controller)
		}
	}
	return version, nil
}

func decodeInspect[T any](data []byte, dst *T) error {
	if len(data) > metadataLimit || !json.Valid(data) {
		return errors.New("invalid Podman inspect JSON")
	}
	// Read only one element even if a malformed response contains a huge array.
	dec := json.NewDecoder(bytes.NewReader(data))
	open, err := dec.Token()
	if err != nil || open != json.Delim('[') || !dec.More() || dec.Decode(dst) != nil || dec.More() {
		return errors.New("expected one Podman inspect JSON object")
	}
	return nil
}

func envMap(entries []string) (map[string]string, error) {
	env := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if _, duplicate := env[key]; !ok || key == "" || duplicate {
			return nil, errors.New("malformed or duplicate environment entry")
		}
		env[key] = value
	}
	return env, nil
}
