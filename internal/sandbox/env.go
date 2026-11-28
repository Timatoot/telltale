// Package sandbox implements the local rootless Podman isolation boundary.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func podmanEnv() []string {
	env := []string{"LANG=C.UTF-8"}
	for _, key := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func podmanCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "podman", args...)
	cmd.Env = podmanEnv()
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	return cmd
}

// Podman diagnostics and inspect data can contain environment values. Never
// include either stream or the supplied arguments in a returned error.
func podmanOutput(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := podmanCommand(ctx, args...)
	out := metadataOutput{cancel: cancel}
	cmd.Stdout = &out
	err := cmd.Run()
	switch {
	case out.overflow:
		return nil, errors.New("metadata output exceeds the Podman limit")
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, fmt.Errorf("run Podman: %w", err)
	default:
		return out.buf.Bytes(), nil
	}
}

const metadataLimit = 4 << 20

type metadataOutput struct {
	buf      bytes.Buffer
	cancel   context.CancelFunc
	overflow bool
}

func (o *metadataOutput) Write(p []byte) (int, error) {
	if len(p) > metadataLimit-o.buf.Len() {
		o.overflow = true
		o.cancel()
		return 0, errors.New("metadata limit exceeded")
	}
	return o.buf.Write(p)
}
