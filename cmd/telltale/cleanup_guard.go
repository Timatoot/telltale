package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Timatoot/telltale/internal/sandbox"
)

const guardArg = "__cleanup_guard"
const guardWait = 70 * time.Second

type runResources struct {
	ID  string
	Dir string
}

type cleanupGuard struct {
	runResources
	owner *os.File
	done  <-chan error
}

func startCleanupGuard(ctx context.Context) (*cleanupGuard, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	live, owner, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer func() { _ = live.Close() }()
	reply, ready, err := os.Pipe()
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	defer func() { _ = reply.Close() }()

	// The helper outlives audit cancellation. Only it inherits the read end
	// of the ownership pipe. Both parent descriptors are close-on-exec.
	cmd := exec.CommandContext(context.WithoutCancel(ctx), exe, guardArg) //nolint:gosec // Re-exec our own binary with a constant argument.
	cmd.Env = []string{"LANG=C.UTF-8"}
	for _, key := range []string{"PATH", "HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Stdin = live
	cmd.ExtraFiles = []*os.File{ready}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Start()
	_ = ready.Close()
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	g := &cleanupGuard{owner: owner, done: done}

	stop := context.AfterFunc(ctx, func() { _ = reply.Close() })
	defer stop()
	err = reply.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err == nil {
		err = json.NewDecoder(io.LimitReader(reply, 32<<10)).Decode(&g.runResources)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("cleanup guard readiness: %w", err), g.close())
	}
	return g, nil
}

func (g *cleanupGuard) close() error {
	_, writeErr := g.owner.Write([]byte{'D'})
	closeErr := g.owner.Close()
	timer := time.NewTimer(guardWait)
	defer timer.Stop()
	select {
	case err := <-g.done:
		return errors.Join(writeErr, closeErr, err)
	case <-timer.C:
		return errors.Join(writeErr, closeErr, errors.New("cleanup guard did not acknowledge teardown"))
	}
}

func cleanupGuardMain() int {
	reply := os.NewFile(3, "guard-readiness")
	if reply == nil {
		return exitFatalError
	}
	defer func() { _ = reply.Close() }()
	syscall.CloseOnExec(3)
	if err := serveGuard(os.Stdin, reply, sandbox.ContainerRuntime{}.ForceCleanup, 31*time.Second); err != nil {
		return exitFatalError
	}
	return exitPass
}

func serveGuard(owner io.Reader, reply io.Writer, cleanup func(context.Context, string) error, settle time.Duration) error {
	id := rand.Text()
	parent, err := filepath.Abs(os.TempDir())
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(parent, "telltale-run-"+id+"-")
	if err != nil {
		return err
	}

	if err := json.NewEncoder(reply).Encode(runResources{ID: id, Dir: dir}); err != nil {
		return errors.Join(err, removeRunTree(dir))
	}

	// 'A' arms container reconciliation after rootless preflight. Before
	// then there can only be host files. 'D' means all owner operations
	// have returned. EOF without it may race an outstanding runtime create.
	var msg [1]byte
	_, err = io.ReadFull(owner, msg[:])
	if err == nil && msg[0] == 'A' {
		_, err = io.ReadFull(owner, msg[:])
		if err != nil || msg[0] != 'D' {
			time.Sleep(settle)
		}
		var cleanupErr error
		for range 3 {
			cleanupErr = cleanup(context.Background(), id)
			if cleanupErr == nil {
				break
			}
		}
		if cleanupErr != nil {
			return fmt.Errorf("cleanup run containers: %w", cleanupErr)
		}
	}
	return removeRunTree(dir)
}

// Containers are gone before this walk. OpenRoot confines permission repair
// and WalkDir never follows target-created symlinks.
func removeRunTree(dir string) error {
	err := os.RemoveAll(dir)
	if !errors.Is(err, fs.ErrPermission) {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return root.Chmod(path, 0o700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}
