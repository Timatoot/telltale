package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Timatoot/telltale/internal/mcpclient"
)

const cleanupTimeout = 10 * time.Second

var (
	errGraceStop = errors.New("session closing")
	gracePeriod  = 2 * time.Second
	exitGrace    = 250 * time.Millisecond
)

func wrapTimeout(err error) error {
	if errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, mcpclient.ErrTimeout) {
		return errors.Join(mcpclient.ErrTimeout, err)
	}
	return err
}

func exitedWithin(ctx context.Context, exited <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-exited:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		return false
	}
}

// SessionFixtures carries the two bind sources allocated by FixtureManager.
// Callers cannot supply arbitrary paths for Podman's private SELinux relabel.
type SessionFixtures struct{ workspace, restricted string }

func (f SessionFixtures) Workspace() string { return f.workspace }

// SessionSpec binds a preflighted image to manager-owned fixtures.
type SessionSpec struct{ createSpec }

func (f SessionFixtures) SessionSpec(image RuntimeInfo, runID string, timeout time.Duration, argv []string) SessionSpec {
	return SessionSpec{newCreateSpec(image, f.workspace, f.restricted, runID, timeout, argv)}
}

type Session struct {
	id      string
	spec    createSpec
	started atomic.Bool
}

var runLabel = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func (r ContainerRuntime) CreateSession(ctx context.Context, spec SessionSpec) (*Session, error) {
	s := spec.createSpec
	if !runLabel.MatchString(s.runID) {
		return nil, &FatalError{errors.New("invalid run label")}
	}
	args, err := s.args()
	if err != nil {
		return nil, err
	}
	data, err := podmanOutput(ctx, args...)
	id := strings.TrimSpace(string(data))
	if err != nil || !fullID.MatchString(id) {
		// Create may have reached the runtime even when its output was lost.
		return nil, errors.Join(&FatalError{errors.Join(errors.New("create container failed"), err)}, r.ForceCleanup(ctx, s.runID))
	}
	if err := s.inspectCreated(ctx, id); err != nil {
		return nil, errors.Join(err, removeSession(ctx, id))
	}
	return &Session{id: id, spec: s}, nil
}

func removeSession(ctx context.Context, id string) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	_, err := podmanOutput(cleanup, "rm", "--force", "--time", "0", "--ignore", "--", id)
	return err
}

func (ContainerRuntime) ForceCleanup(ctx context.Context, runID string) error {
	if !runLabel.MatchString(runID) {
		return errors.New("invalid cleanup label")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	ids, err := podmanOutput(ctx, "ps", "--all", "--no-trunc", "--filter", "label=telltale.run="+runID, "--format", "{{.ID}}")
	if err != nil {
		return fmt.Errorf("list run containers: %w", err)
	}
	var failures []error
	for id := range strings.FieldsSeq(string(ids)) {
		if err := ctx.Err(); err != nil {
			return errors.Join(errors.Join(failures...), err)
		}
		if !fullID.MatchString(id) {
			return errors.New("invalid container ID in run listing")
		}
		if _, err := podmanOutput(ctx, "rm", "--force", "--time", "0", "--ignore", "--", id); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// StdioSession uses the MCP client's bounded stderr ring and redaction.
// Close closes stdin, gives the target a bounded grace period, and joins teardown.
type StdioSession struct {
	*mcpclient.Client
	lifetime context.Context
	stdin    io.WriteCloser
	stop     context.CancelCauseFunc
	exited   chan struct{}
	done     chan struct{}
	closing  atomic.Bool
	err      error // published by closing done
}

// Context bounds snapshots and settling waits to the lifetime of this session.
// Its cancellation cause preserves watchdog failures during non-RPC work.
func (s *StdioSession) Context() context.Context { return s.lifetime }

func (s *StdioSession) Close() error {
	s.closing.Store(true)
	_ = s.stdin.Close()
	timer := time.NewTimer(gracePeriod)
	select {
	case <-s.exited:
	case <-timer.C:
		s.stop(errGraceStop)
	}
	timer.Stop()
	<-s.done
	_ = s.Client.Close()
	return s.err
}

func (s *Session) Start(ctx context.Context) (*StdioSession, error) {
	return s.start(ctx, "/sys/fs/cgroup")
}

func (s *Session) start(parent context.Context, cgroupRoot string) (*StdioSession, error) {
	if !s.started.CompareAndSwap(false, true) {
		return nil, errors.New("session already started")
	}
	deadline, release := context.WithTimeout(parent, s.spec.timeout)
	ctx, stop := context.WithCancelCause(deadline)
	cmd := podmanCommand(ctx, "start", "--attach", "--interactive", "--", s.id)
	// Own the read ends separately from Cmd.Wait, which can run while the
	// client is still consuming the last output from an exiting container.
	stdout, out, err := os.Pipe()
	if err != nil {
		stop(err)
		release()
		return nil, errors.Join(err, removeSession(ctx, s.id))
	}
	defer func() { _ = out.Close() }()
	stderr, diag, err := os.Pipe()
	if err != nil {
		_ = stdout.Close()
		stop(err)
		release()
		return nil, errors.Join(err, removeSession(ctx, s.id))
	}
	defer func() { _ = diag.Close() }()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		stop(err)
		release()
		return nil, errors.Join(err, removeSession(ctx, s.id))
	}
	cmd.Stdout, cmd.Stderr = out, diag
	joinWatch := armWatchdog(ctx, s.spec.workspace, stop)
	err = cmd.Start()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		stop(err)
		release()
		return nil, errors.Join(err, removeSession(ctx, s.id), joinWatch())
	}

	stream := &StdioSession{lifetime: ctx, stdin: stdin, stop: stop, done: make(chan struct{}), exited: make(chan struct{})}
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(stream.exited)
	}()
	go func() {
		select {
		case <-stream.exited:
		case <-ctx.Done():
		}
		// Stop the container as soon as a limit trips, even if the local
		// attach process is still handling its cancellation signal.
		cleanupErr := removeSession(ctx, s.id)
		<-stream.exited
		watchErr := joinWatch()
		cause := context.Cause(ctx)
		switch {
		case errors.Is(cause, errGraceStop):
			cause = nil
		case cause == nil && !stream.closing.Load():
			cause = errors.Join(mcpclient.ErrServerCrash, waitErr)
		default:
			cause = wrapTimeout(cause)
		}
		stream.err = errors.Join(cause, cleanupErr, watchErr)
		stop(cause)
		release()
		close(stream.done)
	}()
	if err := s.checkRunning(ctx, cgroupRoot, stream.exited); err != nil {
		stop(err)
		_ = stdout.Close()
		_ = stderr.Close()
		<-stream.done
		return nil, errors.Join(err, stream.err)
	}
	stream.Client = mcpclient.New(ctx, stdin, stdout, stderr)
	return stream, nil
}

func (s *Session) checkRunning(ctx context.Context, cgroupRoot string, exited <-chan struct{}) error {
	for {
		data, err := podmanOutput(ctx, "container", "inspect", "--format", "{{json .State}}", "--", s.id)
		if cause := context.Cause(ctx); cause != nil {
			return wrapTimeout(cause)
		}
		select {
		case <-exited:
			return mcpclient.ErrServerCrash
		default:
		}
		var state struct{ Status, CgroupPath string }
		if err != nil || json.Unmarshal(data, &state) != nil {
			if exitedWithin(ctx, exited, exitGrace) {
				return mcpclient.ErrServerCrash
			}
			if cause := context.Cause(ctx); cause != nil {
				return wrapTimeout(cause)
			}
			return &FatalError{errors.New("cannot inspect started container")}
		}
		switch state.Status {
		case "running":
			err := checkCgroup(cgroupRoot, state.CgroupPath)
			if err == nil {
				return nil
			}
			if errors.Is(err, fs.ErrNotExist) && exitedWithin(ctx, exited, exitGrace) {
				return mcpclient.ErrServerCrash
			}
			if cause := context.Cause(ctx); cause != nil {
				return wrapTimeout(cause)
			}
			return err
		case "configured", "created", "initialized":
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return wrapTimeout(context.Cause(ctx))
			case <-exited:
				timer.Stop()
				return mcpclient.ErrServerCrash
			case <-timer.C:
			}
		case "exited", "stopped", "removing":
			return mcpclient.ErrServerCrash
		default:
			return &FatalError{errors.New("unexpected container state at start")}
		}
	}
}

func checkCgroup(base, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return &FatalError{errors.New("missing or malformed container cgroup path")}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return &FatalError{fmt.Errorf("open cgroup filesystem: %w", err)}
	}
	defer func() { _ = root.Close() }()
	group, err := root.OpenRoot(strings.TrimPrefix(path, "/"))
	if err != nil {
		return &FatalError{fmt.Errorf("open container cgroup: %w", err)}
	}
	defer func() { _ = group.Close() }()
	for _, limit := range []struct{ file, want string }{
		{"memory.max", "536870912"}, {"pids.max", "64"}, {"cpu.max", "100000 100000"},
	} {
		f, err := group.Open(limit.file)
		if err != nil {
			return &FatalError{fmt.Errorf("open %s: %w", limit.file, err)}
		}
		data, err := io.ReadAll(io.LimitReader(f, 128))
		_ = f.Close()
		if err != nil {
			return &FatalError{fmt.Errorf("read %s: %w", limit.file, err)}
		}
		if len(data) == 128 || strings.TrimSpace(string(data)) != limit.want {
			return &FatalError{fmt.Errorf("post-start %s mismatch", limit.file)}
		}
	}
	return nil
}
