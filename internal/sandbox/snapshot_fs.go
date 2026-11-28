package sandbox

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"
)

const (
	maxEntries        = 10_000
	maxDepth          = 32
	maxWorkspaceBytes = 256 << 20
	fullHashLimit     = 8 << 20
	hashWindow        = 1 << 20
	watchInterval     = 250 * time.Millisecond
	// Linux O_PATH pins an inode without opening a device or blocking on a FIFO.
	pathOnly = 0x200000
)

var (
	ErrResourceLimit     = errors.New("resource_limit")
	ErrUnstableWorkspace = errors.New("noisy_workspace")
)

type FileEntry struct {
	Mode        fs.FileMode // includes the file type
	Size        int64
	SHA256      [sha256.Size]byte
	PartialHash bool
	LinkTarget  string
	// Identity matters for multiply linked files, even if their bytes match.
	HardlinkDevice, HardlinkInode, Links uint64
}

type WorkspaceSnapshot map[string]FileEntry

type WorkspaceDiff struct{ Added, Removed, Changed []string }

func (before WorkspaceSnapshot) Diff(after WorkspaceSnapshot) WorkspaceDiff {
	var d WorkspaceDiff
	for path, previous := range before {
		current, ok := after[path]
		switch {
		case !ok:
			d.Removed = append(d.Removed, path)
		case current != previous:
			d.Changed = append(d.Changed, path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			d.Added = append(d.Added, path)
		}
	}
	slices.Sort(d.Added)
	slices.Sort(d.Removed)
	slices.Sort(d.Changed)
	return d
}

func (f SessionFixtures) Snapshot(ctx context.Context) (WorkspaceSnapshot, error) {
	snapshot := make(WorkspaceSnapshot)
	w := workspaceWalk{snapshot: snapshot}
	if err := w.observe(ctx, f.workspace); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// A nil snapshot selects the metadata-only watchdog walk.
type workspaceWalk struct {
	snapshot  WorkspaceSnapshot
	count     int
	bytes     int64
	hardlinks map[[2]uint64]bool
}

func (w *workspaceWalk) observe(ctx context.Context, workspace string) error {
	// The bind source has a private parent that the target cannot access.
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return ErrUnstableWorkspace
	}
	defer func() { _ = root.Close() }()
	// The caller's session deadline normally expires first.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = w.walk(ctx, root, ".", 0)
	if err != nil && !errors.Is(err, ErrResourceLimit) && ctx.Err() == nil {
		// An inaccessible or unstable tree cannot provide a usable observation.
		// Avoid propagating target-controlled path components into diagnostics.
		return ErrUnstableWorkspace
	}
	return err
}

func (w *workspaceWalk) walk(ctx context.Context, root *os.Root, rel string, depth int) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	before, err := dir.Stat()
	if err != nil {
		return err
	}
	if w.snapshot != nil {
		w.snapshot[rel] = FileEntry{Mode: before.Mode()}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, readErr := dir.Readdirnames(128)
		w.count += len(names)
		if w.count > maxEntries || (depth >= maxDepth && len(names) > 0) {
			return ErrResourceLimit
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			info, err := root.Lstat(name)
			if err != nil {
				return err
			}
			if err := w.entry(ctx, root, name, filepath.Join(rel, name), depth+1, info); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if w.snapshot != nil {
		after, err := dir.Stat()
		if err != nil || !stable(before, after) {
			return ErrUnstableWorkspace
		}
	}
	return ctx.Err()
}

// Each name is one directory entry in an already pinned parent. O_PATH plus
// O_NOFOLLOW pins even a substituted symlink without dereferencing it. Only a
// verified regular file or directory is reopened through its kernel fd link.
func (w *workspaceWalk) entry(ctx context.Context, root *os.Root, name, rel string, depth int, before fs.FileInfo) error {
	pin, err := root.OpenFile(name, pathOnly|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = pin.Close() }()
	info, err := pin.Stat()
	if err != nil || !os.SameFile(before, info) || before.Mode().Type() != info.Mode().Type() {
		return ErrUnstableWorkspace
	}
	fdPath := fmt.Sprintf("/proc/self/fd/%d", pin.Fd())
	switch {
	case info.IsDir():
		child, err := os.OpenRoot(fdPath)
		if err != nil {
			return err
		}
		defer func() { _ = child.Close() }()
		if err := w.walk(ctx, child, rel, depth); err != nil {
			return err
		}
	case w.snapshot == nil:
		if err := w.charge(info); err != nil {
			return err
		}
	default:
		e := FileEntry{Mode: info.Mode(), Size: info.Size()}
		switch {
		case info.Mode().IsRegular():
			e.SHA256, e.PartialHash, err = hashFile(fdPath, info.Size())
		case info.Mode()&fs.ModeSymlink != 0:
			e.LinkTarget, err = root.Readlink(name)
		}
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		if stat.Nlink > 1 {
			e.HardlinkDevice, e.HardlinkInode, e.Links = stat.Dev, stat.Ino, stat.Nlink
		}
		w.snapshot[rel] = e
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, after) || (w.snapshot != nil && !stable(info, after)) {
		return ErrUnstableWorkspace
	}
	return nil
}

func stable(a, b fs.FileInfo) bool {
	return a.Mode() == b.Mode() && a.Size() == b.Size() && a.Sys().(*syscall.Stat_t).Ctim == b.Sys().(*syscall.Stat_t).Ctim
}

func (w *workspaceWalk) charge(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return nil
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink > 1 {
		key := [2]uint64{st.Dev, st.Ino}
		if w.hardlinks[key] {
			return nil
		}
		if w.hardlinks == nil {
			w.hardlinks = make(map[[2]uint64]bool)
		}
		w.hardlinks[key] = true
	}
	if info.Size() > maxWorkspaceBytes-w.bytes {
		return ErrResourceLimit
	}
	w.bytes += info.Size()
	return nil
}

func hashFile(fdPath string, size int64) ([sha256.Size]byte, bool, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(fdPath) //nolint:gosec // G304: kernel descriptor for a pinned, verified regular file.
	if err != nil {
		return sum, false, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	partial := size > fullHashLimit
	if partial {
		if _, err = io.CopyN(h, f, hashWindow); err == nil {
			_, err = io.CopyN(h, io.NewSectionReader(f, size-hashWindow, hashWindow), hashWindow)
		}
	} else {
		_, err = io.CopyN(h, f, size)
	}
	if err != nil {
		return sum, false, err
	}
	copy(sum[:], h.Sum(nil))
	return sum, partial, nil
}

const maxWatchUnstable = 3

// armWatchdog schedules the first sample before the attach process starts.
// Its independent context keeps sampling during graceful and forced teardown.
// The owner must stop and join it, including when cmd.Start fails.
func armWatchdog(session context.Context, workspace string, abort context.CancelCauseFunc) func() error {
	ctx, stop := context.WithCancel(context.WithoutCancel(session))
	var outcome error
	done := make(chan struct{})
	ticker := time.NewTicker(watchInterval)
	go func() {
		defer close(done)
		defer ticker.Stop()
		unstable := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var w workspaceWalk
				err := w.observe(ctx, workspace)
				if err == nil {
					unstable = 0
					continue
				}
				if ctx.Err() != nil {
					return
				}
				if errors.Is(err, ErrUnstableWorkspace) {
					unstable++
					if unstable < maxWatchUnstable {
						continue
					}
				}
				outcome = err
				abort(err)
				return
			}
		}
	}()
	return func() error {
		stop()
		<-done
		return outcome
	}
}
