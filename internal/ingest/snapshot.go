// Package ingest copies untrusted Python source into a private per-run directory.
package ingest

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Timatoot/telltale/internal/model"
)

const (
	maxFiles      = 10_000
	maxFileBytes  = 1 << 20
	maxTotalBytes = 64 << 20
	maxEntries    = 1_000_000
	maxDepth      = 256
	walkTimeout   = 2 * time.Minute
	// Linux/amd64 O_PATH pins an inode without opening it for I/O. The
	// frozen syscall package omits this flag on amd64.
	oPath = 0x200000
)

type Snapshot struct {
	root         *os.Root
	Files        []string // sorted repo-relative POSIX paths
	FilesSkipped []model.SkippedFile
}

func (s *Snapshot) Root() *os.Root { return s.root }

// RepoRelPath maps a known absolute snapshot filename or a relative manifest
// entry back to the repository. Unknown engine paths have no mapping.
func (s *Snapshot) RepoRelPath(snapshotPath string) (string, bool) {
	rel := strings.TrimPrefix(snapshotPath, s.root.Name()+"/")
	if _, ok := slices.BinarySearch(s.Files, rel); ok {
		return rel, true
	}
	return "", false
}

func (s *Snapshot) Close() error {
	return errors.Join(s.root.Close(), os.RemoveAll(s.root.Name()))
}

// CreateSnapshot uses the system temp directory if tempParent is empty.
// Otherwise the caller owns tempParent, and Close removes only its fresh child.
func CreateSnapshot(ctx context.Context, repoPath, tempParent string) (_ *Snapshot, err error) {
	ctx, cancel := context.WithTimeout(ctx, walkTimeout)
	defer cancel()

	// OpenRoot follows its argument. Pin a directory first, so even a FIFO
	// or symlink supplied as the repository itself cannot redirect or block us.
	// Remove trailing slashes (which make Linux dereference a final link)
	// without collapsing caller-supplied ".." components across mount points.
	name := strings.TrimRight(repoPath, "/")
	if name == "" && repoPath != "" {
		name = "/"
	}
	dir, err := os.OpenFile(name, syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: caller-selected root, restricted to a directory.
	if err != nil {
		return nil, fmt.Errorf("open repository directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	repo, err := os.OpenRoot(fdPath(dir))
	if err != nil {
		return nil, fmt.Errorf("pin repository root: %w", err)
	}
	defer func() { _ = repo.Close() }()

	if tempParent == "" {
		tempParent = os.TempDir()
	}
	parent, err := filepath.Abs(tempParent)
	if err != nil {
		return nil, fmt.Errorf("resolve temporary parent: %w", err)
	}
	path, err := os.MkdirTemp(parent, "telltale-snapshot-*")
	if err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(path))
		}
	}()
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open snapshot directory: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, root.Close())
		}
	}()
	if err := root.WriteFile(".semgrepignore", nil, 0o600); err != nil {
		return nil, fmt.Errorf("initialize snapshot: %w", err)
	}
	ownDir, err := root.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("identify snapshot directory: %w", err)
	}
	s := &Snapshot{root: root}
	w := walker{snap: s, ownDir: ownDir}
	if err := w.walk(ctx, repo, "", 0); err != nil {
		return nil, fmt.Errorf("ingest repository: %w", err)
	}
	slices.Sort(s.Files)
	slices.SortFunc(s.FilesSkipped, func(a, b model.SkippedFile) int { return cmp.Compare(a.Path, b.Path) })
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ingest repository: %w", err)
	}
	return s, nil
}

type walker struct {
	snap                *Snapshot
	ownDir              fs.FileInfo
	entries, candidates int
	total               int64
}

// fdPath names a kernel-owned procfs descriptor link. Its owner keeps f open
// until the operation completes. No repository-supplied link is resolved.
func fdPath(f *os.File) string { return fmt.Sprintf("/proc/self/fd/%d", f.Fd()) }

func (w *walker) walk(ctx context.Context, root *os.Root, prefix string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("repository exceeds directory depth limit at %q", prefix)
	}
	dir, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open directory %q: %w", prefix, err)
	}
	defer func() { _ = dir.Close() }()

	var names []string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		batch, err := dir.Readdirnames(512)
		w.entries += len(batch)
		if w.entries > maxEntries {
			return errors.New("repository exceeds entry limit")
		}
		names = append(names, batch...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("list directory %q: %w", prefix, err)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == ".git" || name == ".gitignore" || name == ".semgrepignore" {
			continue
		}
		info, err := root.Lstat(name)
		if err != nil {
			return fmt.Errorf("classify %q: %w", filepath.Join(prefix, name), err)
		}
		rel := filepath.Join(prefix, name)
		reason, err := w.visit(ctx, dir, name, rel, depth, info)
		if err != nil {
			return err
		}
		if reason != "" {
			w.snap.FilesSkipped = append(w.snap.FilesSkipped, model.SkippedFile{Path: rel, Reason: reason})
		}
	}
	return nil
}

func typeReason(mode fs.FileMode) model.SkipReason {
	switch {
	case mode&fs.ModeSymlink != 0:
		return model.Symlink
	case !mode.IsDir() && !mode.IsRegular():
		return model.NonRegular
	default:
		return ""
	}
}

func (w *walker) visit(ctx context.Context, dir *os.File, name, rel string, depth int, info fs.FileInfo) (model.SkipReason, error) {
	if reason := typeReason(info.Mode()); reason != "" {
		return reason, nil
	}
	if info.IsDir() {
		if os.SameFile(info, w.ownDir) {
			return "", nil // TMPDIR or the caller's temp parent can be under the repository.
		}
	} else {
		if !strings.HasSuffix(name, ".py") {
			return "", nil
		}
		w.candidates++
		if w.candidates > maxFiles {
			return model.CountCap, nil
		}
		if reason := w.sizeReason(info.Size()); reason != "" {
			return reason, nil
		}
	}

	// name is a single Readdirnames component in a pinned directory. O_PATH
	// with O_NOFOLLOW pins even a substituted device or link without invoking
	// its driver or following the link.
	pin, err := os.OpenFile(filepath.Join(fdPath(dir), name), oPath|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: descriptor-relative single component, metadata only.
	if err != nil {
		return "", fmt.Errorf("pin entry %q: %w", rel, err)
	}
	defer func() { _ = pin.Close() }()
	actual, err := pin.Stat()
	if err != nil {
		return "", fmt.Errorf("stat pinned entry %q: %w", rel, err)
	}
	if reason := typeReason(actual.Mode()); reason != "" {
		return reason, nil
	}
	if !os.SameFile(info, actual) || info.Mode().Type() != actual.Mode().Type() {
		return "", fmt.Errorf("directory entry changed during ingestion at %q", rel)
	}
	if actual.IsDir() {
		child, err := os.OpenRoot(fdPath(pin))
		if err != nil {
			return "", fmt.Errorf("open pinned directory %q: %w", rel, err)
		}
		defer func() { _ = child.Close() }()
		return "", w.walk(ctx, child, rel, depth+1)
	}
	if reason := w.sizeReason(actual.Size()); reason != "" {
		return reason, nil
	}
	file, err := os.OpenFile(fdPath(pin), os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: kernel link to the verified regular inode.
	if err != nil {
		return "", fmt.Errorf("open pinned source %q: %w", rel, err)
	}
	defer func() { _ = file.Close() }()
	return w.copyFile(file, rel)
}

func (w *walker) sizeReason(size int64) model.SkipReason {
	switch {
	case size > maxFileBytes:
		return model.SizeCap
	case size > maxTotalBytes-w.total:
		return model.TotalCap
	default:
		return ""
	}
}

func (w *walker) copyFile(file io.Reader, rel string) (model.SkipReason, error) {
	// File size is advisory. Detect growth with at most one lookahead byte,
	// and publish a file only after we know its complete contents fit.
	limit := min(int64(maxFileBytes), maxTotalBytes-w.total)
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", fmt.Errorf("read pinned source %q: %w", rel, err)
	}
	size := int64(len(data))
	reason := w.sizeReason(size)
	// Charge discarded reads as well, so repeated growth cannot replenish
	// the run budget. Each candidate can consume one extra lookahead byte.
	w.total += min(size, limit)
	if reason != "" {
		return reason, nil
	}
	if err := w.snap.root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
		return "", fmt.Errorf("create snapshot subdirectory: %w", err)
	}
	if err := w.snap.root.WriteFile(rel, data, 0o600); err != nil {
		return "", fmt.Errorf("write snapshot file: %w", err)
	}
	w.snap.Files = append(w.snap.Files, rel)
	return "", nil
}
