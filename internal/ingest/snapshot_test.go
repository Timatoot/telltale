package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/model"
)

func tempRoot(t *testing.T) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func write(t *testing.T, r *os.Root, name string, data []byte) {
	t.Helper()
	if err := r.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func snapshot(t *testing.T, repo *os.Root) *Snapshot {
	t.Helper()
	s, err := CreateSnapshot(t.Context(), repo.Name(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestSnapshotContentsAndClose(t *testing.T) {
	repo := tempRoot(t)
	files := map[string][]byte{
		"pkg/source.py": []byte("\xef\xbb\xbf# nosemgrep\r\n\x00\xff\r\n"),
		"pkg.py":        bytes.Repeat([]byte("a"), 1<<20),
	}
	for name, data := range files {
		write(t, repo, name, data)
	}
	for _, name := range []string{".git/hook.py", "pkg/.git/private.py", ".gitignore", ".semgrepignore", "pkg/.semgrepignore", "README"} {
		write(t, repo, name, []byte("*"))
	}

	parent := filepath.Join(repo.Name(), "scratch")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := CreateSnapshot(t.Context(), repo.Name(), parent)
	if err != nil {
		t.Fatal(err)
	}
	path := s.Root().Name()
	if filepath.Dir(path) != parent {
		t.Fatalf("unexpected snapshot parent for %q", path)
	}
	info, err := s.Root().Stat(".")
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot permissions: %v, %v", info, err)
	}
	if want := []string{"pkg.py", "pkg/source.py"}; !slices.Equal(s.Files, want) || len(s.FilesSkipped) != 0 {
		t.Fatalf("unexpected manifest: %v, skips %v", s.Files, s.FilesSkipped)
	}
	var contents []string
	err = fs.WalkDir(s.Root().FS(), ".", func(name string, _ fs.DirEntry, err error) error {
		contents = append(contents, name)
		return err
	})
	if err != nil || !slices.Equal(contents, []string{".", ".semgrepignore", "pkg", "pkg/source.py", "pkg.py"}) {
		t.Fatalf("unexpected snapshot tree: %v, %v", contents, err)
	}
	ignore, err := s.Root().ReadFile(".semgrepignore")
	if err != nil || len(ignore) != 0 {
		t.Fatalf("snapshot ignore contents = %q, %v", ignore, err)
	}
	for name, want := range files {
		write(t, repo, name, []byte("changed after ingest"))
		got, err := s.Root().ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("snapshot bytes differ for %q: %v", name, err)
		}
		for _, path := range []string{name, filepath.Join(path, name)} {
			if rel, ok := s.RepoRelPath(path); !ok || rel != name {
				t.Fatalf("map %q = %q, %v", path, rel, ok)
			}
		}
	}
	for _, unknown := range []string{".semgrepignore", "missing.py", "../pkg.py", filepath.Join(repo.Name(), "pkg.py")} {
		if rel, ok := s.RepoRelPath(unknown); ok {
			t.Fatalf("unexpected mapping %q for %q", rel, unknown)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("snapshot cleanup: %v, %v", entries, err)
	}
}

func TestSpecialEntries(t *testing.T) {
	repo := tempRoot(t)
	for name, target := range map[string]string{"a": "b", "b": "a", "outside.py": "/etc/passwd"} {
		if err := repo.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(repo.Name(), "pipe.py"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(repo.Name(), "sock")
	sock, err := net.Listen("unix", sockPath)
	if errors.Is(err, syscall.EPERM) {
		// Some test sandboxes forbid socket() but permit a real filesystem socket inode.
		err = syscall.Mknod(sockPath, syscall.S_IFSOCK|0o600, 0)
	}
	if err != nil {
		t.Fatal(err)
	}
	if sock != nil {
		defer func() { _ = sock.Close() }()
	}
	s := snapshot(t, repo)
	want := []model.SkippedFile{
		{Path: "a", Reason: model.Symlink}, {Path: "b", Reason: model.Symlink},
		{Path: "outside.py", Reason: model.Symlink}, {Path: "pipe.py", Reason: model.NonRegular},
		{Path: "sock", Reason: model.NonRegular},
	}
	if len(s.Files) != 0 || !slices.Equal(want, s.FilesSkipped) {
		t.Fatalf("files %v, skips %v", s.Files, s.FilesSkipped)
	}
	for _, mode := range []fs.FileMode{fs.ModeDevice, fs.ModeDevice | fs.ModeCharDevice} {
		if reason := typeReason(mode); reason != model.NonRegular {
			t.Fatalf("device %v classified as %q", mode, reason)
		}
	}
}

func TestSubstitutionAfterLstat(t *testing.T) {
	for _, kind := range []string{"link", "fifo", "different regular file"} {
		t.Run(kind, func(t *testing.T) {
			repo := tempRoot(t)
			const name = "source.py"
			write(t, repo, name, []byte("original"))
			write(t, repo, "other", []byte("substituted"))
			dir, err := repo.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dir.Close() }()
			before, err := repo.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.Rename(name, "original"); err != nil {
				t.Fatal(err)
			}
			var want model.SkipReason
			switch kind {
			case "link":
				err = repo.Symlink("other", name)
				want = model.Symlink
			case "fifo":
				err = syscall.Mkfifo(filepath.Join(repo.Name(), name), 0o600)
				want = model.NonRegular
			default:
				err = repo.Rename("other", name)
			}
			if err != nil {
				t.Fatal(err)
			}

			w := walker{snap: &Snapshot{root: tempRoot(t)}}
			type result struct {
				reason model.SkipReason
				err    error
			}
			done := make(chan result, 1)
			go func() {
				reason, err := w.visit(t.Context(), dir, name, name, 0, before)
				done <- result{reason, err}
			}()
			select {
			case got := <-done:
				if got.reason != want || (got.err != nil) != (kind == "different regular file") {
					t.Fatalf("substituted entry: %q, %v", got.reason, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("opening the replacement blocked")
			}
			if _, err := w.snap.Root().Lstat(name); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("unexpected destination after substitution: %v", err)
			}
		})
	}
}

func TestCandidateCount(t *testing.T) {
	repo := tempRoot(t)
	for i := 10_000; i >= 0; i-- {
		write(t, repo, fmt.Sprintf("%05d.py", i), nil)
	}
	s := snapshot(t, repo)
	if len(s.Files) != 10_000 || !slices.Equal(s.FilesSkipped, []model.SkippedFile{{Path: "10000.py", Reason: model.CountCap}}) {
		t.Fatalf("copied %d, skips %v", len(s.Files), s.FilesSkipped)
	}
	if _, err := s.Root().Stat("10000.py"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("over-budget file: %v", err)
	}
}

func TestSourceByteBudgets(t *testing.T) {
	repo := tempRoot(t)
	write(t, repo, "oversize.py", make([]byte, (1<<20)+1))
	write(t, repo, "source", make([]byte, 1<<20))
	for i := range 65 {
		if err := repo.Link("source", fmt.Sprintf("%02d.py", i)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, repo, "zero.py", nil)
	s := snapshot(t, repo)
	want := []model.SkippedFile{{Path: "64.py", Reason: model.TotalCap}, {Path: "oversize.py", Reason: model.SizeCap}}
	if len(s.Files) != 65 || !slices.Contains(s.Files, "zero.py") || !slices.Equal(s.FilesSkipped, want) {
		t.Fatalf("copied %d, skips %v", len(s.Files), s.FilesSkipped)
	}
	for _, entry := range want {
		if _, err := s.Root().Stat(entry.Path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("over-budget destination %q: %v", entry.Path, err)
		}
	}
}

func TestCopyBoundsActualReads(t *testing.T) {
	for _, tc := range []struct {
		total, limit int64
		reason       model.SkipReason
	}{{0, 1 << 20, model.SizeCap}, {(64 << 20) - 8, 8, model.TotalCap}} {
		w := walker{snap: &Snapshot{root: tempRoot(t)}, total: tc.total}
		source := bytes.NewReader(make([]byte, (1<<20)+100))
		reason, err := w.copyFile(source, "growing.py")
		if err != nil || reason != tc.reason || w.total != tc.total+tc.limit || source.Size()-int64(source.Len()) != tc.limit+1 {
			t.Fatalf("growth check: reason %q, remaining %d, err %v", reason, source.Len(), err)
		}
		if _, err := w.snap.Root().Stat("growing.py"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("growth left partial copy: %v", err)
		}
	}
}

func TestTraversalGuards(t *testing.T) {
	repo := tempRoot(t)
	write(t, repo, "plain.txt", nil)
	w := walker{entries: maxEntries - 1}
	if err := w.walk(t.Context(), repo, "", 0); err != nil {
		t.Fatalf("exact entry cap: %v", err)
	}
	if err := w.walk(t.Context(), repo, "", 0); err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("missing entry limit: %v", err)
	}

	parent := t.TempDir()
	parts := strings.Repeat("d/", maxDepth)
	write(t, repo, parts+"source.py", nil)
	s := snapshot(t, repo)
	if !slices.Equal(s.Files, []string{parts + "source.py"}) {
		t.Fatalf("exact depth cap: %v", s.Files)
	}
	write(t, repo, parts+"d/ignored.txt", nil)
	if _, err := CreateSnapshot(t.Context(), repo.Name(), parent); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("missing depth limit: %v", err)
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := CreateSnapshot(ctx, repo.Name(), parent); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing deadline: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed ingest left temp files: %v, %v", entries, err)
	}
}

func TestRenamedParentUsesPinnedDirectory(t *testing.T) {
	repo := tempRoot(t)
	write(t, repo, "pkg/source.py", []byte("original"))
	write(t, repo, "other/source.py", []byte("replacement"))
	dir, err := repo.Open("pkg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	before, err := repo.Lstat("pkg/source.py")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Rename("pkg", "moved"); err != nil {
		t.Fatal(err)
	}
	if err := repo.Symlink("other", "pkg"); err != nil {
		t.Fatal(err)
	}
	w := walker{snap: &Snapshot{root: tempRoot(t)}}
	reason, err := w.visit(t.Context(), dir, "source.py", "pkg/source.py", 1, before)
	if reason != "" || err != nil {
		t.Fatalf("pinned directory read: %q, %v", reason, err)
	}
	got, err := w.snap.Root().ReadFile("pkg/source.py")
	if err != nil || string(got) != "original" {
		t.Fatalf("snapshot read %q, %v", got, err)
	}
}
