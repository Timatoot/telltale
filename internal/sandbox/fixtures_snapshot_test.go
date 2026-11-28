package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixtureRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestDisposableFixtures(t *testing.T) {
	parent := t.TempDir()
	sibling := filepath.Join(parent, "other-run")
	writeFixture(t, sibling, "untouched")
	var previousID, previousToken string
	for range 2 {
		manager, err := NewFixtureManager(parent)
		if err != nil {
			t.Fatal(err)
		}
		id := manager.FileID()
		token, err := manager.ContentToken()
		if err != nil {
			t.Fatal(err)
		}
		filename, err := hex.DecodeString(id)
		if err != nil || len(filename) < 16 {
			t.Fatal("invalid file ID")
		}
		content, err := hex.DecodeString(token)
		if err != nil || len(content) < 32 || strings.Contains(token, id) || id == previousID || token == previousToken {
			t.Fatal("invalid or repeated canary values")
		}
		previousID, previousToken = id, token
		one, err := manager.NewWorkspace()
		if err != nil {
			t.Fatal(err)
		}
		two, err := manager.NewWorkspace()
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]fs.FileMode{one.workspace: 0o700, two.workspace: 0o700, one.restricted: 0o500, filepath.Join(one.restricted, id): 0o400} {
			info, err := os.Lstat(path)
			rel, relErr := filepath.Rel(parent, path)
			if err != nil || relErr != nil || !filepath.IsLocal(rel) || info.Mode().Perm() != want {
				t.Fatalf("unexpected path or mode for %s", rel)
			}
		}
		entries, err := os.ReadDir(one.restricted)
		if err != nil || len(entries) != 1 || entries[0].Name() != id || one.restricted != two.restricted || one.workspace == two.workspace {
			t.Fatal("fixture isolation or contents")
		}
		notes := filepath.Join("seed", "notes.txt")
		writeFixture(t, filepath.Join(one.workspace, notes), "changed")
		buf, err := fixtureRoot(t, two.workspace).ReadFile(notes)
		if err != nil || string(buf) != "Sample workspace notes.\n" {
			t.Fatal("workspaces shared state")
		}
		spec := fixtureSpec(t)
		spec.workspace, spec.restricted = one.workspace, one.restricted
		args, err := spec.args()
		if err != nil {
			t.Fatal(err)
		}
		mounts := []string{}
		for _, arg := range args {
			if strings.HasSuffix(arg, ",Z") {
				mounts = append(mounts, arg)
			}
		}
		if len(mounts) != 2 || mounts[0] != one.workspace+":/workspace:rw,Z" || mounts[1] != one.restricted+":/restricted:ro,Z" {
			t.Fatal("unexpected relabel source")
		}
		if err := os.Chmod(filepath.Join(one.workspace, "seed"), 0); err != nil {
			t.Fatal(err)
		}
		if err := manager.Cleanup(); err != nil {
			t.Fatal(err)
		}
		if err := manager.Cleanup(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(manager.dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("fixture subtree survived cleanup")
		}
		if _, err := os.Stat(sibling); err != nil {
			t.Fatal("cleanup removed unrelated file")
		}
	}
}

func takeSnapshot(t *testing.T, dir string) WorkspaceSnapshot {
	t.Helper()
	s, err := (SessionFixtures{workspace: dir}).Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSnapshotChanges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a")
	writeFixture(t, file, "hello")
	writeFixture(t, filepath.Join(dir, "removed"), "remove")
	writeFixture(t, filepath.Join(dir, "to-dir"), "file")
	baseline := takeSnapshot(t, dir)
	if baseline["a"].SHA256 != sha256.Sum256([]byte("hello")) {
		t.Fatal("incorrect content digest")
	}
	tm := time.Unix(100000, 0)
	if err := os.Chtimes(file, tm, tm); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(baseline, takeSnapshot(t, dir)) {
		t.Fatal("timestamps produced a change")
	}
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	if d := baseline.Diff(takeSnapshot(t, dir)); !slices.Equal(d.Changed, []string{"a"}) {
		t.Fatal(d)
	}
	before := takeSnapshot(t, dir)
	if err := os.Link(file, filepath.Join(dir, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(dir, "link")
	if err := os.Symlink("/etc/passwd", sym); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "to-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "to-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "removed")); err != nil {
		t.Fatal(err)
	}
	after := takeSnapshot(t, dir)
	d := before.Diff(after)
	if !slices.Equal(d.Added, []string{"fifo", "hard", "link"}) || !slices.Equal(d.Removed, []string{"removed"}) || !slices.Contains(d.Changed, "a") || !slices.Contains(d.Changed, "to-dir") {
		t.Fatal(d)
	}
	if after["a"].Links != 2 || after["a"] != after["hard"] || !after["to-dir"].Mode.IsDir() || after["fifo"].Mode&fs.ModeNamedPipe == 0 {
		t.Fatal("lost entry type or link information")
	}
	if e := after["link"]; e.LinkTarget != "/etc/passwd" || e.Mode&fs.ModeSymlink == 0 || e.SHA256 != ([32]byte{}) {
		t.Fatal("followed workspace symlink")
	}
	if err := os.Remove(sym); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", sym); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(after.Diff(takeSnapshot(t, dir)).Changed, "link") {
		t.Fatal("missed link target change")
	}
}

func TestSnapshotHashLimits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	writeFixture(t, p, "")
	if err := os.Truncate(p, fullHashLimit); err != nil {
		t.Fatal(err)
	}
	if e := takeSnapshot(t, dir)["file"]; e.PartialHash || e.SHA256 != sha256.Sum256(make([]byte, fullHashLimit)) {
		t.Fatal("incorrect full hash at cutoff")
	}
	if err := os.Truncate(p, fullHashLimit+1); err != nil {
		t.Fatal(err)
	}
	baseline := takeSnapshot(t, dir)
	if e := baseline["file"]; !e.PartialHash || e.SHA256 != sha256.Sum256(make([]byte, 2*hashWindow)) {
		t.Fatal("incorrect partial digest")
	}
	f, err := fixtureRoot(t, dir).OpenFile("file", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, offset := range []int64{hashWindow + 1, 0, fullHashLimit} {
		if _, err := f.WriteAt([]byte{1}, offset); err != nil {
			t.Fatal(err)
		}
		after := takeSnapshot(t, dir)
		changed := slices.Contains(baseline.Diff(after).Changed, "file")
		if changed != (offset != hashWindow+1) {
			t.Fatalf("unexpected sampled change at %d", offset)
		}
		baseline = after
	}
}

func TestSwappedEntryInconclusive(t *testing.T) {
	for _, kind := range []string{"symlink", "FIFO"} {
		for _, hash := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/hash=%t", kind, hash), func(t *testing.T) {
				dir := t.TempDir()
				root, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = root.Close() }()
				p := filepath.Join(dir, "file")
				writeFixture(t, p, "sample")
				before, err := root.Lstat("file")
				if err != nil {
					t.Fatal(err)
				}
				if err := root.Remove("file"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = root.Symlink("/etc/passwd", "file")
				} else {
					err = syscall.Mkfifo(p, 0o600)
				}
				if err != nil {
					t.Fatal(err)
				}
				var w workspaceWalk
				if hash {
					w.snapshot = make(WorkspaceSnapshot)
				}
				done := make(chan error, 1)
				go func() { done <- w.entry(t.Context(), root, "file", "file", 1, before) }()
				select {
				case err := <-done:
					if !errors.Is(err, ErrUnstableWorkspace) || len(w.snapshot) != 0 || w.bytes != 0 {
						t.Fatalf("accepted substituted inode: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("blocked opening substituted inode")
				}
			})
		}
	}
}

func TestWorkspaceLimits(t *testing.T) {
	dir := t.TempDir()
	for i := range maxEntries {
		writeFixture(t, filepath.Join(dir, strconv.Itoa(i)), "")
	}
	if err := new(workspaceWalk).observe(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(dir, "extra"), "")
	requireWalkLimit(t, dir)

	deep := t.TempDir()
	p := strings.Repeat("d/", maxDepth)
	if err := os.MkdirAll(filepath.Join(deep, p), 0o700); err != nil {
		t.Fatal(err)
	}
	takeSnapshot(t, deep)
	if err := os.Mkdir(filepath.Join(deep, p, "extra"), 0o700); err != nil {
		t.Fatal(err)
	}
	requireWalkLimit(t, deep)

	dir = t.TempDir()
	p = filepath.Join(dir, "sparse")
	writeFixture(t, p, "")
	if err := os.Truncate(p, maxWorkspaceBytes); err != nil {
		t.Fatal(err)
	}
	if err := new(workspaceWalk).observe(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, maxWorkspaceBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := new(workspaceWalk).observe(t.Context(), dir); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
}

func requireWalkLimit(t *testing.T, dir string) {
	t.Helper()
	if s, err := (SessionFixtures{workspace: dir}).Snapshot(t.Context()); !errors.Is(err, ErrResourceLimit) || s != nil {
		t.Fatal("expected snapshot limit")
	}
	if err := new(workspaceWalk).observe(t.Context(), dir); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("expected watchdog limit")
	}
}
