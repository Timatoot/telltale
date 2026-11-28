package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FixtureManager owns one fresh subtree of the caller's private run directory.
// Cleanup must run after containers using the bind sources have been removed.
type FixtureManager struct {
	dir, restricted, fileID string
}

func NewFixtureManager(runDir string) (*FixtureManager, error) {
	if !filepath.IsAbs(runDir) {
		return nil, errors.New("expected an absolute run directory suitable for bind mounts")
	}
	parent, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		return nil, err
	}
	if strings.ContainsRune(parent, ':') {
		return nil, errors.New("invalid fixture bind parent")
	}
	dir, err := os.MkdirTemp(parent, "fixtures-")
	if err != nil {
		return nil, err
	}
	f := &FixtureManager{dir: dir, restricted: filepath.Join(dir, "restricted"), fileID: randomHex(16)}
	if err := f.createCanary(); err != nil {
		return nil, errors.Join(err, f.Cleanup())
	}
	return f, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (f *FixtureManager) createCanary() error {
	if err := os.Mkdir(f.restricted, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(f.restricted, f.fileID), []byte(randomHex(32)), 0o400); err != nil {
		return err
	}
	return os.Chmod(f.restricted, 0o500) //nolint:gosec // G302: owner-only read and traversal of the sealed canary directory.
}

func (f *FixtureManager) FileID() string { return f.fileID }

// ContentToken is for the response oracle and redaction. Only FileID is public
// to the target. Keeping the content on disk also keeps it out of struct dumps.
func (f *FixtureManager) ContentToken() (string, error) {
	token, err := os.ReadFile(filepath.Join(f.restricted, f.fileID)) //nolint:gosec // G304: private, read-only canary created by this manager.
	return string(token), err
}

func (f *FixtureManager) NewWorkspace() (SessionFixtures, error) {
	if f.dir == "" {
		return SessionFixtures{}, errors.New("uninitialized fixture manager")
	}
	dir, err := os.MkdirTemp(f.dir, "workspace-")
	if err != nil {
		return SessionFixtures{}, err
	}
	seed := filepath.Join(dir, "seed")
	if err := os.Mkdir(seed, 0o700); err != nil {
		return SessionFixtures{}, errors.Join(err, os.RemoveAll(dir))
	}
	if err := os.WriteFile(filepath.Join(seed, "notes.txt"), []byte("Sample workspace notes.\n"), 0o600); err != nil {
		return SessionFixtures{}, errors.Join(err, os.RemoveAll(dir))
	}
	return SessionFixtures{workspace: dir, restricted: f.restricted}, nil
}

func (f *FixtureManager) Cleanup() error {
	// RemoveAll does not follow links. Retry permission failures after making
	// remaining directories (including the sealed canary) traversable.
	err := os.RemoveAll(f.dir)
	if !errors.Is(err, fs.ErrPermission) {
		return err
	}
	root, err := os.OpenRoot(f.dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	if err := filepath.WalkDir(f.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, err := filepath.Rel(f.dir, path)
			if err != nil {
				return err
			}
			return root.Chmod(rel, 0o700)
		}
		return nil
	}); err != nil {
		return err
	}
	return os.RemoveAll(f.dir)
}
