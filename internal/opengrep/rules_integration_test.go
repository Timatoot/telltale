//go:build staticacceptance

package opengrep

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Timatoot/telltale/internal/ingest"
)

func TestOpengrepIntegration(t *testing.T) {
	// An engine that falls back to a directory walk can still return all
	// matches after attempting Git. Observe the invocation independently.
	bin := t.TempDir()
	marker := filepath.Join(bin, "git-called")
	t.Setenv("GIT_CALL_MARKER", marker)
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n: > \"$GIT_CALL_MARKER\"\nexit 1\n"), 0o700); err != nil { //nolint:gosec // Private test executable.
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(func() {
		if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected no Git invocation during preflight or analysis, marker stat: %v", err)
		}
	})
	a := analyzer(t)
	if _, err := a.Preflight(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Keep the hostile ignore file in the original fixture. If it disappears
	// this test would stop exercising the snapshot boundary.
	ignore, err := os.ReadFile("../../testdata/fixtures/opengrep/.semgrepignore")
	if err != nil || string(ignore) != "read.py\n" {
		t.Fatalf("fixture ignore file: %q, %v", ignore, err)
	}
	s := snapshot(t, a)
	if !slices.Equal(s.Files, []string{"benign.py", "read.py"}) {
		t.Fatalf("unexpected snapshot manifest: %v", s.Files)
	}
	snapshotIgnore, err := s.Root().ReadFile(".semgrepignore")
	if err != nil || len(snapshotIgnore) != 0 {
		t.Fatalf("snapshot ignore file: %q, %v", snapshotIgnore, err)
	}
	source, err := s.Root().ReadFile("read.py")
	if err != nil || !bytes.Contains(source, []byte("open(path) as source:  # nosemgrep")) {
		t.Fatalf("missing inline suppression on fixture read: %v", err)
	}
	result, err := a.Analyze(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ParseErrors) != 0 || len(result.FilesSkipped) != 0 {
		t.Fatalf("incomplete scan: errors %v, skipped %v", result.ParseErrors, result.FilesSkipped)
	}
	var ids []string
	for _, match := range result.Matches {
		if match.Span.Path != "read.py" {
			t.Fatalf("unexpected match in benign fixture: %+v", match)
		}
		ids = append(ids, match.RuleID)
	}
	if want := []string{"fs-read", "fs-write", "fs-overwrite", "fs-delete", "exec", "network"}; !slices.Equal(ids, want) {
		t.Fatalf("matched rules in source order: %v, want %v", ids, want)
	}

	t.Run("symlinked RunDir", func(t *testing.T) {
		realDir := t.TempDir()
		linkDir := filepath.Join(t.TempDir(), "run-link")
		if err := os.Symlink(realDir, linkDir); err != nil {
			t.Fatal(err)
		}
		sa := SinkAnalyzer{RunDir: linkDir}
		t.Cleanup(func() {
			entries, err := os.ReadDir(realDir)
			if err != nil || len(entries) != 0 {
				t.Errorf("stage cleanup: %v, %v", entries, err)
			}
		})
		if _, err := sa.Preflight(t.Context()); err != nil {
			t.Fatal(err)
		}
		snap, err := ingest.CreateSnapshot(t.Context(), "../../testdata/fixtures/opengrep", linkDir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := snap.Close(); err != nil {
				t.Error(err)
			}
		})
		res, err := sa.Analyze(t.Context(), snap)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.ParseErrors) != 0 || len(res.FilesSkipped) != 0 {
			t.Fatalf("incomplete scan: errors %v, skipped %v", res.ParseErrors, res.FilesSkipped)
		}
		var symIDs []string
		for _, m := range res.Matches {
			symIDs = append(symIDs, m.RuleID)
		}
		if !slices.Equal(symIDs, ids) {
			t.Fatalf("matched rules under symlinked RunDir: %v, want %v", symIDs, ids)
		}
	})
}
