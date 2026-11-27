//go:build staticacceptance

package opengrep

import (
	"bytes"
	"os"
	"slices"
	"testing"
)

func TestOpengrepIntegration(t *testing.T) {
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
}
