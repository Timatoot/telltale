//go:build staticacceptance

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Timatoot/telltale/internal/model"
)

const staticFixtures = "../../testdata/fixtures"

func TestStaticE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "telltale")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, ".") //nolint:gosec // The sole variable argument is the private test output path.
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build telltale: %v\n%s", err, output)
	}

	audit := func(t *testing.T, repo string, wantExit int, flags ...string) (model.ScanReport, []byte) {
		t.Helper()
		dir := t.TempDir()
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		args := append([]string{"audit", repo, "--json", filepath.Join(dir, "report.json")}, flags...)
		cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // Test-built CLI with fixture paths and explicit arguments.
		output, err := cmd.CombinedOutput()
		var exitErr *exec.ExitError
		if err != nil && !errors.As(err, &exitErr) {
			t.Fatalf("start audit: %v", err)
		}
		if code := cmd.ProcessState.ExitCode(); code != wantExit {
			t.Fatalf("audit %v: exit %d, want %d\n%s", args, code, wantExit, output)
		}
		raw := readStaticFile(t, dir, "report.json")
		var r model.ScanReport
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if r.Summary.AnalysisExitCode != wantExit {
			t.Fatalf("report exit %d, want %d", r.Summary.AnalysisExitCode, wantExit)
		}
		return r, raw
	}

	for _, tc := range []struct {
		fixture string
		tools   int
		code    int
		rules   map[string]model.StaticStatus
	}{
		{"poison_vuln", 1, 1, map[string]model.StaticStatus{
			"POISON-INVISIBLE-UNICODE": model.Proven, "POISON-PROMPT-OVERRIDE": model.Suspected,
			"POISON-HIDDEN-EXFIL": model.Suspected, "POISON-CROSS-TOOL-MISLEAD": model.Suspected,
		}},
		{"poison_benign", 1, 0, nil},
		{"contract_vuln", 2, 1, map[string]model.StaticStatus{
			"CONTRACT-READONLY-WRITE": model.Suspected, "CONTRACT-DESTRUCTIVE-MUTATION": model.Suspected,
			"CONTRACT-OPENWORLD-NETWORK": model.Suspected,
		}},
		{"contract_benign", 2, 0, nil},
		{"fs_vuln", 1, 1, map[string]model.StaticStatus{"FS-PATH-TRAVERSAL": model.Suspected}},
		{"fs_benign", 1, 0, nil},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			r, _ := audit(t, filepath.Join(staticFixtures, tc.fixture), tc.code)
			if !r.Summary.CoverageComplete || r.Coverage.FilesScanned != 1 || len(r.Inventory) != tc.tools {
				t.Fatalf("coverage %+v, inventory size %d", r.Coverage, len(r.Inventory))
			}
			if len(r.Findings) != len(tc.rules) {
				t.Fatalf("findings %+v, want %v", r.Findings, tc.rules)
			}
			for _, f := range r.Findings {
				want, ok := tc.rules[f.ID]
				if !ok || f.StaticStatus != want || f.DynamicStatus != model.NotRun || f.Origin != model.OriginStatic {
					t.Errorf("unexpected finding %+v, expected static status %q", f, want)
				}
				delete(tc.rules, f.ID) // Each expected rule must occur exactly once.
			}
		})
	}

	t.Run("coverage", func(t *testing.T) {
		r, _ := audit(t, filepath.Join(staticFixtures, "coverage"), 3, "--strict")
		c := r.Coverage
		const prefix = "py:edge_registrations.py:"
		if r.Summary.CoverageComplete || len(r.Findings) != 0 || c.FilesScanned != 2 || c.ToolsDiscovered != 4 ||
			len(c.ParseErrors)+len(c.FilesSkipped) != 0 ||
			!slices.Equal(c.UnresolvedRegistrations, []model.UnresolvedRegistration{{Path: "edge_registrations.py", Line: 25, Reason: "loop_registration"}}) ||
			!slices.Equal(c.UnresolvedDescriptions, []model.UnresolvedDescription{{ToolID: prefix + "clean#2", Field: "description"}}) ||
			!slices.Equal(c.AnalysisLimits.CrossFileHelperCalls, []model.HelperCall{
				{ToolID: prefix + "clean", CalleeModule: "helper_mod"}, {ToolID: prefix + "echo", CalleeModule: "helper_mod"},
			}) {
			t.Fatalf("coverage %+v, summary %+v", c, r.Summary)
		}
	})

	t.Run("helper alone preserves complete coverage", func(t *testing.T) {
		repo := t.TempDir()
		writeStaticFile(t, repo, "helper_mod.py", readStaticFile(t, staticFixtures, "coverage/helper_mod.py"))
		writeStaticFile(t, repo, "server.py", []byte(`from mcp.server.fastmcp import FastMCP
from helper_mod import normalize

app = FastMCP("helper")

@app.tool()
def clean(value: str):
    """Normalize a value."""
    return normalize(value)
`))
		r, _ := audit(t, repo, 0, "--strict")
		c := r.Coverage
		want := []model.HelperCall{{ToolID: "py:server.py:clean", CalleeModule: "helper_mod"}}
		if !r.Summary.CoverageComplete || len(r.Findings) != 0 || c.FilesScanned != 2 || c.ToolsDiscovered != 1 ||
			len(c.FilesSkipped)+len(c.ParseErrors)+len(c.UnresolvedRegistrations)+len(c.UnresolvedDescriptions) != 0 ||
			!slices.Equal(c.AnalysisLimits.CrossFileHelperCalls, want) {
			t.Fatalf("coverage %+v, summary %+v", c, r.Summary)
		}
	})

	t.Run("checkout independent JSON", func(t *testing.T) {
		first := copyStaticFixture(t, "poison_vuln")
		second := copyStaticFixture(t, "poison_vuln")
		_, a := audit(t, first, 1)
		_, b := audit(t, second, 1)
		if !bytes.Equal(a, b) {
			t.Fatalf("canonical JSON differs between checkouts:\n%s\n%s", a, b)
		}
	})

	t.Run("line independent fingerprints", func(t *testing.T) {
		repo := copyStaticFixture(t, "fs_vuln")
		source := readStaticFile(t, repo, "server.py")
		scan := func() model.Finding {
			t.Helper()
			sarifDir := t.TempDir()
			r, _ := audit(t, repo, 1, "--sarif", filepath.Join(sarifDir, "report.sarif"))
			if len(r.Findings) != 1 {
				t.Fatalf("want one FS finding, got %+v", r.Findings)
			}
			f := r.Findings[0]
			if f.ID != "FS-PATH-TRAVERSAL" || f.Fingerprint == "" || f.Location == nil {
				t.Fatalf("missing FS finding identity or location: %+v", f)
			}

			var sarif struct {
				Runs []struct {
					Results []struct {
						RuleID              string            `json:"ruleId"`
						PartialFingerprints map[string]string `json:"partialFingerprints"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(readStaticFile(t, sarifDir, "report.sarif"), &sarif); err != nil {
				t.Fatal(err)
			}
			if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 {
				t.Fatalf("expected one SARIF result: %+v", sarif)
			}
			result := sarif.Runs[0].Results[0]
			if result.RuleID != f.ID || result.PartialFingerprints["telltale/v1"] != f.Fingerprint {
				t.Fatalf("SARIF result %+v, want %s %s", result, f.ID, f.Fingerprint)
			}
			return f
		}
		before := scan()
		lines := strings.Split(string(source), "\n")
		if line := before.Location.StartLine; line < 1 || line > len(lines) || !strings.Contains(lines[line-1], "# nosemgrep") {
			t.Fatalf("FS finding should point to the annotated read, got %+v", before.Location)
		}
		writeStaticFile(t, repo, "server.py", append([]byte("\n\n"), source...))
		after := scan()
		if after.Location.StartLine != before.Location.StartLine+2 || after.Fingerprint != before.Fingerprint {
			t.Fatalf("after shifting by two lines: %d %s -> %d %s", before.Location.StartLine, before.Fingerprint, after.Location.StartLine, after.Fingerprint)
		}
	})

	t.Run("policy and exit precedence", func(t *testing.T) {
		// Use the same four findings and registration gap for every policy.
		repo := copyStaticFixture(t, "coverage")
		writeStaticFile(t, repo, "server.py", readStaticFile(t, staticFixtures, "poison_vuln/server.py"))
		for _, tc := range []struct {
			name   string
			flags  []string
			code   int
			gating []string
		}{
			{"default high", nil, 1, []string{"POISON-HIDDEN-EXFIL", "POISON-INVISIBLE-UNICODE"}},
			{"medium", []string{"--strict", "--fail-on", "medium"}, 1, []string{"POISON-CROSS-TOOL-MISLEAD", "POISON-HIDDEN-EXFIL", "POISON-INVISIBLE-UNICODE", "POISON-PROMPT-OVERRIDE"}},
			{"verified only", []string{"--strict", "--fail-on", "medium", "--verified-only"}, 1, []string{"POISON-INVISIBLE-UNICODE"}},
			{"strict gap", []string{"--strict", "--fail-on", "critical"}, 3, nil},
			{"ungated", []string{"--fail-on", "critical"}, 0, nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				r, _ := audit(t, repo, tc.code, tc.flags...)
				var gating []string
				for _, f := range r.Findings {
					if f.Gating {
						gating = append(gating, f.ID)
					}
				}
				slices.Sort(gating)
				if len(r.Findings) != 4 || !slices.Equal(gating, tc.gating) || r.Summary.CoverageComplete ||
					r.Summary.GatingCount != len(tc.gating) || r.Summary.PolicyPassed != (len(tc.gating) == 0) {
					t.Fatalf("gating %v, want %v; summary %+v", gating, tc.gating, r.Summary)
				}
			})
		}
	})
}

func copyStaticFixture(t *testing.T, name string) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), name)
	if err := os.CopyFS(repo, os.DirFS(filepath.Join(staticFixtures, name))); err != nil {
		t.Fatal(err)
	}
	return repo
}

func readStaticFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := fs.ReadFile(os.DirFS(dir), name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeStaticFile(t *testing.T, repo, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
