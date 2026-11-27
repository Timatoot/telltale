package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Timatoot/telltale/internal/model"
)

func emptyReport() model.ScanReport {
	return model.ScanReport{SchemaVersion: model.SchemaVersion, Tool: model.Tool{Name: "telltale", Version: "dev", RuntimeBackend: "none"}, Target: model.Target{RepoName: "repo", Mode: "static"}, Summary: model.Summary{PolicyPassed: true, CoverageComplete: true}}
}

func TestJSONSchema(t *testing.T) {
	r := emptyReport()
	data, err := RenderJSON(&r, "")
	if err != nil {
		t.Fatal(err)
	}
	const want = `{
	"schema_version":"1.0","tool":{"name":"telltale","version":"dev","opengrep_version":"","runtime_backend":"none","runtime_version":null},
	"target":{"repo_name":"repo","mode":"static","image":null},
	"coverage":{"files_scanned":0,"files_skipped":[],"parse_errors":[],"tools_discovered":0,"unresolved_registrations":[],"unresolved_descriptions":[],"analysis_limits":{"cross_file_helper_calls":[]}},
	"inventory":[],"findings":[],
	"summary":{"counts_by_severity":{},"counts_by_static_status":{},"counts_by_dynamic_status":{},"gating_count":0,"coverage_complete":true,"policy_passed":true,"analysis_exit_code":0}
	}`
	var got, expected map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected schema: %s", data)
	}
	r.Target.Mode = "verify"
	r.Inventory = []model.ToolFact{{ToolID: "live:reader", Name: "reader"}}
	r.Findings = []model.Finding{{ID: "POISON-RUNTIME-DRIFT", Origin: "runtime", StaticStatus: model.None, DynamicStatus: model.Confirmed}}
	data, err = RenderJSON(&r, "")
	if err != nil {
		t.Fatal(err)
	}
	var verify model.ScanReport
	if err = json.Unmarshal(data, &verify); err != nil {
		t.Fatal(err)
	}
	tool, finding := verify.Inventory[0], verify.Findings[0]
	if verify.Coverage.RuntimeCoverage == nil || verify.Coverage.StaticOnlyTools == nil || verify.Coverage.RuntimeOnlyTools == nil || verify.Coverage.AmbiguousJoins == nil ||
		tool.Parameters == nil || tool.InferredSinks == nil || finding.Evidence == nil || finding.Mappings.CWE == nil {
		t.Fatalf("missing nested arrays: %s", data)
	}
	for _, field := range []string{"source_location", "read_only_hint", "destructive_hint", "open_world_hint", "declared_description", "live_description", "dynamic_reason", "location"} {
		if !bytes.Contains(data, []byte(`"`+field+`": null`)) {
			t.Errorf("missing explicit null for %s", field)
		}
	}
}

func TestJSONCheckoutAndOrderIndependence(t *testing.T) {
	build := func(root string, reverse bool) []byte {
		t.Helper()
		r := emptyReport()
		r.Target.RepoName = filepath.Base(root)
		path, err := filepath.Rel(root, filepath.Join(root, "pkg", "server.py"))
		if err != nil {
			t.Fatal(err)
		}
		loc := model.Location{Path: filepath.ToSlash(path), StartLine: 3, StartColumn: 1, EndLine: 4, EndColumn: 10}
		r.Inventory = []model.ToolFact{{ToolID: "py:pkg/server.py:z", SourceLocation: &loc, Parameters: []model.Parameter{{Name: "b"}, {Name: "a"}}}, {ToolID: "py:pkg/server.py:a"}}
		r.Findings = []model.Finding{
			{Severity: model.Medium, ID: "R", Fingerprint: "c", Location: &loc},
			{Severity: model.High, ID: "R", Fingerprint: "b", Evidence: []model.EvidenceItem{{Detail: "b"}, {Detail: "a"}}, Mappings: model.Mappings{CWE: []string{"CWE-3", "CWE-2"}}},
			{Severity: model.High, ID: "R", Fingerprint: "a"},
			{Severity: model.High, ID: "A", Fingerprint: "z"},
		}
		r.Coverage.UnresolvedRegistrations = []model.UnresolvedRegistration{{Path: "z.py", Line: 2, Reason: "unknown"}, {Path: path, Line: 8}, {Path: path, Line: 4}}
		if reverse {
			slices.Reverse(r.Inventory[0].Parameters)
			slices.Reverse(r.Findings[1].Evidence)
			slices.Reverse(r.Findings[1].Mappings.CWE)
			slices.Reverse(r.Inventory)
			slices.Reverse(r.Findings)
			slices.Reverse(r.Coverage.UnresolvedRegistrations)
		}
		original, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := RenderJSON(&r, "")
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, after) {
			t.Fatal("renderer mutated the caller's report")
		}
		if bytes.Contains(data, []byte(root)) {
			t.Fatal("checkout path leaked")
		}
		var got model.ScanReport
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		var fps []string
		for _, f := range got.Findings {
			fps = append(fps, f.Fingerprint)
		}
		if !slices.Equal(fps, []string{"z", "a", "b", "c"}) || got.Inventory[0].ToolID != "py:pkg/server.py:a" ||
			got.Coverage.UnresolvedRegistrations[0].Line != 4 || got.Coverage.UnresolvedRegistrations[2].Path != "z.py" {
			t.Fatalf("wrong ordering: %s", data)
		}
		return data
	}
	left := build(filepath.Join(t.TempDir(), "repo"), false)
	right := build(filepath.Join(t.TempDir(), "repo"), true)
	if !bytes.Equal(left, right) {
		t.Fatal("canonical bytes differ across checkout paths or input permutations")
	}
}

func TestJSONSanitizedAfterDecoding(t *testing.T) {
	const canary = "synthetic-canary"
	hostile := "\x1b[31m\u202e Bearer lightweight " + canary
	fingerprint := model.Fingerprint("rule", "server.py", "reader", "anchor")
	r := emptyReport()
	r.Inventory = []model.ToolFact{{DeclaredDescription: &hostile, Parameters: []model.Parameter{{Description: &hostile}}}}
	r.Findings = []model.Finding{{Fingerprint: fingerprint, Evidence: []model.EvidenceItem{{Detail: hostile, RedactedExcerpt: hostile + strings.Repeat("!", 1000)}}}}
	raw, err := RenderJSON(&r, canary)
	if err != nil {
		t.Fatal(err)
	}
	var got model.ScanReport
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	e := got.Findings[0].Evidence[0]
	for _, s := range []string{*got.Inventory[0].DeclaredDescription, *got.Inventory[0].Parameters[0].Description, e.Detail, e.RedactedExcerpt} {
		if !strings.Contains(s, "<U+001B>[31m<U+202E> Bearer [REDACTED] [REDACTED]") || strings.ContainsAny(s, "\x1b\u202e") {
			t.Errorf("unsafe decoded text %q", s)
		}
	}
	if bytes.Contains(raw, []byte(canary)) || len(e.RedactedExcerpt) > excerptBytes || got.Findings[0].Fingerprint != fingerprint {
		t.Fatal("credential, excerpt or digest contract violated")
	}
	// Inject the canary into the digest, which bypasses prose redaction.
	for _, needle := range []string{canary, "<synthetic>&"} {
		r.Findings[0].Fingerprint = needle
		if raw, err := RenderJSON(&r, needle); err == nil || raw != nil || strings.Contains(err.Error(), needle) {
			t.Fatal("guard did not fail closed")
		}
	}
}

func TestJSONRejectsInvalidPathsAndFatalExit(t *testing.T) {
	for _, path := range []string{"/tmp/scan/server.py", "../server.py", "pkg/../server.py", `C:\checkout\server.py`, `\\host\repo\server.py`} {
		r := emptyReport()
		r.Findings = []model.Finding{{Location: &model.Location{Path: path}}}
		if data, err := RenderJSON(&r, ""); err == nil || data != nil {
			t.Errorf("accepted path %q", path)
		}
	}
	r := emptyReport()
	r.Summary.AnalysisExitCode = 2
	if data, err := RenderJSON(&r, ""); err == nil || data != nil {
		t.Fatal("rendered fatal exit code")
	}
}
