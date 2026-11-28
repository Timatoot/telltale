package report

import (
	"bytes"
	"encoding/json"
	"html"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Timatoot/telltale/internal/model"
)

const testCanary = "fixture-canary-content"

func reporterFixture() (model.ScanReport, fstest.MapFS) {
	r := emptyReport()
	r.Target.Mode = "verify"
	const file = "pkg/a #.py"
	const line = "label = 'é🦊'; read('猫')"
	source := fstest.MapFS{file: &fstest.MapFile{Data: []byte("# fixture\r\n" + line + "\r\n")}}
	payload := "<script>alert(1)</script> <img onerror=alert(1)> javascript:alert(1) \u202e\u200b\x07\x1b[31m " + testCanary
	r.Inventory = []model.ToolFact{{ToolID: "live:" + payload, Name: payload, DeclaredDescription: &payload}}
	loc := model.Location{Path: file, StartLine: 2, StartColumn: strings.Index(line, "read") + 1, EndLine: 2, EndColumn: len(line) + 1}
	r.Findings = []model.Finding{
		{ID: "FS-PATH-TRAVERSAL", Title: "Path read", Fingerprint: "static-fingerprint", ToolID: "py:pkg/a #.py:read",
			Severity: model.High, StaticStatus: model.Suspected, DynamicStatus: model.NotRun, Location: &loc,
			Evidence: []model.EvidenceItem{{Detail: "description", RedactedExcerpt: payload + " Bearer fictitious"}}},
		{ID: "POISON-RUNTIME-DRIFT", Title: "Live description changed", Fingerprint: "live-fingerprint", ToolID: "live:" + payload,
			Origin: model.OriginRuntime, Severity: model.Medium, StaticStatus: model.None, DynamicStatus: model.Confirmed},
	}
	r.Coverage.ParseErrors = []model.ParseError{{Engine: "opengrep", Reason: "scan-wide warning"}}
	r.Coverage.AnalysisLimits.CrossFileHelperCalls = []model.HelperCall{{ToolID: "live:read", CalleeModule: "helpers"}}
	r.ApplyPolicy(model.Policy{})
	return r, source
}

func TestReporterBoundaries(t *testing.T) {
	r, snapshot := reporterFixture()
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := RenderTerminal(&r, testCanary, true)
	if err != nil {
		t.Fatal(err)
	}
	htmlReport, err := RenderHTML(&r, testCanary)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := RenderSARIF(&r, testCanary, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := RenderJSON(&r, testCanary)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(sarif, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 || len(run.Tool.Driver.Rules) != 2 || run.Results[0].Locations[0].Physical.Artifact.URI != "pkg/a%20%23.py" ||
		len(run.Results[1].Locations) != 0 || run.Results[1].Properties["dynamic_status"] != "confirmed" {
		t.Fatalf("unexpected SARIF: %s", sarif)
	}
	for _, data := range [][]byte{terminal, htmlReport, canonical, sarif} {
		if bytes.Contains(data, []byte(testCanary)) || bytes.Contains(data, []byte("fictitious")) {
			t.Fatal("redaction failed")
		}
	}
	for _, value := range []string{string(terminal), html.UnescapeString(string(htmlReport)), run.Results[0].Message.Text} {
		if strings.ContainsAny(value, "\u202e\u200b\x07\x1b") || !strings.Contains(value, "<U+202E><U+200B><U+0007><U+001B>[31m") {
			t.Fatalf("unsafe or missing escaped text: %q", value)
		}
	}
	for _, forbidden := range []string{"<script", "<img", "href=", "src=", "http://", "https://", "url(", "@import"} {
		if strings.Contains(strings.ToLower(string(htmlReport)), forbidden) {
			t.Fatalf("unexpected markup %q", forbidden)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;img onerror=alert(1)&gt;", "javascript:alert(1)"} {
		if !strings.Contains(string(htmlReport), want) {
			t.Errorf("HTML omitted %q", want)
		}
	}
	for _, want := range []string{"findings=2", "static_status=suspected dynamic_status=not_run", "scan-wide warning", "analysis_limits: live:read calls into helpers"} {
		if !strings.Contains(string(terminal), want) {
			t.Errorf("terminal omitted %q", want)
		}
	}
	color, err := RenderTerminal(&r, testCanary, false)
	if err != nil || !bytes.Contains(color, []byte("\x1b[33mpolicy_violation\x1b[0m")) {
		t.Fatal("missing trusted status color", err)
	}
	after, err := json.Marshal(r)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("renderer mutated report", err)
	}
}

func TestSARIFSourceRegions(t *testing.T) {
	r, snapshot := reporterFixture()
	data, err := RenderSARIF(&r, testCanary, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	checkSARIFRegion(t, data)
	for _, loc := range []model.Location{
		{Path: "pkg/a #.py", StartLine: 2, StartColumn: 11, EndLine: 2, EndColumn: 20}, // splits é
		{Path: "pkg/a #.py", StartLine: 8, StartColumn: 1, EndLine: 8, EndColumn: 2},
		{Path: "pkg/a #.py", StartLine: 2, StartColumn: 999, EndLine: 2, EndColumn: 1000},
		{Path: "../outside", StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2},
	} {
		r.Findings[0].Location = &loc
		if payload, err := RenderSARIF(&r, "", snapshot); err == nil || payload != nil {
			t.Fatalf("accepted invalid location %+v", loc)
		}
	}
}

func checkSARIFRegion(t *testing.T, data []byte) {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	f := run.Results[0]
	if log.Version != "2.1.0" || run.ColumnKind != "unicodeCodePoints" || f.Locations[0].Physical.Region != (sarifRegion{2, 15, 2, 24}) ||
		!reflect.DeepEqual(f.PartialFingerprints, map[string]string{"telltale/v1": "static-fingerprint"}) ||
		bytes.Contains(data, []byte(`"markdown":`)) {
		t.Fatalf("invalid result: %s", data)
	}
}

func TestSARIFURIIdentifiesOriginalFile(t *testing.T) {
	r, sources := reporterFixture()
	const path = "odd:name\u202e #.py"
	sources[path] = sources[r.Findings[0].Location.Path]
	r.Findings[0].Location.Path = path
	data, err := RenderSARIF(&r, testCanary, sources)
	if err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if got := log.Runs[0].Results[0].Locations[0].Physical.Artifact.URI; got != "odd%3Aname%E2%80%AE%20%23.py" {
		t.Fatalf("artifact URI %q", got)
	}
}

func TestReporterFormattingDynamicReasonAndCanaryGuard(t *testing.T) {
	r, snapshot := reporterFixture()
	reason := model.ToolError
	r.Findings[0].DynamicStatus = model.Inconclusive
	r.Findings[0].DynamicReason = &reason
	r.Findings[0].Evidence = append(r.Findings[0].Evidence, model.EvidenceItem{
		Kind:   model.EvidenceDeclared,
		Source: model.SourceTreeSitter,
		Detail: "readOnlyHint=true",
	})

	terminal, err := RenderTerminal(&r, testCanary, true)
	if err != nil {
		t.Fatal(err)
	}
	htmlOut, err := RenderHTML(&r, testCanary)
	if err != nil {
		t.Fatal(err)
	}
	sarifOut, err := RenderSARIF(&r, testCanary, snapshot)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(terminal), "Coverage: opengrep: scan-wide warning") || strings.Contains(string(terminal), "opengrep :") {
		t.Fatalf("unexpected terminal scan-wide warning formatting: %s", terminal)
	}
	if !strings.Contains(string(htmlOut), "<li>opengrep: scan-wide warning</li>") || strings.Contains(string(htmlOut), "opengrep :") {
		t.Fatalf("unexpected HTML scan-wide warning formatting: %s", htmlOut)
	}

	if !strings.Contains(string(terminal), "  tree-sitter: readOnlyHint=true\n") || strings.Contains(string(terminal), "  tree-sitter: readOnlyHint=true \n") {
		t.Fatalf("unexpected terminal empty-excerpt formatting: %q", string(terminal))
	}
	if !strings.Contains(string(terminal), "dynamic_status=inconclusive (tool_error)") {
		t.Fatalf("terminal missing dynamic_reason: %s", terminal)
	}
	if !strings.Contains(string(htmlOut), "Dynamic: inconclusive (tool_error)") {
		t.Fatalf("HTML missing dynamic_reason: %s", htmlOut)
	}

	var log sarifLog
	if err := json.Unmarshal(sarifOut, &log); err != nil {
		t.Fatal(err)
	}
	var checkedEmptyExcerpt bool
	for _, res := range log.Runs[0].Results {
		if res.RuleID != "FS-PATH-TRAVERSAL" {
			continue
		}
		if res.Properties["dynamic_reason"] != "tool_error" {
			t.Fatalf("SARIF missing dynamic_reason property: %+v", res.Properties)
		}
		if !strings.Contains(res.Message.Text, "\ntree-sitter: readOnlyHint=true") || strings.Contains(res.Message.Text, "readOnlyHint=true ") {
			t.Fatalf("unexpected SARIF empty-excerpt formatting: %q", res.Message.Text)
		}
		checkedEmptyExcerpt = true
	}
	if !checkedEmptyExcerpt {
		t.Fatal("missing FS-PATH-TRAVERSAL result in SARIF")
	}

	for _, needle := range []string{testCanary, "<synthetic>&"} {
		bad, snap := reporterFixture()
		bad.Findings[0].ID = needle
		if out, err := RenderTerminal(&bad, needle, true); err == nil || out != nil || strings.Contains(err.Error(), needle) {
			t.Fatalf("RenderTerminal did not fail closed for needle %q: %v", needle, err)
		}
		if out, err := RenderHTML(&bad, needle); err == nil || out != nil || strings.Contains(err.Error(), needle) {
			t.Fatalf("RenderHTML did not fail closed for needle %q: %v", needle, err)
		}
		if out, err := RenderSARIF(&bad, needle, snap); err == nil || out != nil || strings.Contains(err.Error(), needle) {
			t.Fatalf("RenderSARIF did not fail closed for needle %q: %v", needle, err)
		}
	}
}
