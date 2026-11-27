// Package rules evaluates static tool metadata and single-file sink evidence.
package rules

import (
	"cmp"
	"slices"

	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/opengrep"
)

const (
	invisible    = "POISON-INVISIBLE-UNICODE"
	override     = "POISON-PROMPT-OVERRIDE"
	exfil        = "POISON-HIDDEN-EXFIL"
	crossTool    = "POISON-CROSS-TOOL-MISLEAD"
	RuntimeDrift = "POISON-RUNTIME-DRIFT"
	readOnly     = "CONTRACT-READONLY-WRITE"
	destructive  = "CONTRACT-DESTRUCTIVE-MUTATION"
	openWorld    = "CONTRACT-OPENWORLD-NETWORK"
	traversal    = "FS-PATH-TRAVERSAL"
)

type rule struct {
	family                      model.Family
	severity                    model.Severity
	title, summary, remediation string
	cwe                         []string
}

var catalog = map[string]rule{
	invisible:    {model.FamilyPoisoning, model.High, "Invisible characters in tool metadata", "A metadata field contains hidden or control characters.", "Remove hidden characters from the declared text.", []string{"CWE-116", "CWE-1007"}},
	override:     {model.FamilyPoisoning, model.Medium, "Instruction override in tool metadata", "A directive asks the reader to disregard other instructions.", "Describe the tool without directing the reader to override instructions.", []string{"CWE-77", "CWE-74"}},
	exfil:        {model.FamilyPoisoning, model.High, "Data disclosure directive", "The metadata requests credentials or covert data transfer.", "Remove data disclosure instructions from the tool metadata.", []string{"CWE-200"}},
	crossTool:    {model.FamilyPoisoning, model.Medium, "Misleading cross-tool directive", "The metadata directs the reader to replace or misrepresent another tool.", "Describe the tool's own behavior accurately.", []string{"CWE-451"}},
	RuntimeDrift: {model.FamilyPoisoning, model.Medium, "Tool metadata changed at runtime", "The live metadata differs from the resolved declaration.", "Reconcile the declared and advertised metadata.", []string{"CWE-345"}},
	readOnly:     {model.FamilyContractMismatch, model.High, "Read-only hint conflicts with handler", "The handler may modify files or execute a subprocess.", "Align the read-only hint with the handler's behavior.", []string{"CWE-732"}},
	destructive:  {model.FamilyContractMismatch, model.High, "Non-destructive hint conflicts with handler", "The handler may delete or overwrite files or execute a subprocess.", "Align the destructive hint with the handler's behavior.", []string{"CWE-732"}},
	openWorld:    {model.FamilyContractMismatch, model.Medium, "Closed-world hint conflicts with handler", "The handler contains an outbound network operation.", "Review the network operation and the open-world hint.", []string{"CWE-918", "CWE-284"}},
	traversal:    {model.FamilyFilesystemEscape, model.High, "Tool input reaches a filesystem read", "A tool parameter flows into a filesystem read operation.", "Confine the resolved path to the intended workspace before reading.", []string{"CWE-22"}},
}

type VerificationHypothesis struct {
	RuleID, ToolID, Fingerprint string
	TaintedParameter            string // Present only for filesystem reads.
}

type Result struct {
	Inventory  []model.ToolFact
	Findings   []model.Finding
	Hypotheses []VerificationHypothesis
}

func staticFinding(id string, tool model.ToolFact, loc *model.Location, fingerprint string, evidence ...model.EvidenceItem) model.Finding {
	r := catalog[id]
	f := model.Finding{ID: id, Origin: model.OriginStatic, Family: r.family, Severity: r.severity, Title: r.title, Summary: r.summary,
		Remediation: r.remediation, Confidence: model.ConfidenceMedium, StaticStatus: model.Suspected, DynamicStatus: model.NotRun,
		ToolID: tool.ToolID, Location: loc, Fingerprint: fingerprint, Evidence: evidence, Mappings: model.Mappings{CWE: slices.Clone(r.cwe)}}
	if id == invisible {
		f.StaticStatus, f.Confidence = model.Proven, model.ConfidenceHigh
	}
	return f
}

func (r *Result) addHypothesis(f model.Finding, param string) {
	r.Hypotheses = append(r.Hypotheses, VerificationHypothesis{RuleID: f.ID, ToolID: f.ToolID, Fingerprint: f.Fingerprint, TaintedParameter: param})
}

// Evaluate consumes handler-attributed matches and returns an owned inventory.
// Ordinals count distinct call sites with the same callee in source order.
func Evaluate(tools []model.ToolFact, matches []opengrep.SinkMatch, verify bool) Result {
	// Tool names and POSIX paths may contain ID delimiters. Include the
	// actual handler span so a literal name cannot borrow another call site.
	type handler struct {
		id       string
		location model.Location
	}
	byTool := make(map[handler][]opengrep.SinkMatch)
	for _, m := range matches {
		key := handler{m.ToolID, m.HandlerSpan}
		byTool[key] = append(byTool[key], m)
	}
	r := Result{Inventory: slices.Clone(tools)}
	for i := range r.Inventory {
		t := &r.Inventory[i]
		t.Parameters = slices.Clone(t.Parameters)
		t.InferredSinks = nil
		if t.SourceLocation == nil {
			continue
		}
		r.Findings = append(r.Findings, staticPoison(*t)...)
		hits := byTool[handler{t.ToolID, *t.SourceLocation}]
		slices.SortFunc(hits, compareMatch)
		ordinals := make(map[string]int)
		var lastCall model.Location
		for _, m := range slices.Compact(hits) {
			if m.CallSpan != lastCall {
				ordinals[m.NormalizedCallee]++
				lastCall = m.CallSpan
			}
			sink := model.Sink{RuleID: m.RuleID, Category: m.Category(), Span: m.Span, NormalizedCallee: m.NormalizedCallee}
			if len(t.InferredSinks) == 0 || t.InferredSinks[len(t.InferredSinks)-1] != sink {
				t.InferredSinks = append(t.InferredSinks, sink)
			}
			if m.RuleID == "fs-read" {
				r.evalFS(*t, m, ordinals[m.NormalizedCallee])
			} else {
				r.evalContract(*t, sink, ordinals[m.NormalizedCallee], verify)
			}
		}
	}
	report := model.ScanReport{Inventory: r.Inventory, Findings: r.Findings}
	report.Sort()
	slices.SortFunc(r.Hypotheses, func(a, b VerificationHypothesis) int {
		return cmp.Or(cmp.Compare(a.ToolID, b.ToolID), cmp.Compare(a.RuleID, b.RuleID), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return r
}

func compareMatch(a, b opengrep.SinkMatch) int {
	return cmp.Or(cmp.Compare(a.CallSpan.StartLine, b.CallSpan.StartLine), cmp.Compare(a.CallSpan.StartColumn, b.CallSpan.StartColumn),
		cmp.Compare(a.CallSpan.EndLine, b.CallSpan.EndLine), cmp.Compare(a.CallSpan.EndColumn, b.CallSpan.EndColumn),
		cmp.Compare(a.RuleID, b.RuleID), cmp.Compare(a.Span.StartLine, b.Span.StartLine), cmp.Compare(a.Span.StartColumn, b.Span.StartColumn),
		cmp.Compare(a.Span.EndLine, b.Span.EndLine), cmp.Compare(a.Span.EndColumn, b.Span.EndColumn), cmp.Compare(a.TaintedParameter, b.TaintedParameter))
}
