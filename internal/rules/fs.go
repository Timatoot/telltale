package rules

import (
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/opengrep"
)

func (r *Result) evalFS(t model.ToolFact, m opengrep.SinkMatch, ordinal int) {
	// The extractor resolves the engine source against the public signature.
	// An unresolved binding stays in inventory and coverage.
	if m.TaintedParameter == "" {
		return
	}
	fp := model.FSFingerprint(traversal, m.Span.Path, t.Name, m.TaintedParameter, m.NormalizedCallee, ordinal)
	f := staticFinding(traversal, t, &m.Span, fp,
		model.EvidenceItem{Kind: model.EvidenceDeclared, Source: model.SourceTreeSitter, Detail: "Tool parameter", RedactedExcerpt: m.TaintedParameter},
		model.EvidenceItem{Kind: model.EvidenceInferred, Source: model.SourceOpengrep, Detail: "Parameter flows to a filesystem read", RedactedExcerpt: m.NormalizedCallee})
	r.Findings = append(r.Findings, f)
	r.addHypothesis(f, m.TaintedParameter)
}
