package rules

import "github.com/Timatoot/telltale/internal/model"

func (r *Result) evalContract(t model.ToolFact, s model.Sink, ordinal int, verify bool) {
	emit := func(ruleID, key, value string) {
		fp := model.ContractFingerprint(ruleID, s.Span.Path, t.Name, key, s.Category, s.NormalizedCallee, ordinal)
		f := staticFinding(ruleID, t, &s.Span, fp,
			model.EvidenceItem{Kind: model.EvidenceDeclared, Source: model.SourceTreeSitter, Detail: key + "=" + value},
			model.EvidenceItem{Kind: model.EvidenceInferred, Source: model.SourceOpengrep, Detail: s.Category, RedactedExcerpt: s.NormalizedCallee})
		if verify && ruleID == openWorld {
			f.DynamicStatus = model.NotApplicable
		}
		r.Findings = append(r.Findings, f)
		if ruleID != openWorld {
			r.addHypothesis(f, "")
		}
	}
	a := t.Annotations
	switch s.Category {
	case "fs_delete", "fs_overwrite", "exec", "fs_write":
		if a.ReadOnlyHint != nil && *a.ReadOnlyHint {
			emit(readOnly, "readOnlyHint", "true")
		}
		if s.Category != "fs_write" && a.DestructiveHint != nil && !*a.DestructiveHint {
			emit(destructive, "destructiveHint", "false")
		}
	case "network":
		if a.OpenWorldHint != nil && !*a.OpenWorldHint {
			emit(openWorld, "openWorldHint", "false")
		}
	}
}
