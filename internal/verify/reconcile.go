package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/Timatoot/telltale/internal/mcpclient"
	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/report"
	"github.com/Timatoot/telltale/internal/rules"
)

// InventoryReconciler joins one complete tools/list response to the static report.
type InventoryReconciler struct{}

// Reconcile publishes the inventory, coverage and finding updates together.
// The caller applies policy after the remaining verification outcomes are known.
func (InventoryReconciler) Reconcile(ctx context.Context, scan *model.ScanReport, live []mcpclient.LiveTool) error {
	next := *scan
	next.Inventory = slices.Clone(scan.Inventory)
	next.Findings = slices.Clone(scan.Findings)
	next.Coverage.RuntimeCoverage = &model.RuntimeCoverage{}
	registrations := make(map[string][]int)
	for i, t := range scan.Inventory {
		if t.Name != "" {
			registrations[t.Name] = append(registrations[t.Name], i)
		}
	}
	// The source span disambiguates static IDs containing a literal '#' or ':'.
	type registration struct {
		id       string
		location model.Location
	}
	findings := make(map[registration][]int)
	for i, f := range scan.Findings {
		if f.Origin == model.OriginStatic && f.Family == model.FamilyPoisoning && f.DynamicStatus == model.NotRun && f.Location != nil {
			key := registration{f.ToolID, *f.Location}
			findings[key] = append(findings[key], i)
		}
	}
	recordOutcome := func(tool model.ToolFact, observed *liveMetadata, reason model.DynamicReason) {
		if tool.SourceLocation == nil {
			return
		}
		for _, i := range findings[registration{tool.ToolID, *tool.SourceLocation}] {
			f := &next.Findings[i]
			switch reason {
			case model.ToolNotLive:
				f.DynamicStatus, f.DynamicReason = model.Skipped, new(reason)
			case model.AmbiguousJoin:
				f.DynamicStatus, f.DynamicReason = model.Inconclusive, new(reason)
			default:
				observed.updateStatic(f)
			}
		}
	}
	seen := make(map[string]bool)
	for _, peer := range live {
		if err := ctx.Err(); err != nil {
			return err
		}
		if peer.Name == "" || seen[peer.Name] {
			return mcpclient.ErrProtocolViolation
		}
		seen[peer.Name] = true
		m, err := readLiveMetadata(peer)
		if err != nil {
			return err
		}
		indices := registrations[peer.Name]
		if len(indices) == 1 {
			tool := &next.Inventory[indices[0]]
			tool.LiveDescription = peer.Description
			m.fact.ToolID = tool.ToolID
			next.Findings = append(next.Findings, m.drift(*tool)...)
		} else {
			// An ambiguous live observation has no unique static identity.
			next.Inventory = append(next.Inventory, m.fact)
			if len(indices) == 0 {
				next.Coverage.RuntimeOnlyTools = append(next.Coverage.RuntimeOnlyTools, peer.Name)
			}
		}
		textFindings, err := m.evalText(ctx)
		if err != nil {
			return err
		}
		next.Findings = append(next.Findings, textFindings...)
		if len(indices) == 1 {
			recordOutcome(next.Inventory[indices[0]], m, "")
		}
	}
	for name, indices := range registrations {
		if !seen[name] {
			next.Coverage.StaticOnlyTools = append(next.Coverage.StaticOnlyTools, name)
		}
		var reason model.DynamicReason
		switch {
		case len(indices) > 1:
			next.Coverage.AmbiguousJoins = append(next.Coverage.AmbiguousJoins, name)
			reason = model.AmbiguousJoin
		case !seen[name]:
			reason = model.ToolNotLive
		default:
			continue
		}
		for _, i := range indices {
			recordOutcome(next.Inventory[i], nil, reason)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next.Coverage.ToolsDiscovered = len(next.Inventory)
	next.Sort()
	*scan = next
	return nil
}

type liveMetadata struct {
	fact model.ToolFact
	// Key by field as well as rule and matched content. A directive that
	// moved between parameters cannot confirm the original static finding.
	fields     map[string]string
	matches    map[string][]rules.TextMatch
	unresolved map[string]bool
}

func paramField(name string) string { return "param:" + name + ".description" }

func readLiveMetadata(peer mcpclient.LiveTool) (*liveMetadata, error) {
	m := &liveMetadata{
		fact: model.ToolFact{ToolID: model.LiveToolID(peer.Name), Name: peer.Name, LiveDescription: peer.Description,
			Annotations: model.Annotations(peer.Annotations)},
		fields: map[string]string{"name": peer.Name}, matches: make(map[string][]rules.TextMatch), unresolved: make(map[string]bool),
	}
	if peer.Description != nil {
		m.fields["description"] = *peer.Description
	}
	var root map[string]json.RawMessage
	if len(peer.InputSchema) > maxSchemaBytes || json.Unmarshal(peer.InputSchema, &root) != nil || root == nil {
		return nil, mcpclient.ErrProtocolViolation
	}
	var properties map[string]json.RawMessage
	if raw, ok := root["properties"]; ok && (json.Unmarshal(raw, &properties) != nil || properties == nil) {
		return nil, mcpclient.ErrProtocolViolation
	}
	for name, raw := range properties {
		p := model.Parameter{Name: name}
		// Boolean schemas and union types still declare a parameter name.
		if !bytes.Equal(raw, []byte("true")) && !bytes.Equal(raw, []byte("false")) {
			var prop map[string]json.RawMessage
			if json.Unmarshal(raw, &prop) != nil || prop == nil {
				return nil, mcpclient.ErrProtocolViolation
			}
			if desc, ok := prop["description"]; ok {
				if json.Unmarshal(desc, &p.Description) != nil || p.Description == nil {
					return nil, mcpclient.ErrProtocolViolation
				}
				p.DescriptionResolved = true
				m.fields[paramField(name)] = *p.Description
			}
			if typ := prop["type"]; len(typ) > 0 && typ[0] == '"' {
				if err := json.Unmarshal(typ, &p.DeclaredType); err != nil {
					return nil, mcpclient.ErrProtocolViolation
				}
			}
		}
		m.fact.Parameters = append(m.fact.Parameters, p)
	}
	return m, nil
}

func (m *liveMetadata) runtimeFinding(id, field, normalized, excerpt string) model.Finding {
	f, _ := rules.FindingMetadata(id) // Only EvalPoisonText IDs and RuntimeDrift reach this path.
	f.Origin, f.StaticStatus, f.DynamicStatus = model.OriginRuntime, model.None, model.Confirmed
	f.ToolID, f.Confidence = m.fact.ToolID, model.ConfidenceHigh
	f.Fingerprint = model.LivePoisonFingerprint(id, m.fact.Name, field, normalized)
	f.Evidence = []model.EvidenceItem{{Kind: model.EvidenceObserved, Source: model.SourceMCPStdio, Detail: field,
		RedactedExcerpt: report.Sanitize(excerpt, "", 512)}}
	return f
}

func (m *liveMetadata) evalText(ctx context.Context) ([]model.Finding, error) {
	var found []model.Finding
	for field, raw := range m.fields {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		matches := rules.EvalPoisonText(field, raw)
		if len(matches) == 0 {
			continue
		}
		m.matches[field] = matches
		normalized := report.NormalizeDocstring(raw)
		for _, match := range matches {
			found = append(found, m.runtimeFinding(match.RuleID, field, normalized, match.MatchedContent))
		}
	}
	return found, nil
}

func (m *liveMetadata) drift(t model.ToolFact) []model.Finding {
	var found []model.Finding
	compare := func(field string, resolved bool, declaration *string) {
		if !resolved {
			m.unresolved[field] = true
			return
		}
		if declaration == nil {
			return
		}
		normalized := report.NormalizeDocstring(m.fields[field])
		if report.NormalizeDocstring(*declaration) != normalized {
			found = append(found, m.runtimeFinding(rules.RuntimeDrift, field, normalized, normalized))
		}
	}
	compare("description", t.DescriptionResolved, t.DeclaredDescription)
	liveNames := make(map[string]bool, len(m.fact.Parameters))
	for _, p := range m.fact.Parameters {
		liveNames[p.Name] = true
	}
	staticNames := make(map[string]bool, len(t.Parameters))
	for _, p := range t.Parameters {
		staticNames[p.Name] = true
		if liveNames[p.Name] {
			compare(paramField(p.Name), p.DescriptionResolved, p.Description)
		} else if !p.DescriptionResolved {
			m.unresolved[paramField(p.Name)] = true
		}
	}
	if !maps.Equal(staticNames, liveNames) {
		// JSON delimits names unambiguously, even for commas and control bytes.
		sortedNames := slices.AppendSeq(make([]string, 0, len(liveNames)), maps.Keys(liveNames))
		slices.Sort(sortedNames)
		names, _ := json.Marshal(sortedNames)
		found = append(found, m.runtimeFinding(rules.RuntimeDrift, "parameters", string(names), string(names)))
	}
	return found
}

func (m *liveMetadata) updateStatic(f *model.Finding) {
	for _, item := range f.Evidence {
		if item.Kind != model.EvidenceDeclared || item.Source != model.SourceTreeSitter || m.unresolved[item.Detail] {
			continue
		}
		for _, match := range m.matches[item.Detail] {
			if match.RuleID == f.ID && match.MatchedContent == item.RedactedExcerpt {
				f.DynamicStatus, f.DynamicReason = model.Confirmed, nil
				observed := item
				observed.Kind, observed.Source = model.EvidenceObserved, model.SourceMCPStdio
				f.Evidence = slices.Concat(f.Evidence, []model.EvidenceItem{observed})
				return
			}
		}
		f.DynamicStatus, f.DynamicReason = model.NotReproduced, nil
		return
	}
	f.DynamicStatus, f.DynamicReason = model.Inconclusive, new(model.DescriptionUnresolved)
}
