package report

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/Timatoot/telltale/internal/model"
)

func analysisStatus(code int) string {
	switch code {
	case 1:
		return "policy_violation"
	case 3:
		return "incomplete"
	default:
		return "pass"
	}
}

func coverageWarnings(c model.Coverage) []string {
	var warnings []string
	for _, s := range c.FilesSkipped {
		warnings = append(warnings, fmt.Sprintf("Skipped %s (%s)", s.Path, s.Reason))
	}
	for _, e := range c.ParseErrors {
		warnings = append(warnings, fmt.Sprintf("%s %s: %s", e.Engine, e.Path, e.Reason))
	}
	for _, u := range c.UnresolvedRegistrations {
		warnings = append(warnings, fmt.Sprintf("Unresolved registration at %s:%d (%s)", u.Path, u.Line, u.Reason))
	}
	for _, u := range c.UnresolvedDescriptions {
		warnings = append(warnings, fmt.Sprintf("Unresolved description for %s (%s)", u.ToolID, u.Field))
	}
	if c.RuntimeCoverage != nil {
		for _, id := range c.StaticOnlyTools {
			warnings = append(warnings, "Static-only tool: "+id)
		}
		for _, id := range c.RuntimeOnlyTools {
			warnings = append(warnings, "Runtime-only tool: "+id)
		}
		for _, id := range c.AmbiguousJoins {
			warnings = append(warnings, "Ambiguous tool: "+id)
		}
	}
	return warnings
}

func guardedOutput(data []byte, canary string, encoded string) ([]byte, error) {
	if canary != "" && (bytes.Contains(data, []byte(canary)) || bytes.Contains(data, []byte(encoded))) {
		return nil, errors.New("canary present in report")
	}
	return data, nil
}

// RenderTerminal applies color only to the scanner's own status label.
func RenderTerminal(input *model.ScanReport, canary string, noColor bool) ([]byte, error) {
	p := presentation{canary: canary, singleLine: true}
	r, err := p.report(input)
	if err != nil {
		return nil, err
	}
	status := analysisStatus(r.Summary.AnalysisExitCode)
	if !noColor {
		color := "\x1b[32m"
		if r.Summary.AnalysisExitCode != 0 {
			color = "\x1b[33m"
		}
		status = color + status + "\x1b[0m"
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "telltale audit: repo=%s mode=%s findings=%d status=%s\n",
		r.Target.RepoName, r.Target.Mode, len(r.Findings), status)
	fmt.Fprintf(&out, "Files scanned: %d  Tools discovered: %d  Gating findings: %d  Coverage complete: %t\n",
		r.Coverage.FilesScanned, r.Coverage.ToolsDiscovered, r.Summary.GatingCount, r.Summary.CoverageComplete)
	for _, f := range r.Findings {
		fmt.Fprintf(&out, "\n[%s] %s  %s\n  %s", f.Severity, f.ID, f.Title, f.ToolID)
		if loc := f.Location; loc != nil {
			fmt.Fprintf(&out, "  %s:%d:%d", loc.Path, loc.StartLine, loc.StartColumn)
		}
		fmt.Fprintf(&out, "\n  static_status=%s dynamic_status=%s", f.StaticStatus, f.DynamicStatus)
		if f.DynamicReason != nil {
			fmt.Fprintf(&out, " (%s)", *f.DynamicReason)
		}
		fmt.Fprintln(&out)
		fmt.Fprintf(&out, "  %s\n", f.Summary)
		for _, e := range f.Evidence {
			fmt.Fprintf(&out, "  %s: %s %s\n", e.Source, e.Detail, e.RedactedExcerpt)
		}
	}
	for _, warning := range coverageWarnings(r.Coverage) {
		fmt.Fprintln(&out, "Coverage:", warning)
	}
	for _, h := range r.Coverage.AnalysisLimits.CrossFileHelperCalls {
		fmt.Fprintf(&out, "analysis_limits: %s calls into %s\n", h.ToolID, h.CalleeModule)
	}
	return guardedOutput(out.Bytes(), canary, canary)
}
