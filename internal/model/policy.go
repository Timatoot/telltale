package model

// Policy contains the validated audit policy options. Its zero value applies
// the default high severity threshold to a static audit.
type Policy struct {
	FailOn       Severity
	VerifiedOnly bool
	Strict       bool
	Verify       bool
}

// ApplyPolicy updates the report after analysis. Fatal process or artifact
// errors take precedence at the CLI and never become analysis exit codes.
func (r *ScanReport) ApplyPolicy(p Policy) {
	if p.FailOn == "" {
		p.FailOn = High
	}
	c := r.Coverage
	s := Summary{
		CountsBySeverity:      make(map[Severity]int),
		CountsByStaticStatus:  make(map[StaticStatus]int),
		CountsByDynamicStatus: make(map[DynamicStatus]int),
		CoverageComplete: len(c.FilesSkipped) == 0 && len(c.ParseErrors) == 0 &&
			len(c.UnresolvedRegistrations) == 0 && (!p.Verify || c.RuntimeCoverage == nil || len(c.AmbiguousJoins) == 0),
	}
	strictGap := !s.CoverageComplete
	for i := range r.Findings {
		f := &r.Findings[i]
		s.CountsBySeverity[f.Severity]++
		s.CountsByStaticStatus[f.StaticStatus]++
		s.CountsByDynamicStatus[f.DynamicStatus]++
		eligible := f.StaticStatus == Proven || f.DynamicStatus == Confirmed || (!p.VerifiedOnly && f.StaticStatus == Suspected)
		f.Gating = eligible && severityRank(f.Severity) >= severityRank(p.FailOn)
		if f.Gating {
			s.GatingCount++
		}
		if p.Verify && (f.DynamicStatus == Skipped || f.DynamicStatus == Inconclusive) {
			strictGap = true
		}
	}
	s.PolicyPassed = s.GatingCount == 0
	switch {
	case !s.PolicyPassed:
		s.AnalysisExitCode = 1
	case p.Strict && strictGap:
		s.AnalysisExitCode = 3
	}
	r.Summary = s
}
