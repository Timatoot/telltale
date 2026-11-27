package model

import "testing"

func TestPolicySeverity(t *testing.T) {
	levels := []Severity{Info, Low, Medium, High, Critical}
	for i, threshold := range levels[1:] {
		for j, severity := range levels {
			r := ScanReport{Findings: []Finding{{Severity: severity, StaticStatus: Proven, DynamicStatus: NotRun}}}
			r.ApplyPolicy(Policy{FailOn: threshold})
			if r.Findings[0].Gating != (j >= i+1) {
				t.Errorf("%s at threshold %s: %+v", severity, threshold, r.Summary)
			}
		}
	}
}

func TestPolicyEvidenceAndPrecedence(t *testing.T) {
	for _, status := range []DynamicStatus{NotRun, Confirmed, NotReproduced, Inconclusive, Skipped, NotApplicable} {
		for _, static := range []StaticStatus{None, Proven, Suspected} {
			for _, only := range []bool{false, true} {
				for _, confidence := range []Confidence{ConfidenceLow, ConfidenceMedium, ConfidenceHigh} {
					r := ScanReport{Findings: []Finding{{Severity: High, StaticStatus: static, DynamicStatus: status, Confidence: confidence}}}
					r.ApplyPolicy(Policy{VerifiedOnly: only, Strict: true, Verify: true})
					wantCode, wantCount := 0, 0
					switch {
					case status == Confirmed || static == Proven || (!only && static == Suspected):
						wantCode, wantCount = 1, 1
					case status == Skipped || status == Inconclusive:
						wantCode = 3
					}
					s := r.Summary
					if r.Findings[0].Gating != (wantCount == 1) || s.GatingCount != wantCount ||
						s.AnalysisExitCode != wantCode || s.PolicyPassed != (wantCount == 0) || !s.CoverageComplete ||
						s.CountsBySeverity[High] != 1 || s.CountsByStaticStatus[static] != 1 || s.CountsByDynamicStatus[status] != 1 {
						t.Fatalf("%s/%s verified-only=%v confidence=%s: %+v", static, status, only, confidence, s)
					}
				}
			}
		}
	}
}

func TestPolicyStrictCoverage(t *testing.T) {
	for _, tc := range []struct {
		name             string
		coverage         Coverage
		verify, complete bool
	}{
		{name: "parse", coverage: Coverage{ParseErrors: []ParseError{{}}}},
		{name: "skipped file", coverage: Coverage{FilesSkipped: []SkippedFile{{}}}},
		{name: "registration", coverage: Coverage{UnresolvedRegistrations: []UnresolvedRegistration{{}}}},
		{name: "ambiguous join", verify: true, coverage: Coverage{RuntimeCoverage: &RuntimeCoverage{AmbiguousJoins: []string{"a"}}}},
		{name: "informational", verify: true, complete: true, coverage: Coverage{
			UnresolvedDescriptions: []UnresolvedDescription{{}}, AnalysisLimits: AnalysisLimits{CrossFileHelperCalls: []HelperCall{{}}},
			RuntimeCoverage: &RuntimeCoverage{RuntimeOnlyTools: []string{"a"}, StaticOnlyTools: []string{"b"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ScanReport{Coverage: tc.coverage, Findings: []Finding{{Severity: Medium, StaticStatus: Suspected, DynamicStatus: NotRun}}}
			for _, strict := range []bool{true, false} {
				r.ApplyPolicy(Policy{Strict: strict, Verify: tc.verify})
				want := 0
				if strict && !tc.complete {
					want = 3
				}
				if r.Findings[0].Gating || r.Summary.AnalysisExitCode != want || r.Summary.CoverageComplete != tc.complete {
					t.Fatalf("strict=%v: %+v", strict, r.Summary)
				}
			}
			r.ApplyPolicy(Policy{FailOn: Medium, Strict: true, Verify: tc.verify})
			if r.Summary.AnalysisExitCode != 1 {
				t.Fatalf("gate must take precedence over strict coverage: %+v", r.Summary)
			}
		})
	}
}
