// Package model defines telltale's canonical 1.0 report and finding identities.
package model

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
)

const SchemaVersion = "1.0"

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type StaticStatus string

const (
	Proven    StaticStatus = "proven"
	Suspected StaticStatus = "suspected"
	None      StaticStatus = "none"
)

type DynamicStatus string

const (
	NotRun        DynamicStatus = "not_run"
	Confirmed     DynamicStatus = "confirmed"
	NotReproduced DynamicStatus = "not_reproduced"
	Inconclusive  DynamicStatus = "inconclusive"
	Skipped       DynamicStatus = "skipped"
	NotApplicable DynamicStatus = "not_applicable"
)

type DynamicReason string

const (
	NoWorkspaceClaim      DynamicReason = "no_workspace_claim"
	ServerCrash           DynamicReason = "server_crash"
	HandshakeFailed       DynamicReason = "handshake_failed"
	ProtocolViolation     DynamicReason = "protocol_violation"
	Timeout               DynamicReason = "timeout"
	ResourceLimit         DynamicReason = "resource_limit"
	UnsupportedSchema     DynamicReason = "unsupported_schema"
	ToolError             DynamicReason = "tool_error"
	ResponseTruncated     DynamicReason = "response_truncated"
	AmbiguousJoin         DynamicReason = "ambiguous_join"
	NoisyWorkspace        DynamicReason = "noisy_workspace"
	BudgetExhausted       DynamicReason = "budget_exhausted"
	ToolNotLive           DynamicReason = "tool_not_live"
	DescriptionUnresolved DynamicReason = "description_unresolved"
)

type SkipReason string

const (
	Symlink       SkipReason = "symlink"
	NonRegular    SkipReason = "non_regular"
	SizeCap       SkipReason = "size_cap"
	CountCap      SkipReason = "count_cap"
	TotalCap      SkipReason = "total_cap"
	EngineSkipped SkipReason = "engine_skipped"
)

type ScanReport struct {
	SchemaVersion string     `json:"schema_version"`
	Tool          Tool       `json:"tool"`
	Target        Target     `json:"target"`
	Coverage      Coverage   `json:"coverage"`
	Inventory     []ToolFact `json:"inventory"`
	Findings      []Finding  `json:"findings"`
	Summary       Summary    `json:"summary"`
}

type Tool struct {
	Name            string  `json:"name"`
	Version         string  `json:"version"`
	OpengrepVersion string  `json:"opengrep_version"`
	RuntimeBackend  string  `json:"runtime_backend"`
	RuntimeVersion  *string `json:"runtime_version"`
}

type Target struct {
	RepoName string `json:"repo_name"`
	Mode     string `json:"mode"`
	Image    *Image `json:"image"`
}
type Image struct {
	Ref     string `json:"ref"`
	ImageID string `json:"image_id"`
}

type Coverage struct {
	FilesScanned            int                      `json:"files_scanned"`
	FilesSkipped            []SkippedFile            `json:"files_skipped"`
	ParseErrors             []ParseError             `json:"parse_errors"`
	ToolsDiscovered         int                      `json:"tools_discovered"`
	UnresolvedRegistrations []UnresolvedRegistration `json:"unresolved_registrations"`
	UnresolvedDescriptions  []UnresolvedDescription  `json:"unresolved_descriptions"`
	*RuntimeCoverage
	AnalysisLimits AnalysisLimits `json:"analysis_limits"`
}
type RuntimeCoverage struct {
	StaticOnlyTools  []string `json:"static_only_tools"`
	RuntimeOnlyTools []string `json:"runtime_only_tools"`
	AmbiguousJoins   []string `json:"ambiguous_joins"`
}
type SkippedFile struct {
	Path   string     `json:"path"`
	Reason SkipReason `json:"reason"`
}
type ParseError struct {
	Path   string `json:"path"`
	Engine string `json:"engine"`
	Reason string `json:"reason"`
}
type UnresolvedRegistration struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Reason string `json:"reason"`
}
type UnresolvedDescription struct {
	ToolID string `json:"tool_id"`
	Field  string `json:"field"`
}
type AnalysisLimits struct {
	CrossFileHelperCalls []HelperCall `json:"cross_file_helper_calls"`
}
type HelperCall struct {
	ToolID       string `json:"tool_id"`
	CalleeModule string `json:"callee_module"`
}

type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column"`
}

type ToolFact struct {
	ToolID              string      `json:"tool_id"`
	Name                string      `json:"name"`
	SourceLocation      *Location   `json:"source_location"`
	DeclaredDescription *string     `json:"declared_description"`
	DescriptionResolved bool        `json:"description_resolved"`
	LiveDescription     *string     `json:"live_description"`
	Parameters          []Parameter `json:"parameters"`
	Annotations         Annotations `json:"annotations"`
	InferredSinks       []Sink      `json:"inferred_sinks"`
}
type Parameter struct {
	Name                string  `json:"name"`
	DeclaredType        string  `json:"declared_type"`
	Description         *string `json:"description"`
	DescriptionResolved bool    `json:"description_resolved"`
}
type Annotations struct {
	ReadOnlyHint    *bool `json:"read_only_hint"`
	DestructiveHint *bool `json:"destructive_hint"`
	OpenWorldHint   *bool `json:"open_world_hint"`
}
type Sink struct {
	Category         string   `json:"category"`
	RuleID           string   `json:"rule_id"`
	Span             Location `json:"span"`
	NormalizedCallee string   `json:"normalized_callee"`
}

type Finding struct {
	ID            string         `json:"id"`
	Fingerprint   string         `json:"fingerprint"`
	Origin        string         `json:"origin"`
	Family        string         `json:"family"`
	Title         string         `json:"title"`
	Summary       string         `json:"summary"`
	Remediation   string         `json:"remediation"`
	Severity      Severity       `json:"severity"`
	Confidence    string         `json:"confidence"`
	StaticStatus  StaticStatus   `json:"static_status"`
	DynamicStatus DynamicStatus  `json:"dynamic_status"`
	DynamicReason *DynamicReason `json:"dynamic_reason"`
	Gating        bool           `json:"gating"`
	ToolID        string         `json:"tool_id"`
	Location      *Location      `json:"location"`
	Evidence      []EvidenceItem `json:"evidence"`
	Mappings      Mappings       `json:"mappings"`
}
type EvidenceItem struct {
	Kind            string `json:"kind"`
	Source          string `json:"source"`
	Detail          string `json:"detail"`
	RedactedExcerpt string `json:"redacted_excerpt"`
}
type Mappings struct {
	CWE []string `json:"cwe"`
}
type Summary struct {
	CountsBySeverity      map[Severity]int      `json:"counts_by_severity"`
	CountsByStaticStatus  map[StaticStatus]int  `json:"counts_by_static_status"`
	CountsByDynamicStatus map[DynamicStatus]int `json:"counts_by_dynamic_status"`
	GatingCount           int                   `json:"gating_count"`
	CoverageComplete      bool                  `json:"coverage_complete"`
	PolicyPassed          bool                  `json:"policy_passed"`
	AnalysisExitCode      int                   `json:"analysis_exit_code"`
}

// Sort orders an owned report in place. Break ties on the complete record so
// worker completion order cannot change the artifact, even for duplicate keys.
func (r *ScanReport) Sort() {
	c := &r.Coverage
	slices.SortFunc(c.FilesSkipped, func(a, b SkippedFile) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason, b.Reason))
	})
	slices.SortFunc(c.ParseErrors, func(a, b ParseError) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Engine, b.Engine), cmp.Compare(a.Reason, b.Reason))
	})
	slices.SortFunc(c.UnresolvedRegistrations, func(a, b UnresolvedRegistration) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Line, b.Line), cmp.Compare(a.Reason, b.Reason))
	})
	slices.SortFunc(c.UnresolvedDescriptions, func(a, b UnresolvedDescription) int {
		return cmp.Or(cmp.Compare(a.ToolID, b.ToolID), cmp.Compare(a.Field, b.Field))
	})
	slices.SortFunc(c.AnalysisLimits.CrossFileHelperCalls, func(a, b HelperCall) int {
		return cmp.Or(cmp.Compare(a.ToolID, b.ToolID), cmp.Compare(a.CalleeModule, b.CalleeModule))
	})
	if c.RuntimeCoverage != nil {
		slices.Sort(c.StaticOnlyTools)
		slices.Sort(c.RuntimeOnlyTools)
		slices.Sort(c.AmbiguousJoins)
	}
	for _, t := range r.Inventory {
		order(t.Parameters, func(a, b Parameter) int { return cmp.Compare(a.Name, b.Name) })
		order(t.InferredSinks, func(a, b Sink) int {
			return cmp.Or(cmp.Compare(a.Span.Path, b.Span.Path), cmp.Compare(a.Span.StartLine, b.Span.StartLine), cmp.Compare(a.Span.StartColumn, b.Span.StartColumn))
		})
	}
	order(r.Inventory, func(a, b ToolFact) int { return cmp.Compare(a.ToolID, b.ToolID) })
	for _, f := range r.Findings {
		slices.SortFunc(f.Evidence, func(a, b EvidenceItem) int {
			return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Source, b.Source), cmp.Compare(a.Detail, b.Detail), cmp.Compare(a.RedactedExcerpt, b.RedactedExcerpt))
		})
		slices.Sort(f.Mappings.CWE)
	}
	order(r.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(severityRank(b.Severity), severityRank(a.Severity)), cmp.Compare(a.ID, b.ID), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
}

func severityRank(s Severity) int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

func order[T any](items []T, primary func(T, T) int) {
	slices.SortFunc(items, func(a, b T) int {
		if n := primary(a, b); n != 0 {
			return n
		}
		// All callers use fixed report structs with JSON-encodable fields.
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Compare(left, right)
	})
}
