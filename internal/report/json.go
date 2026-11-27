package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Timatoot/telltale/internal/model"
)

// RenderJSON builds a presentation copy. Keep the original bytes, spans and
// ordering available for identity, evidence correlation and other reporters.
func RenderJSON(input *model.ScanReport, canary string) ([]byte, error) {
	if input == nil || input.SchemaVersion != model.SchemaVersion {
		return nil, errors.New("expected a schema 1.0 report")
	}
	if code := input.Summary.AnalysisExitCode; code != 0 && code != 1 && code != 3 {
		return nil, errors.New("invalid analysis exit code")
	}
	p := presentation{canary: canary}
	r := *input
	r.Tool.Name = p.ident(r.Tool.Name)
	r.Tool.Version = p.ident(r.Tool.Version)
	r.Tool.OpengrepVersion = p.ident(r.Tool.OpengrepVersion)
	r.Tool.RuntimeBackend = p.ident(r.Tool.RuntimeBackend)
	r.Tool.RuntimeVersion = p.optionalIdent(r.Tool.RuntimeVersion)
	r.Target.RepoName = strings.ToValidUTF8(r.Target.RepoName, "�")
	if !fs.ValidPath(r.Target.RepoName) || strings.Contains(r.Target.RepoName, "/") || windowsAbsolute(r.Target.RepoName) {
		return nil, errors.New("expected a repository basename")
	}
	r.Target.RepoName = p.ident(r.Target.RepoName)
	if r.Target.Image != nil {
		img := *r.Target.Image
		img.Ref = p.ident(img.Ref)
		// The image digest and finding fingerprints are generated identifiers.
		r.Target.Image = &img
	}
	r.Coverage = p.coverage(r.Coverage, r.Target.Mode)
	r.Inventory = project(r.Inventory, p.tool)
	r.Findings = project(r.Findings, p.finding)
	if p.err != nil {
		return nil, p.err
	}
	r.Summary.CountsBySeverity = counts(r.Summary.CountsBySeverity)
	r.Summary.CountsByStaticStatus = counts(r.Summary.CountsByStaticStatus)
	r.Summary.CountsByDynamicStatus = counts(r.Summary.CountsByDynamicStatus)
	r.Sort()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serialize report: %w", err)
	}
	if canary != "" {
		// Check even trusted metadata and JSON keys. Marshal the needle with
		// the same encoder so that JSON-escaped contents cannot slip through.
		quoted, err := json.Marshal(canary)
		if err != nil {
			return nil, fmt.Errorf("encode redaction guard: %w", err)
		}
		if bytes.Contains(data, []byte(canary)) || bytes.Contains(data, quoted[1:len(quoted)-1]) {
			return nil, errors.New("canary present in report")
		}
	}
	return append(data, '\n'), nil
}

func counts[K comparable](m map[K]int) map[K]int {
	if m == nil {
		return map[K]int{}
	}
	return m
}

// project always allocates an owned JSON array, including for an empty input.
func project[T any](items []T, transform func(T) T) []T {
	out := make([]T, len(items))
	for i, item := range items {
		out[i] = transform(item)
	}
	return out
}

type presentation struct {
	canary string
	err    error
}

func (p *presentation) text(s string) string { return Sanitize(s, p.canary, maxFieldBytes) }
func (p *presentation) ident(s string) string {
	return SanitizeIdentifier(s, p.canary, maxFieldBytes)
}
func (p *presentation) optionalIdent(s *string) *string {
	if s == nil {
		return nil
	}
	clean := p.ident(*s)
	return &clean
}
func (p *presentation) multiline(s string) string {
	return SanitizeMultiline(s, p.canary, maxFieldBytes)
}
func (p *presentation) optionalMultiline(s *string) *string {
	if s == nil {
		return nil
	}
	clean := p.multiline(*s)
	return &clean
}

func windowsAbsolute(s string) bool {
	if strings.HasPrefix(s, `\\`) {
		return true
	}
	if len(s) < 3 || s[1] != ':' {
		return false
	}
	drive := (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')
	return drive && (s[2] == '/' || s[2] == '\\')
}

func (p *presentation) path(s string) string {
	s = strings.ToValidUTF8(filepath.ToSlash(s), "�")
	if !fs.ValidPath(s) || s == "." || windowsAbsolute(s) {
		p.err = errors.New("expected a repository-relative file path")
		return ""
	}
	parts := strings.Split(s, "/")
	for i := range parts {
		parts[i] = p.ident(parts[i])
	}
	return strings.Join(parts, "/")
}

func (p *presentation) id(id string) string {
	// The ID format permits colons in both names and POSIX filenames. Its
	// source path is validated separately via the location or coverage record.
	if body, static := strings.CutPrefix(id, "py:"); static {
		if strings.HasPrefix(body, "/") || strings.HasPrefix(body, "../") || windowsAbsolute(body) {
			p.err = errors.New("expected a repository-relative path in tool ID")
			return ""
		}
	}
	return p.ident(id)
}

func (p *presentation) location(loc *model.Location) *model.Location {
	if loc == nil {
		return nil
	}
	out := *loc
	out.Path = p.path(loc.Path)
	return &out
}
func (p *presentation) coverage(c model.Coverage, mode string) model.Coverage {
	c.FilesSkipped = project(c.FilesSkipped, func(v model.SkippedFile) model.SkippedFile {
		v.Path = p.path(v.Path)
		return v
	})
	c.ParseErrors = project(c.ParseErrors, func(v model.ParseError) model.ParseError {
		// Opengrep can report an error for the entire scan.
		if v.Path != "" || v.Engine != string(model.SourceOpengrep) {
			v.Path = p.path(v.Path)
		}
		v.Engine = p.ident(v.Engine)
		v.Reason = p.text(v.Reason)
		return v
	})
	c.UnresolvedRegistrations = project(c.UnresolvedRegistrations, func(v model.UnresolvedRegistration) model.UnresolvedRegistration {
		v.Path = p.path(v.Path)
		v.Reason = p.text(v.Reason)
		return v
	})
	c.UnresolvedDescriptions = project(c.UnresolvedDescriptions, func(v model.UnresolvedDescription) model.UnresolvedDescription {
		v.ToolID = p.id(v.ToolID)
		v.Field = p.ident(v.Field)
		return v
	})
	c.AnalysisLimits.CrossFileHelperCalls = project(c.AnalysisLimits.CrossFileHelperCalls, func(v model.HelperCall) model.HelperCall {
		v.ToolID = p.id(v.ToolID)
		v.CalleeModule = p.ident(v.CalleeModule)
		return v
	})
	if mode == "verify" {
		var runtime model.RuntimeCoverage
		if c.RuntimeCoverage != nil {
			runtime = *c.RuntimeCoverage
		}
		runtime.StaticOnlyTools = project(runtime.StaticOnlyTools, p.ident)
		runtime.RuntimeOnlyTools = project(runtime.RuntimeOnlyTools, p.ident)
		runtime.AmbiguousJoins = project(runtime.AmbiguousJoins, p.ident)
		c.RuntimeCoverage = &runtime
	} else {
		c.RuntimeCoverage = nil
	}
	return c
}

func (p *presentation) tool(t model.ToolFact) model.ToolFact {
	t.ToolID = p.id(t.ToolID)
	t.Name = p.ident(t.Name)
	t.SourceLocation = p.location(t.SourceLocation)
	t.DeclaredDescription = p.optionalMultiline(t.DeclaredDescription)
	t.LiveDescription = p.optionalMultiline(t.LiveDescription)
	t.Parameters = project(t.Parameters, func(v model.Parameter) model.Parameter {
		v.Name = p.ident(v.Name)
		v.DeclaredType = p.ident(v.DeclaredType)
		v.Description = p.optionalMultiline(v.Description)
		return v
	})
	t.InferredSinks = project(t.InferredSinks, func(v model.Sink) model.Sink {
		v.Span.Path = p.path(v.Span.Path)
		v.Category = p.ident(v.Category)
		v.RuleID = p.ident(v.RuleID)
		v.NormalizedCallee = p.ident(v.NormalizedCallee)
		return v
	})
	return t
}

func (p *presentation) finding(f model.Finding) model.Finding {
	f.ToolID = p.id(f.ToolID)
	f.Location = p.location(f.Location)
	f.Title = p.text(f.Title)
	f.Summary = p.multiline(f.Summary)
	f.Remediation = p.multiline(f.Remediation)
	f.Evidence = project(f.Evidence, func(e model.EvidenceItem) model.EvidenceItem {
		e.Detail = p.text(e.Detail)
		e.RedactedExcerpt = SanitizeMultiline(e.RedactedExcerpt, p.canary, excerptBytes)
		return e
	})
	f.Mappings.CWE = project(f.Mappings.CWE, p.ident)
	return f
}
