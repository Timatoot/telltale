package opengrep

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Timatoot/telltale/internal/model"
)

// SinkMatch identifies an embedded rule and its 1-based, end-exclusive span.
type SinkMatch struct {
	RuleID string
	Span   model.Location
}

type Result struct {
	Matches      []SinkMatch
	FilesSkipped []model.SkippedFile
	ParseErrors  []model.ParseError
}

type position struct{ Line, Col int }

// Cap decoded records as well as wire bytes. A compact array of nulls
// otherwise expands many times over when decoded into Go structs.
type records[T any] []T

func (r *records[T]) UnmarshalJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('[') {
		return errors.New("expected an engine record array")
	}
	items := make(records[T], 0)
	for d.More() {
		if len(items) >= 1<<20 {
			return errors.New("engine record limit exceeded")
		}
		var item T
		if err := d.Decode(&item); err != nil {
			return err
		}
		items = append(items, item)
	}
	*r = items
	return nil
}

type scanOutput struct {
	Results records[struct {
		CheckID    string `json:"check_id"`
		Path       string
		Start, End position
	}]
	Errors records[struct {
		Path string
		Type json.RawMessage
	}]
	Paths struct{ Scanned records[string] }
}

// errorKind extracts the diagnostic class. Opengrep encodes it either as a
// string or as [class, detail]. The detail and message can contain source text.
func errorKind(raw json.RawMessage) string {
	var name string
	if len(raw) > 0 && raw[0] == '[' {
		d := json.NewDecoder(bytes.NewReader(raw))
		_, _ = d.Token()
		_ = d.Decode(&name)
	} else {
		_ = json.Unmarshal(raw, &name)
	}
	if name == "" {
		return "engine diagnostic"
	}
	return name
}

func parseScan(data []byte, files []string, repoRel func(string) (string, bool)) (Result, error) {
	var out scanOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return Result{}, fmt.Errorf("decode scan output: %w", err)
	}
	if out.Results == nil || out.Errors == nil || out.Paths.Scanned == nil {
		return Result{}, errors.New("missing results, errors or paths.scanned array")
	}
	var result Result
	seen := make(map[string]bool, len(files))
	for _, path := range out.Paths.Scanned {
		rel, ok := repoRel(path)
		if !ok {
			return Result{}, errors.New("scanned path outside target manifest")
		}
		seen[rel] = true
	}
	for _, path := range files {
		if !seen[path] {
			result.FilesSkipped = append(result.FilesSkipped, model.SkippedFile{Path: path, Reason: model.EngineSkipped})
		}
	}
	for _, diag := range out.Errors {
		// A process-wide diagnostic has no file. Keep it as incomplete coverage.
		rel, _ := repoRel(diag.Path)
		result.ParseErrors = append(result.ParseErrors, model.ParseError{Path: rel, Engine: "opengrep", Reason: errorKind(diag.Type)})
	}
	for _, hit := range out.Results {
		rel, ok := repoRel(hit.Path)
		if !ok {
			return Result{}, errors.New("match outside target manifest")
		}
		id := strings.TrimPrefix(hit.CheckID, "rules.")
		if id == "" || hit.Start.Line < 1 || hit.Start.Col < 1 || hit.End.Col < 1 || hit.End.Line < hit.Start.Line || hit.End.Line == hit.Start.Line && hit.End.Col < hit.Start.Col {
			return Result{}, errors.New("invalid match ID or span")
		}
		result.Matches = append(result.Matches, SinkMatch{RuleID: id, Span: model.Location{Path: rel, StartLine: hit.Start.Line, StartColumn: hit.Start.Col, EndLine: hit.End.Line, EndColumn: hit.End.Col}})
	}
	slices.SortFunc(result.Matches, func(a, b SinkMatch) int {
		return cmp.Or(cmp.Compare(a.Span.Path, b.Span.Path), cmp.Compare(a.Span.StartLine, b.Span.StartLine), cmp.Compare(a.Span.StartColumn, b.Span.StartColumn), cmp.Compare(a.Span.EndLine, b.Span.EndLine), cmp.Compare(a.Span.EndColumn, b.Span.EndColumn), cmp.Compare(a.RuleID, b.RuleID))
	})
	slices.SortFunc(result.ParseErrors, func(a, b model.ParseError) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reason, b.Reason))
	})
	return result, nil
}
