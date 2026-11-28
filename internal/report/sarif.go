package report

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Timatoot/telltale/internal/model"
)

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifLocation struct {
	Physical struct {
		Artifact struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region sarifRegion `json:"region"`
	} `json:"physicalLocation"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]string `json:"properties"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name    string      `json:"name"`
			Version string      `json:"version"`
			Rules   []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	ColumnKind string        `json:"columnKind"`
	Results    []sarifResult `json:"results"`
}

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// RenderSARIF uses only immutable snapshot files for source coordinates.
// Byte columns in the canonical report remain available to other consumers.
func RenderSARIF(input *model.ScanReport, canary string, snapshot fs.FS) ([]byte, error) {
	if input == nil {
		return nil, errors.New("missing report")
	}
	copyReport := *input
	findings, err := sarifLocations(input.Findings, snapshot, canary)
	if err != nil {
		return nil, err
	}
	copyReport.Findings = findings
	p := presentation{canary: canary, singleLine: true}
	r, err := p.report(&copyReport)
	if err != nil {
		return nil, err
	}
	run := sarifRun{ColumnKind: "unicodeCodePoints", Results: make([]sarifResult, 0, len(r.Findings))}
	driver := &run.Tool.Driver
	driver.Name, driver.Version = r.Tool.Name, r.Tool.Version
	driver.Rules = []sarifRule{}
	seen := make(map[string]bool)
	for _, f := range r.Findings {
		if !seen[f.ID] {
			driver.Rules = append(driver.Rules, sarifRule{f.ID, sarifText{f.Title}})
			seen[f.ID] = true
		}
		var msg strings.Builder
		fmt.Fprintf(&msg, "%s (%s): %s", f.Title, f.ToolID, f.Summary)
		for _, e := range f.Evidence {
			fmt.Fprintf(&msg, "\n%s: %s %s", e.Source, e.Detail, e.RedactedExcerpt)
		}
		result := sarifResult{RuleID: f.ID, Level: sarifLevel(f.Severity), Message: sarifText{msg.String()},
			PartialFingerprints: map[string]string{"telltale/v1": f.Fingerprint},
			Properties:          map[string]string{"static_status": string(f.StaticStatus), "dynamic_status": string(f.DynamicStatus)}}
		if f.DynamicReason != nil {
			result.Properties["dynamic_reason"] = string(*f.DynamicReason)
		}
		if loc := f.Location; loc != nil {
			var l sarifLocation
			l.Physical.Artifact.URI = loc.Path
			l.Physical.Region = sarifRegion{loc.StartLine, loc.StartColumn, loc.EndLine, loc.EndColumn}
			result.Locations = []sarifLocation{l}
		}
		run.Results = append(run.Results, result)
	}
	return marshalReport(sarifLog{Version: "2.1.0", Runs: []sarifRun{run}}, canary)
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	default:
		return "note"
	}
}

// Group by path so each bounded ingest file is read and indexed once, even
// when many overlapping findings refer to the same long line.
func sarifLocations(findings []model.Finding, snapshot fs.FS, canary string) ([]model.Finding, error) {
	out := slices.Clone(findings)
	byPath := make(map[string][]int)
	for i, f := range out {
		if loc := f.Location; loc != nil {
			if !fs.ValidPath(loc.Path) || snapshot == nil {
				return nil, errors.New("expected snapshot-relative source location")
			}
			byPath[loc.Path] = append(byPath[loc.Path], i)
		}
	}
	for path, indices := range byPath {
		data, err := fs.ReadFile(snapshot, path)
		if err != nil {
			return nil, fmt.Errorf("read snapshot source: %w", err)
		}
		lines := []int{0}
		var continuation []int
		for i, b := range data {
			if b == '\n' {
				lines = append(lines, i+1)
			} else if !utf8.RuneStart(b) {
				continuation = append(continuation, i)
			}
		}
		column := func(line, col int) (int, error) {
			if line < 1 || line > len(lines) || col < 1 {
				return 0, errors.New("invalid source position")
			}
			begin, end := lines[line-1], len(data)
			if line < len(lines) {
				end = lines[line] - 1
			}
			if col-1 > end-begin {
				return 0, errors.New("source column past end of line")
			}
			at := begin + col - 1
			prior, _ := slices.BinarySearch(continuation, begin)
			until, split := slices.BinarySearch(continuation, at)
			if split {
				return 0, errors.New("source column splits a Unicode code point")
			}
			return col - (until - prior), nil
		}
		// A URI identifies the real filename, even when it contains an
		// invisible character. Percent-encode it before display sanitization.
		if canary != "" {
			path = strings.ReplaceAll(path, canary, redacted)
		}
		u := url.URL{Path: path}
		uri := strings.ReplaceAll(u.EscapedPath(), ":", "%3A")
		for _, i := range indices {
			loc := *out[i].Location
			if loc.EndLine < loc.StartLine || loc.EndLine == loc.StartLine && loc.EndColumn < loc.StartColumn {
				return nil, errors.New("reversed source region")
			}
			loc.StartColumn, err = column(loc.StartLine, loc.StartColumn)
			if err != nil {
				return nil, err
			}
			loc.EndColumn, err = column(loc.EndLine, loc.EndColumn)
			if err != nil {
				return nil, err
			}
			loc.Path = uri
			out[i].Location = &loc
		}
	}
	return out, nil
}
