package rules

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/Timatoot/telltale/internal/model"
)

// TextMatch carries the static content anchor. Live callers can apply the same
// detector and use the normalized full field for the runtime fingerprint.
type TextMatch struct {
	RuleID         string
	MatchedContent string
}

var directives = []struct {
	id string
	re *regexp.Regexp
}{
	{override, regexp.MustCompile(`(?i)\b(ignore|disregard|override|forget)\s+(all\s+|any\s+|the\s+|your\s+)*(previous|prior|earlier|system|developer|above)\s+(instructions?|prompts?|rules?|messages?)\b`)},
	{exfil, regexp.MustCompile(`(?i)\b(?:(send|upload|forward|transmit|reveal|disclose|exfiltrate)\s+(?:(?:all|any|the|your|user['’]s|stored|saved|secret)\s+)*(?:api[ _-]?keys?|access[ _-]?tokens?|credentials?|passwords?|secrets?)|(?:secretly|silently|covertly)\s+(?:send|upload|forward|transmit)\s+(?:the\s+)?(?:files?|data|contents?))\b`)},
	{crossTool, regexp.MustCompile(`(?i)\b(?:(?:(?:call|invoke)\s+(?:the\s+)?(?:tool\s+)?[\w.-]+|use\s+(?:the\s+)?[\w.-]+\s+tool)\s+(?:instead of|in place of)\s+(?:the\s+)?[\w.-]+|(?:impersonate|pretend to be)\s+(?:the\s+|another\s+)?[\w.-]+\s+tool)\b`)},
}

var negated = regexp.MustCompile(`(?i)\b(?:not|never|don['’]t|avoid)\s+(?:ever\s+)?$`)

// EvalPoisonText evaluates one resolved metadata field. Normal multiline
// layout is permitted in prose. Inspect the raw Unicode before normalizing
// matched phrases so formatting controls are preserved as evidence.
func EvalPoisonText(field, value string) []TextMatch {
	var matches []TextMatch
	codes := make(map[rune]bool)
	multiline := field == "description" || strings.HasSuffix(field, ".description")
	if multiline {
		value = strings.ReplaceAll(value, "\r\n", "\n")
	}
	for _, r := range value {
		if (unicode.IsControl(r) && (!multiline || r != '\n' && r != '\t')) ||
			unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			codes[r] = true
		}
	}
	if len(codes) > 0 {
		var labels []string
		for _, r := range slices.Sorted(maps.Keys(codes)) {
			labels = append(labels, fmt.Sprintf("U+%04X", r))
		}
		matches = append(matches, TextMatch{invisible, strings.Join(labels, " ")})
	}
	for _, d := range directives {
		for rest := value; ; {
			at := d.re.FindStringIndex(rest)
			if at == nil {
				break
			}
			if !negated.MatchString(rest[max(0, at[0]-64):at[0]]) {
				phrase := strings.ToLower(strings.Join(strings.Fields(rest[at[0]:at[1]]), " "))
				matches = append(matches, TextMatch{d.id, phrase})
				break
			}
			rest = rest[at[1]:]
		}
	}
	return matches
}

func staticPoison(t model.ToolFact) []model.Finding {
	var findings []model.Finding
	field := func(path, value string) {
		for _, m := range EvalPoisonText(path, value) {
			fp := model.PoisonFingerprint(m.RuleID, t.SourceLocation.Path, t.Name, path, m.MatchedContent)
			findings = append(findings, staticFinding(m.RuleID, t, t.SourceLocation, fp, model.EvidenceItem{
				Kind: model.EvidenceDeclared, Source: model.SourceTreeSitter, Detail: path, RedactedExcerpt: m.MatchedContent,
			}))
		}
	}
	field("name", t.Name)
	if t.DescriptionResolved && t.DeclaredDescription != nil {
		field("description", *t.DeclaredDescription)
	}
	for _, p := range t.Parameters {
		if p.DescriptionResolved && p.Description != nil {
			field("param:"+p.Name+".description", *p.Description)
		}
	}
	return findings
}
