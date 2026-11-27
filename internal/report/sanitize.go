// Package report formats immutable canonical reports for presentation.
package report

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxFieldBytes = 1 << 20
	excerptBytes  = 512
	redacted      = "[REDACTED]"
)

// Redact explicitly labeled credentials, including ones whose entropy alone
// would be inconclusive. The second pass catches unlabeled token-like values.
var (
	credential = regexp.MustCompile(`(?i)(\bbearer\s+|\b(?:api[_-]?key|access[_-]?token|api[_-]?token|secret|password)["']?\s*[:=]\s*["']?)([A-Za-z0-9._~+/=%-]+)`)
	token      = regexp.MustCompile(`[A-Za-z0-9_+/=-]{24,}`)
)

func redactToken(s string) string {
	var counts [128]int
	hexOnly := true
	for i := range len(s) {
		c := s[i] // token matches ASCII only
		counts[c]++
		hexDigit := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		hexOnly = hexOnly && hexDigit
	}
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(len(s))
			entropy -= p * math.Log2(p)
		}
	}
	if entropy >= 4.25 || hexOnly && len(s) >= 32 && entropy >= 3.4 {
		return redacted
	}
	return s
}

// Sanitize returns at most maxBytes of valid UTF-8. Redact before clipping so
// a cutoff inside a credential cannot disclose its prefix.
func Sanitize(text, canary string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(text) > maxFieldBytes {
		text = "[truncated]"
	}
	if canary != "" {
		text = strings.ReplaceAll(text, canary, redacted)
	}
	text = credential.ReplaceAllString(text, "${1}"+redacted)
	text = token.ReplaceAllStringFunc(text, redactToken)
	var out strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector) {
			esc := fmt.Sprintf("<U+%04X>", r)
			if len(esc) > maxBytes-out.Len() {
				break
			}
			out.WriteString(esc)
		} else {
			if utf8.RuneLen(r) > maxBytes-out.Len() {
				break
			}
			out.WriteRune(r)
		}
	}
	return out.String()
}

// NormalizeDocstring applies inspect.cleandoc indentation rules, also removing
// trailing whitespace on each line. Unicode composition is preserved.
func NormalizeDocstring(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if strings.ContainsRune(text, '\t') {
		var expanded strings.Builder
		column := 0
		for _, r := range text {
			switch r {
			case '\t':
				width := 8 - column%8
				expanded.WriteString("        "[:width])
				column += width
			case '\n', '\r':
				expanded.WriteRune(r)
				column = 0
			default:
				expanded.WriteRune(r)
				column++
			}
		}
		text = expanded.String()
	}

	lines := strings.Split(text, "\n")
	margin := len(text)
	for i, line := range lines {
		line = strings.TrimRightFunc(line, docSpace)
		lines[i] = line
		if i > 0 && line != "" {
			indent := len(line) - len(strings.TrimLeftFunc(line, docSpace))
			margin = min(margin, utf8.RuneCountInString(line[:indent]))
		}
	}
	lines[0] = strings.TrimLeftFunc(lines[0], docSpace)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		for n := 0; n < margin && line != ""; n++ {
			_, width := utf8.DecodeRuneInString(line)
			line = line[width:]
		}
		lines[i] = line
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

// Python str.isspace also includes the four ASCII information separators.
func docSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}
