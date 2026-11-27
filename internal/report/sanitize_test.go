package report

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitize(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"ok\u202E\u2066\u200B\uFEFF", "ok<U+202E><U+2066><U+200B><U+FEFF>"},
		{"\x1b[31mred\x1b[0m\r\n\x00\u0085", "<U+001B>[31mred<U+001B>[0m<U+000D><U+000A><U+0000><U+0085>"},
		{"Bearer abc.def-123", "Bearer " + redacted},
		{`"api_key": "simple-key"`, `"api_key": "[REDACTED]"`},
		{"prefix Az9By8Cx7Dw6Ev5Fu4Gt3Hs2Ir1Jq0 suffix", "prefix " + redacted + " suffix"},
		{"prefix 65fbc132d649a07e7b492a3c20df81e5", "prefix " + redacted},
		{"local canary-value in canary-value", "local " + redacted + " in " + redacted},
		{"normal readable description", "normal readable description"},
	} {
		if got := Sanitize(tc.input, "canary-value", 512); got != tc.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
func TestSanitizeByteLimit(t *testing.T) {
	for _, tc := range []struct {
		text  string
		limit int
		want  string
	}{
		{"a🙂b", 4, "a"}, {"a🙂b", 5, "a🙂"}, {"a\x1b", 8, "a"}, {"a\x1b", 9, "a<U+001B>"},
		{"Bearer abcdef", 10, "Bearer [RE"}, {"canary-value", 4, "[RED"}, {"hello", 0, ""},
		{strings.Repeat("x", maxFieldBytes+1), 32, "[truncated]"},
	} {
		got := Sanitize(tc.text, "canary-value", tc.limit)
		if got != tc.want || !utf8.ValidString(got) || len(got) > tc.limit {
			t.Errorf("limit %d: got %q, want %q", tc.limit, got, tc.want)
		}
	}
}
func TestNormalizeDocstring(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"  title  \r\n\tsecond\tword  \r\n\t  third\n \t\n", "title\nsecond  word\n  third"},
		{"\n   \n  alpha\n    beta\n\n", "alpha\n  beta"},
		{"\n\u3000alpha\n beta", "alpha\nbeta"},
		{"  e\u0301 \n   \ufb01\u200b  ", "e\u0301\n\ufb01\u200b"},
		{"\n\t   \n", ""},
		{"\x1ctitle\x1d\n\x1fmore", "title\nmore"},
	} {
		if got := NormalizeDocstring(tc.in); got != tc.want {
			t.Errorf("NormalizeDocstring(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeMultiline(t *testing.T) {
	in := "line1\n\tindented\r\n\x1b[31m\x00\u0085\u202E\u200B Bearer tok123 Az9By8Cx7Dw6Ev5Fu4Gt3Hs2Ir1Jq0 canary-value"
	want := "line1\n\tindented<U+000D>\n<U+001B>[31m<U+0000><U+0085><U+202E><U+200B> Bearer [REDACTED] [REDACTED] [REDACTED]"
	if got := SanitizeMultiline(in, "canary-value", 512); got != want {
		t.Errorf("SanitizeMultiline() = %q, want %q", got, want)
	}
	if got := SanitizeMultiline("a\n\t🙂b", "", 5); got != "a\n\t" || !utf8.ValidString(got) {
		t.Errorf("SanitizeMultiline byte limit = %q", got)
	}
	if got := SanitizeMultiline(strings.Repeat("x\n", maxFieldBytes), "", 32); got != "[truncated]" {
		t.Errorf("SanitizeMultiline maxFieldBytes = %q", got)
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	const digestRef = "localhost/mcp@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, tc := range []struct{ input, want string }{
		{digestRef, digestRef},
		{"pkg/65fbc132d649a07e7b492a3c20df81e5/server.py", "pkg/65fbc132d649a07e7b492a3c20df81e5/server.py"},
		{"password=demo.py", "password=demo.py"},
		{"id\n\t\r\x1b\u202E\u200B-canary-value", "id<U+000A><U+0009><U+000D><U+001B><U+202E><U+200B>-[REDACTED]"},
	} {
		if got := SanitizeIdentifier(tc.input, "canary-value", 512); got != tc.want {
			t.Errorf("SanitizeIdentifier(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
