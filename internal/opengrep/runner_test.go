package opengrep

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
)

// Each scan must use the embedded rules, the private stage and exactly the
// same argument vector. Keep the fake on an isolated PATH.
func fake(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
set -eu
if [ "$1" = "--version" ]; then
    [ "$#" = 1 ]
    echo "${VERSION:-2.0.0}"
    exit 0
fi
[ "$#" = 11 ]
[ "$1" = scan ]
[ "$2" = --config ]
[ "$3" = "$PWD/rules" ]
[ -f "$3/fs_read.yaml" ]
[ ! -e "$3/fs_read.py" ]
[ "${PWD%/*}" = "$RUN_DIR" ]
[ "$4 $5 $6 $7 $8 $9 ${10}" = "--json --quiet --disable-nosem --max-target-bytes 1048576 --timeout 30" ]
target=${11}
` + body
	if err := os.WriteFile(filepath.Join(dir, "opengrep"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: private synthetic executable in t.TempDir().
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("VERSION", "2.0.0")
}

func analyzer(t *testing.T) SinkAnalyzer {
	t.Helper()
	a := SinkAnalyzer{RunDir: t.TempDir()}
	t.Setenv("RUN_DIR", a.RunDir)
	t.Cleanup(func() {
		entries, err := os.ReadDir(a.RunDir)
		if err != nil || len(entries) != 0 {
			t.Errorf("stage cleanup: %v, %v", entries, err)
		}
	})
	return a
}

func snapshot(t *testing.T, a SinkAnalyzer) *ingest.Snapshot {
	t.Helper()
	s, err := ingest.CreateSnapshot(t.Context(), "../../testdata/fixtures/opengrep", a.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func fatal(t *testing.T, err error) {
	t.Helper()
	var f *FatalError
	if !errors.As(err, &f) || f.ExitCode() != 2 {
		t.Fatalf("expected fatal exit 2, got %v", err)
	}
}

func TestPreflight(t *testing.T) {
	const cleanScan = `[ -f "$target/selftest_fixture.py" ]
printf '{"results":[],"errors":[],"paths":{"scanned":["%s/selftest_fixture.py"]}}' "$target"`
	for _, tc := range []struct {
		name, version, body string
		success             bool
	}{
		{"supported", "2.0.0+local", cleanScan, true},
		{"old", "1.9.0", cleanScan, false},
		{"new", "3.0.0", cleanScan, false},
		{"prerelease below minimum", "2.0.0-beta.1", cleanScan, false},
		{"invalid semver", "2.00.1", cleanScan, false},
		{"rejected flag", "2.0.0", "exit 2", false},
		{"fixture skipped", "2.0.0", `echo '{"results":[],"errors":[],"paths":{"scanned":[]}}'`, false},
		{"fixture diagnostic", "2.0.0", `echo '{"results":[],"errors":[{"type":"Timeout"}],"paths":{"scanned":["selftest_fixture.py"]}}'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := analyzer(t)
			fake(t, tc.body)
			t.Setenv("VERSION", tc.version)
			got, err := a.Preflight(t.Context())
			if !tc.success {
				fatal(t, err)
				return
			}
			if err != nil || got != tc.version {
				t.Fatalf("preflight = %q, %v", got, err)
			}
		})
	}
	t.Run("missing executable", func(t *testing.T) {
		a := analyzer(t)
		t.Setenv("PATH", t.TempDir())
		_, err := a.Preflight(t.Context())
		fatal(t, err)
	})
}

func TestAnalysisCoverage(t *testing.T) {
	for _, code := range []string{"0", "3"} {
		t.Run(code, func(t *testing.T) {
			a := analyzer(t)
			s := snapshot(t, a)
			t.Setenv("SNAPSHOT", s.Dir())
			fake(t, `[ "$target" = "$SNAPSHOT" ]
printf '{"results":[{"check_id":"rules.fs-read","path":"%s/read.py","start":{"line":2,"col":10},"end":{"line":2,"col":20}}],"paths":{"scanned":["read.py"]},"errors":[{"path":"%s/read.py","type":["PartialParsing",[]]},{"path":"read.py","type":"Timeout"}]}' "$target" "$target"
exit `+code)
			result, err := a.Analyze(t.Context(), s)
			if err != nil {
				t.Fatal(err)
			}
			want := Result{
				Matches:      []SinkMatch{{RuleID: "fs-read", Span: model.Location{Path: "read.py", StartLine: 2, StartColumn: 10, EndLine: 2, EndColumn: 20}}},
				ParseErrors:  []model.ParseError{{Path: "read.py", Engine: "opengrep", Reason: "PartialParsing"}, {Path: "read.py", Engine: "opengrep", Reason: "Timeout"}},
				FilesSkipped: []model.SkippedFile{{Path: "benign.py", Reason: model.EngineSkipped}},
			}
			if !reflect.DeepEqual(result, want) {
				t.Fatalf("got %+v, want %+v", result, want)
			}
		})
	}
}

func TestAnalysisFailures(t *testing.T) {
	for _, tc := range []struct{ name, body, reason string }{
		{"fatal exit", `echo '{}' ; exit 5`, "exit status 5"},
		{"stdout limit", `exec /usr/bin/head -c 67108865 /dev/zero`, "stdout exceeds"},
		{"invalid JSON", `echo '{'`, "decode scan output"},
		{"missing coverage", `echo '{"results":[],"errors":[]}'`, "paths.scanned"},
		{"foreign path", `echo '{"results":[],"errors":[],"paths":{"scanned":["../read.py"]}}'`, "manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := analyzer(t)
			s := snapshot(t, a)
			fake(t, tc.body)
			_, err := a.Analyze(t.Context(), s)
			fatal(t, err)
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatal(err)
			}
		})
	}
}

func TestDiagnosticTail(t *testing.T) {
	var tail diagnosticTail
	input := ""
	for _, n := range []int{1, 4095, 2, 5000, 7} {
		s := strings.Repeat(string(rune('a'+len(input)%24)), n)
		input += s
		_, _ = tail.Write([]byte(s))
		if tail.String() != input[max(0, len(input)-4096):] {
			t.Fatal("wrong stderr tail")
		}
	}
}

func TestParseTaintSource(t *testing.T) {
	a := analyzer(t)
	s := snapshot(t, a)
	fake(t, `echo '{"results":[{"check_id":"rules.fs-read","path":"read.py","start":{"line":14,"col":15},"end":{"line":14,"col":19},"extra":{"metavars":{"$PARAM":{"abstract_content":"source_name"},"$PATH":{"abstract_content":"alias"}}}}],"paths":{"scanned":["read.py","benign.py"]},"errors":[]}'`)
	result, err := a.Analyze(t.Context(), s)
	if err != nil || len(result.Matches) != 1 || result.Matches[0].TaintedParameter != "source_name" {
		t.Fatalf("taint binding: %+v, %v", result, err)
	}
}
