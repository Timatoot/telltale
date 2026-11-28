//go:build staticacceptance

package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Exact OASIS Errata 01 bytes (the file declares JSON Schema Draft 4).
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
func TestSARIFSchema(t *testing.T) {
	const schema = "testdata/sarif-2.1.0.schema.json"
	const digest = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
	raw, err := os.ReadFile(schema)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != digest {
		t.Fatalf("official schema digest changed: %s", got)
	}
	r, snapshot := reporterFixture()
	data, err := RenderSARIF(&r, testCanary, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	checkSARIFRegion(t, data)
	file := filepath.Join(t.TempDir(), "report.sarif")
	validate := func(data []byte) ([]byte, error) {
		t.Helper()
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		// All schema references are local fragments; the validator selects the
		// dialect from $schema and supplies its own metaschemas.
		cmd := exec.CommandContext(ctx, "check-jsonschema", "--schemafile", schema, file) //nolint:gosec // Fixed validator and private test artifact, explicit argv.
		return cmd.CombinedOutput()
	}
	if out, err := validate(data); err != nil {
		t.Fatalf("SARIF validation failed: %v\n%s", err, out)
	}
	invalid := bytes.Replace(data, []byte(`"level": "error"`), []byte(`"level": "invalid-level"`), 1)
	out, err := validate(invalid)
	var failure *exec.ExitError
	if !errors.As(err, &failure) || failure.ExitCode() != 1 || !bytes.Contains(out, []byte("invalid-level")) {
		t.Fatalf("validator did not diagnose invalid result level: %v\n%s", err, out)
	}
}
