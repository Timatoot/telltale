package verify

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSynthesizeArgs(t *testing.T) {
	for _, tc := range []struct{ name, schema, want string }{
		{"no schema", "", "{}"},
		{"empty schema", "{}", "{}"},
		{"literal keyword names", `{"required":["$ref"],"properties":{"$ref":{"enum":[{"oneOf":"literal data"}]}}}`, `{"$ref":{"oneOf":"literal data"}}`},
		{"all optional", `{"properties":{"unused":{"type":"string"}}}`, "{}"},
		{"required only", `{"type":"object","properties":{"label":{"type":"string"},"amount":{"type":"number"},"count":{"type":"integer"},"active":{"type":"boolean"},"list":{"type":"array"},"omit":{"type":"string"}},"required":["label","amount","count","active","list"]}`, `{"active":false,"amount":0,"count":0,"label":"telltale","list":[]}`},
		{"path suffixes", `{"properties":{"inputPath":{"type":"string"},"file":{"type":"string"},"out_dir":{"type":"string"},"name":{"type":"string"},"filepath_hint":{"type":"string"}},"required":["inputPath","file","out_dir","name","filepath_hint"]}`, `{"file":"/workspace/seed/notes.txt","filepath_hint":"telltale","inputPath":"/workspace/seed/notes.txt","name":"/workspace/seed/notes.txt","out_dir":"/workspace/seed/notes.txt"}`},
		{"enum precedes default and preserves precision", `{"properties":{"file":{"type":"string","enum":["first","second"]},"n":{"enum":[9007199254740993,0]}},"required":["file","n"]}`, `{"file":"first","n":9007199254740993}`},
		{"three nested objects", nestedSchema(3), `{"child":{"child":{"child":{}}}}`},
		{"array at deepest object", strings.Replace(nestedSchema(3), `{"type":"object"}`, `{"required":["list"],"properties":{"list":{"type":"array","items":{"type":"string"}}}}`, 1), `{"child":{"child":{"child":{"list":[]}}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, err := SynthesizeArgs(json.RawMessage(tc.schema), "", "")
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(args)
			if err != nil || string(wire) != tc.want {
				t.Fatalf("arguments = %s, %v; want %s", wire, err, tc.want)
			}
		})
	}
}

func nestedSchema(depth int) string {
	return strings.Repeat(`{"type":"object","required":["child"],"properties":{"child":`, depth) +
		`{"type":"object"}` + strings.Repeat("}}", depth)
}

func TestSynthesizeArgsUnsupported(t *testing.T) {
	for name, raw := range map[string]string{
		"oneOf": `{"oneOf":[]}`, "anyOf": `{"properties":{"x":{"anyOf":[]}}}`,
		"allOf":                     `{"properties":{"x":{"type":"array","items":{"allOf":[]}}}}`,
		"unresolved reference":      `{"properties":{"x":{"$ref":"#/$defs/missing"}},"required":["x"]}`,
		"existing local reference":  `{"$defs":{"label":{"type":"string"}},"properties":{"x":{"$ref":"#/$defs/label"}},"required":["x"]}`,
		"reference below enum":      `{"properties":{"x":{"enum":[{}],"properties":{"child":{"$ref":"#"}}}}}`,
		"optional schema reference": `{"additionalProperties":{"$ref":"#"}}`,
		"array nesting cap":         `{"properties":{"x":` + strings.Repeat(`{"type":"array","items":`, maxSchemaDepth+1) + `{}` + strings.Repeat("}", maxSchemaDepth+1) + `}}`,
		"too deep":                  nestedSchema(4), "oversize": strings.Repeat(" ", maxSchemaBytes+1),
		"malformed": "{", "null": "null", "non-object root": `{"type":"string"}`,
		"missing required property": `{"required":["x"]}`,
		"unknown required type":     `{"properties":{"x":{}},"required":["x"]}`,
		"empty enum":                `{"properties":{"x":{"enum":[]}},"required":["x"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			args, err := SynthesizeArgs(json.RawMessage(raw), "", "")
			if args != nil || !errors.Is(err, ErrUnsupportedSchema) {
				t.Fatalf("arguments = %v, error = %v", args, err)
			}
		})
	}
}

func TestSynthesizeArgsFSPayload(t *testing.T) {
	const schema = `{
		"type":"object",
		"required":["inputPath","query","count","choice","nested"],
		"properties":{
			"inputPath":{"type":"string"},
			"query":{"type":"string"},
			"count":{"type":"integer"},
			"choice":{"type":"string","enum":["first","second"]},
			"optional":{"type":"string"},
			"nested":{
				"type":"object",
				"required":["inputPath","query"],
				"properties":{"inputPath":{"type":"string"},"query":{"type":"string"}}
			}
		}
	}`
	const payload = "../restricted/synthetic-canary-file"
	for _, tc := range []struct {
		name, parameter, payload, path, query string
	}{
		{"path-like parameter", "inputPath", payload, payload, "telltale"},
		{"ordinary string parameter", "query", payload, "/workspace/seed/notes.txt", payload},
		{"exact name required", "InputPath", payload, "/workspace/seed/notes.txt", "telltale"},
		{"optional parameter omitted", "optional", payload, "/workspace/seed/notes.txt", "telltale"},
		{"missing parameter omitted", "missing", payload, "/workspace/seed/notes.txt", "telltale"},
		{"numeric parameter retains type", "count", payload, "/workspace/seed/notes.txt", "telltale"},
		{"enum retains first item", "choice", payload, "/workspace/seed/notes.txt", "telltale"},
		{"object retains structure", "nested", payload, "/workspace/seed/notes.txt", "telltale"},
		{"empty payload preserved", "query", "", "/workspace/seed/notes.txt", ""},
		{"payload preserved verbatim", "inputPath", "./seed/../fixture with spaces.txt", "./seed/../fixture with spaces.txt", "telltale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(schema)
			args, err := SynthesizeArgs(raw, tc.parameter, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]any{
				"inputPath": tc.path, "query": tc.query, "count": 0, "choice": "first",
				"nested": map[string]any{"inputPath": "/workspace/seed/notes.txt", "query": "telltale"},
			}
			gotJSON, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("arguments = %s; want %s", gotJSON, wantJSON)
			}
			if string(raw) != schema {
				t.Fatal("synthesis mutated the input schema")
			}
		})
	}
}

func TestSynthesizeArgsFSPayloadRejectsUnsupportedSchema(t *testing.T) {
	for _, schema := range []string{
		`{"required":["path"],"properties":{"path":{"type":"string","$ref":"#"}}}`,
		`{"required":["path"],"properties":{"path":{"oneOf":[{"type":"string"}]}}}`,
		`{"required":["path"],"properties":{"path":{}}}`,
		`{"required":["path"],"properties":{}}`,
	} {
		args, err := SynthesizeArgs(json.RawMessage(schema), "path", "../restricted/synthetic-canary-file")
		if args != nil || !errors.Is(err, ErrUnsupportedSchema) {
			t.Fatalf("schema %s: arguments = %v, error = %v", schema, args, err)
		}
	}
}
