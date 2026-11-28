// Package verify reconciles static observations with live MCP metadata.
package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ErrUnsupportedSchema maps to the unsupported_schema verification reason.
var ErrUnsupportedSchema = errors.New("unsupported_schema")

const (
	maxSchemaBytes = 2 << 20 // A schema must fit in one MCP frame.
	maxObjectDepth = 3       // The arguments object is depth zero.
	maxSchemaDepth = 32      // Also bounds nested array item schemas.
)

// SynthesizeArgs returns only required arguments. No schema or an empty
// object describes a tool that can be called with an empty arguments object.
// A nonempty taintedParameter selects a top-level string argument for the
// caller-supplied FS payload. Enums retain their first value. Pass empty strings
// for taintedParameter and payload when synthesizing a regular tool call.
func SynthesizeArgs(raw json.RawMessage, taintedParameter, payload string) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	if len(raw) > maxSchemaBytes || !json.Valid(raw) {
		return nil, ErrUnsupportedSchema
	}
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // Preserve exact numeric enum values.
	if err := dec.Decode(&root); err != nil || root == nil {
		return nil, ErrUnsupportedSchema
	}
	if err := checkSchema(root, 0, 0); err != nil {
		return nil, err
	}
	value, err := synthesize(root, "", true, taintedParameter, payload)
	if err != nil {
		return nil, err
	}
	args, ok := value.(map[string]any)
	if !ok {
		return nil, ErrUnsupportedSchema
	}
	return args, nil
}

// Check schema positions independently of which values will be supplied.
// Property names and literal data in enum, default, and examples are not keywords.
func checkSchema(raw any, objectDepth, schemaDepth int) error {
	if schemaDepth > maxSchemaDepth {
		return ErrUnsupportedSchema
	}
	if _, ok := raw.(bool); ok {
		return nil
	}
	schema, ok := raw.(map[string]any)
	if !ok {
		return ErrUnsupportedSchema
	}
	if objectDepth > maxObjectDepth && (schema["type"] == "object" || schema["properties"] != nil) {
		return ErrUnsupportedSchema
	}
	for key, value := range schema {
		switch key {
		case "oneOf", "anyOf", "allOf", "$ref":
			return ErrUnsupportedSchema
		case "properties", "patternProperties", "dependentSchemas", "$defs", "definitions":
			children, ok := value.(map[string]any)
			if !ok {
				return ErrUnsupportedSchema
			}
			childDepth := objectDepth
			if key == "properties" || key == "patternProperties" {
				childDepth++
			}
			for _, child := range children {
				if err := checkSchema(child, childDepth, schemaDepth+1); err != nil {
					return err
				}
			}
		case "prefixItems":
			children, ok := value.([]any)
			if !ok {
				return ErrUnsupportedSchema
			}
			for _, child := range children {
				if err := checkSchema(child, objectDepth, schemaDepth+1); err != nil {
					return err
				}
			}
		case "items", "contains", "not", "if", "then", "else", "propertyNames", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			if err := checkSchema(value, objectDepth, schemaDepth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func synthesize(raw any, name string, root bool, taintedParameter, payload string) (any, error) {
	schema, ok := raw.(map[string]any)
	if !ok {
		return nil, ErrUnsupportedSchema
	}
	if values, ok := schema["enum"]; ok {
		items, ok := values.([]any)
		if !ok || len(items) == 0 {
			return nil, ErrUnsupportedSchema
		}
		return items[0], nil
	}
	typ, hasType := schema["type"]
	if !hasType && (root || schema["properties"] != nil) {
		typ = "object"
	}
	switch typ {
	case "object":
		args := map[string]any{}
		rawNames, ok := schema["required"]
		if !ok {
			return args, nil
		}
		names, ok := rawNames.([]any)
		if !ok {
			return nil, ErrUnsupportedSchema
		}
		properties, _ := schema["properties"].(map[string]any)
		// The hypothesis identifies a tool argument, so stop propagating its
		// name once recursion enters a nested object.
		if !root {
			taintedParameter = ""
		}
		for _, rawName := range names {
			key, ok := rawName.(string)
			if !ok {
				return nil, ErrUnsupportedSchema
			}
			if _, duplicate := args[key]; duplicate {
				return nil, ErrUnsupportedSchema
			}
			v, err := synthesize(properties[key], key, false, taintedParameter, payload)
			if err != nil {
				return nil, err
			}
			args[key] = v
		}
		return args, nil
	case "string":
		if taintedParameter != "" && name == taintedParameter {
			return payload, nil
		}
		lower := strings.ToLower(name)
		for _, suffix := range []string{"path", "file", "dir", "name"} {
			if strings.HasSuffix(lower, suffix) {
				return "/workspace/seed/notes.txt", nil
			}
		}
		return "telltale", nil
	case "integer", "number":
		return 0, nil
	case "boolean":
		return false, nil
	case "array":
		return []any{}, nil
	default:
		return nil, ErrUnsupportedSchema
	}
}
