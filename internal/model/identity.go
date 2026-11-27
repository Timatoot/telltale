package model

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// Registration uses nil for an unresolved name. Path is a repo-relative POSIX path.
type Registration struct {
	Path       string
	Name       *string
	ByteOffset int
}

// ToolIDs returns IDs in the caller's input order. Numbering follows source
// order within each file, independently for each resolved name and for nil.
func ToolIDs(registrations []Registration) []string {
	indices := make([]int, len(registrations))
	for i := range indices {
		indices[i] = i
	}
	slices.SortStableFunc(indices, func(i, j int) int { return cmp.Compare(registrations[i].ByteOffset, registrations[j].ByteOffset) })
	type group struct {
		path, name string
		unresolved bool
	}
	counts := make(map[group]int)
	ids := make([]string, len(indices))
	for _, i := range indices {
		r := registrations[i]
		key := group{path: r.Path, unresolved: r.Name == nil}
		if r.Name != nil {
			key.name = *r.Name
		}
		counts[key]++
		ids[i] = ToolID(r.Path, r.Name, counts[key])
	}
	return ids
}

// ToolID formats a static registration with a one-based ordinal.
func ToolID(path string, name *string, ordinal int) string {
	prefix := "py:" + path + ":"
	if name == nil {
		return prefix + "?" + strconv.Itoa(ordinal)
	}
	if ordinal > 1 {
		return prefix + *name + "#" + strconv.Itoa(ordinal)
	}
	return prefix + *name
}

func LiveToolID(name string) string { return "live:" + name }

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Fingerprint accepts canonical identity components, independent of the source span.
func Fingerprint(ruleID, path, toolName, anchor string) string {
	return digest(strings.Join([]string{ruleID, path, toolName, anchor}, "\x00"))
}

func PoisonFingerprint(ruleID, path, toolName, field, matchedContent string) string {
	return Fingerprint(ruleID, path, toolName, field+"\x00"+matchedContent)
}

// LivePoisonFingerprint takes the field text after docstring normalization.
func LivePoisonFingerprint(ruleID, toolName, field, normalizedText string) string {
	return Fingerprint(ruleID, "<runtime>", toolName, "live:"+field+"\x00"+digest(normalizedText))
}

func ContractFingerprint(ruleID, path, toolName, key, category, callee string, ordinal int) string {
	return Fingerprint(ruleID, path, toolName, strings.Join([]string{key, category, callee, strconv.Itoa(ordinal)}, "\x00"))
}

func FSFingerprint(ruleID, path, toolName, param, callee string, ordinal int) string {
	return Fingerprint(ruleID, path, toolName, strings.Join([]string{param, callee, strconv.Itoa(ordinal)}, "\x00"))
}
