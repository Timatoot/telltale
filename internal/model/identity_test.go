package model

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
)

func TestToolIDs(t *testing.T) {
	name := "lookup"
	registrations := []Registration{
		{"pkg/a.py", &name, 300}, {"b.py", nil, 500},
		{"pkg/a.py", nil, 70}, {"pkg/a.py", &name, 20},
		{"b.py", &name, 100}, {"pkg/a.py", nil, 40},
		{"pkg/a.py", &name, 80},
	}
	want := []string{"py:pkg/a.py:lookup#3", "py:b.py:?1", "py:pkg/a.py:?2",
		"py:pkg/a.py:lookup", "py:b.py:lookup", "py:pkg/a.py:?1", "py:pkg/a.py:lookup#2"}
	if got := ToolIDs(registrations); !slices.Equal(got, want) {
		t.Fatalf("IDs %q, want %q", got, want)
	}
	if got := LiveToolID(name); got != "live:lookup" {
		t.Fatal(got)
	}
}

func TestFingerprintWireFormat(t *testing.T) {
	hash := func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
	for _, tc := range []struct{ got, preimage string }{
		{Fingerprint("rule", "pkg/x.py", "tool", "anchor"), "rule\x00pkg/x.py\x00tool\x00anchor"},
		{PoisonFingerprint("P", "pkg/x.py", "tool", "description", "U+202E"), "P\x00pkg/x.py\x00tool\x00description\x00U+202E"},
		{LivePoisonFingerprint("P", "tool", "name", "text"), "P\x00<runtime>\x00tool\x00live:name\x00" + hash("text")},
		{ContractFingerprint("C", "x.py", "tool", "readOnlyHint", "write", "Path.touch", 1), "C\x00x.py\x00tool\x00readOnlyHint\x00write\x00Path.touch\x001"},
		{FSFingerprint("F", "x.py", "tool", "file", "open", 2), "F\x00x.py\x00tool\x00file\x00open\x002"},
	} {
		if tc.got != hash(tc.preimage) {
			t.Errorf("fingerprint %q, want hash of %q", tc.got, tc.preimage)
		}
	}
}

func TestFingerprintUsesContentAndNotCoordinates(t *testing.T) {
	before := Location{"p.py", 1, 2, 3, 4}
	after := Location{"p.py", 10, 20, 30, 40}
	anchors := func(loc Location) []string {
		return []string{
			PoisonFingerprint("P", loc.Path, "tool", "description", "phrase"),
			PoisonFingerprint("P", loc.Path, "tool", "name", "phrase"),
			PoisonFingerprint("P", loc.Path, "tool", "name", "changed"),
			LivePoisonFingerprint("P", "tool", "name", "phrase"),
			LivePoisonFingerprint("P", "tool", "name", "changed"),
			ContractFingerprint("C", loc.Path, "tool", "hint", "write", "callee", 1),
			ContractFingerprint("C", loc.Path, "tool", "hint", "write", "different", 1),
			ContractFingerprint("C", loc.Path, "tool", "hint", "write", "callee", 2),
			FSFingerprint("F", loc.Path, "tool", "path", "callee", 1),
			FSFingerprint("F", loc.Path, "tool", "path", "callee", 2),
			FSFingerprint("F", loc.Path, "tool", "other", "callee", 1),
		}
	}
	got := anchors(before)
	if !slices.Equal(got, anchors(after)) {
		t.Fatal("line shift changed identity")
	}
	slices.Sort(got)
	if len(slices.Compact(got)) != len(got) {
		t.Fatal("distinct anchors collided")
	}
}
