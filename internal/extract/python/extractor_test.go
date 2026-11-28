package python

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
)

func snapshot(t *testing.T, files map[string]string) (*ingest.Snapshot, string) {
	t.Helper()
	repo := t.TempDir()
	for path, data := range files {
		dest := filepath.Join(repo, path)
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := ingest.CreateSnapshot(t.Context(), repo, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snap.Close(); err != nil {
			t.Error(err)
		}
	})
	return snap, repo
}

const server = "from mcp.server.fastmcp import FastMCP\napp = FastMCP('local')\n"

func extract(t *testing.T, files map[string]string) Result {
	t.Helper()
	snap, _ := snapshot(t, files)
	result, err := Extract(t.Context(), snap)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDecoratorsAndSourceLocations(t *testing.T) {
	for _, tc := range []struct{ importLine, constructor string }{
		{"from mcp.server.fastmcp import FastMCP", "FastMCP"},
		{"from mcp.server.fastmcp import FastMCP as FM", "FM"},
		{"from mcp.server import MCPServer", "MCPServer"},
		{"from mcp.server import MCPServer as Server", "Server"},
		{"import fastmcp as fm", "fm.FastMCP"},
	} {
		t.Run(tc.constructor, func(t *testing.T) {
			source := tc.importLine + "\napp = " + tc.constructor + `("local")
from typing import Annotated
from pydantic import Field

@app.tool(name="search")
async def lookup(query: Annotated[str, Field(description="Search terms")], /,
                 *, limit: Annotated[int, "Result count"] = 1):
    # A comment may precede the docstring.
    """Look up a café.
    Return matches."""
    return query
`
			result := extract(t, map[string]string{"pkg/tools.py": source})
			if len(result.Tools) != 1 || len(result.ParseErrors)+len(result.UnresolvedDescriptions) != 0 {
				t.Fatalf("%+v", result)
			}
			tool := result.Tools[0]
			loc := model.Location{Path: "pkg/tools.py", StartLine: 6, StartColumn: 1, EndLine: 12, EndColumn: 17}
			if tool.ToolID != "py:pkg/tools.py:search" || tool.Name != "search" ||
				tool.SourceLocation == nil || *tool.SourceLocation != loc ||
				!tool.DescriptionResolved || tool.DeclaredDescription == nil ||
				*tool.DeclaredDescription != "Look up a café.\n    Return matches." {
				t.Fatalf("tool = %+v, location = %+v", tool, tool.SourceLocation)
			}
			q, count := "Search terms", "Result count"
			params := []model.Parameter{
				{Name: "query", DeclaredType: "str", Description: &q, DescriptionResolved: true},
				{Name: "limit", DeclaredType: "int", Description: &count, DescriptionResolved: true},
			}
			if !reflect.DeepEqual(tool.Parameters, params) {
				t.Fatalf("parameters = %+v", tool.Parameters)
			}
		})
	}
}

func TestSnapshotOnlyAndLiteralOverride(t *testing.T) {
	src := server + `@app.tool(description="explicit\n\u200b\xE9")
def original():
    """fallback"""
`
	snap, repo := snapshot(t, map[string]string{"server.py": src})
	if err := os.WriteFile(filepath.Join(repo, "server.py"), []byte("raise Exception()"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Extract(t.Context(), snap)
	if err != nil || len(result.Tools) != 1 {
		t.Fatalf("extract = %+v, %v", result, err)
	}
	tool := result.Tools[0]
	if tool.Name != "original" || !tool.DescriptionResolved || tool.DeclaredDescription == nil || *tool.DeclaredDescription != "explicit\n\u200bé" {
		t.Fatalf("tool = %+v", tool)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Extract(ctx, snap); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled extraction = %v", err)
	}
}

func TestUnrelatedDecorators(t *testing.T) {
	result := extract(t, map[string]string{"negative.py": server + `
from unrelated import FastMCP as Other
other = Other()
@other.tool()
def foreign(): pass

def local(app):
    @app.tool()
    def shadowed(): pass

def factory():
    inner = FastMCP()
@inner.tool()
def outside(): pass

app = object()
@app.tool()
def rebound(): pass
`})
	if len(result.Tools)+len(result.ParseErrors) != 0 {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestDynamicDescriptions(t *testing.T) {
	for _, expr := range []string{`f"hello"`, `f"hello {who}"`, "MESSAGE", `"a" + "b"`, `"a" "b"`} {
		t.Run(expr, func(t *testing.T) {
			src := server + "from typing import Annotated\nfrom pydantic import Field\n" +
				"@app.tool(description=" + expr + ")\ndef find(term: Annotated[str, Field(description=" + expr + ")]):\n    \"fallback\"\n"
			result := extract(t, map[string]string{"a.py": src})
			if len(result.Tools) != 1 || len(result.Tools[0].Parameters) != 1 {
				t.Fatalf("%+v", result)
			}
			tool := result.Tools[0]
			param := tool.Parameters[0]
			gaps := []model.UnresolvedDescription{{ToolID: "py:a.py:find", Field: "description"}, {ToolID: "py:a.py:find", Field: "param:term.description"}}
			if tool.DeclaredDescription != nil || tool.DescriptionResolved || param.Description != nil ||
				param.DescriptionResolved || !reflect.DeepEqual(result.UnresolvedDescriptions, gaps) {
				t.Fatalf("tool = %+v, gaps = %+v", tool, result.UnresolvedDescriptions)
			}
		})
	}
}

func TestAnnotations(t *testing.T) {
	yes, no := true, false
	all := model.Annotations{ReadOnlyHint: &yes, DestructiveHint: &no, OpenWorldHint: &no}
	allKeys := []string{"readOnlyHint", "destructiveHint", "openWorldHint"}
	for _, tc := range []struct {
		name, args string
		want       model.Annotations
		unknown    []string
	}{
		{"missing", "", model.Annotations{}, nil},
		{"direct", "readOnlyHint=True, destructiveHint=False, openWorldHint=False", all, nil},
		{"constructor", "annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)", all, nil},
		{"annotations none", "annotations=None", model.Annotations{}, nil},
		{"hint none", "annotations=ToolAnnotations(readOnlyHint=None, destructiveHint=False)", model.Annotations{DestructiveHint: &no}, nil},
		{"variable", "annotations=hints", model.Annotations{}, allKeys},
		{"dict", "annotations={'readOnlyHint':True}", model.Annotations{}, allKeys},
		{"imported", "annotations=IMPORTED", model.Annotations{}, allKeys},
		{"splat", "description='Known', **options", model.Annotations{}, allKeys},
		{"constructor splat", "annotations=ToolAnnotations(**options)", model.Annotations{}, allKeys},
		{"mixed", "annotations=ToolAnnotations(readOnlyHint=IMPORTED, destructiveHint=False)", model.Annotations{DestructiveHint: &no}, []string{"readOnlyHint"}},
		{"nonboolean", "readOnlyHint=1", model.Annotations{}, []string{"readOnlyHint"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := server + "from mcp.types import ToolAnnotations\nfrom config import IMPORTED\n@app.tool(" + tc.args + ")\ndef tool(): pass\n"
			result := extract(t, map[string]string{"a.py": src})
			if len(result.Tools) != 1 || !reflect.DeepEqual(result.Tools[0].Annotations, tc.want) {
				t.Fatalf("%+v", result)
			}
			if len(result.UnresolvedDescriptions) != len(tc.unknown) {
				t.Fatalf("coverage = %+v", result.UnresolvedDescriptions)
			}
			for i, key := range tc.unknown {
				toolID := "py:a.py:tool"
				if tc.name == "splat" {
					toolID = "py:a.py:?1"
				}
				want := model.UnresolvedDescription{ToolID: toolID, Field: "annotation:" + key}
				if got := result.UnresolvedDescriptions[i]; got != want {
					t.Fatalf("coverage record = %+v, want %+v", got, want)
				}
			}
		})
	}
}

func TestUnpackedDescription(t *testing.T) {
	result := extract(t, map[string]string{"tools.py": server + `@app.tool(**options)
def search():
    """Default description."""
`})
	if len(result.Tools) != 1 || result.Tools[0].ToolID != "py:tools.py:?1" || result.Tools[0].Name != "" ||
		result.Tools[0].DeclaredDescription != nil || result.Tools[0].DescriptionResolved {
		t.Fatalf("unpacked description: %+v", result)
	}
	wantRegs := []model.UnresolvedRegistration{{Path: "tools.py", Line: 3, Reason: "computed_name"}}
	if !reflect.DeepEqual(result.UnresolvedRegistrations, wantRegs) {
		t.Fatalf("unpacked registration gaps = %+v, want %+v", result.UnresolvedRegistrations, wantRegs)
	}
	var want []model.UnresolvedDescription
	for _, field := range []string{"description", "annotation:readOnlyHint", "annotation:destructiveHint", "annotation:openWorldHint"} {
		want = append(want, model.UnresolvedDescription{ToolID: "py:tools.py:?1", Field: field})
	}
	if !reflect.DeepEqual(result.UnresolvedDescriptions, want) {
		t.Fatalf("unpacked keyword gaps = %+v, want %+v", result.UnresolvedDescriptions, want)
	}
}

func TestBareToolDecoratorAndParenthesizedStatements(t *testing.T) {
	result := extract(t, map[string]string{"bare.py": server + `
@app.tool
def bare(path: str):
    """Read a file."""
    return path

@app.tool()
def expr_first(x: int):
    (x + 1)
    return x

@app.tool()
def concat_paren():
    ("a" "b")
`})
	if len(result.ParseErrors) != 0 || len(result.UnresolvedRegistrations) != 0 || len(result.Tools) != 3 {
		t.Fatalf("unexpected extraction: %+v", result)
	}
	bare := result.Tools[0]
	if bare.ToolID != "py:bare.py:bare" || bare.Name != "bare" || !bare.DescriptionResolved ||
		bare.DeclaredDescription == nil || *bare.DeclaredDescription != "Read a file." ||
		len(bare.Parameters) != 1 || bare.Parameters[0].Name != "path" || bare.Parameters[0].DeclaredType != "str" {
		t.Fatalf("bare tool = %+v", bare)
	}
	expr := result.Tools[1]
	if expr.ToolID != "py:bare.py:expr_first" || !expr.DescriptionResolved || expr.DeclaredDescription != nil {
		t.Fatalf("expr_first = %+v", expr)
	}
	concat := result.Tools[2]
	if concat.ToolID != "py:bare.py:concat_paren" || concat.DescriptionResolved || concat.DeclaredDescription != nil {
		t.Fatalf("concat_paren = %+v", concat)
	}
	wantGaps := []model.UnresolvedDescription{{ToolID: "py:bare.py:concat_paren", Field: "description"}}
	if !reflect.DeepEqual(result.UnresolvedDescriptions, wantGaps) {
		t.Fatalf("gaps = %+v, want %+v", result.UnresolvedDescriptions, wantGaps)
	}
}

func TestHostileInputs(t *testing.T) {
	result := extract(t, map[string]string{
		"deep.py":    server + "@app.tool()\ndef early(): pass\nx = " + strings.Repeat("(", 10_000) + "1" + strings.Repeat(")", 10_000) + "\n",
		"invalid.py": "# \xff\n",
		"nul.py":     "# \x00\n",
		"syntax.py":  "def missing(:\n",
		"valid.py":   "\ufeff" + strings.ReplaceAll(server+"@app.tool()\ndef healthy(): pass\n", "\n", "\r\n"),
		"wide.py":    "#" + strings.Repeat("x", (1<<20)-1),
	})
	expected := []model.ParseError{
		{Path: "deep.py", Engine: "tree-sitter", Reason: "depth_exceeded"},
		{Path: "invalid.py", Engine: "tree-sitter", Reason: "invalid_utf8"},
		{Path: "nul.py", Engine: "tree-sitter", Reason: "nul_byte"},
		{Path: "syntax.py", Engine: "tree-sitter", Reason: "syntax_error"},
	}
	if !reflect.DeepEqual(result.ParseErrors, expected) || len(result.Tools) != 1 || result.Tools[0].ToolID != "py:valid.py:healthy" {
		t.Fatalf("%+v", result)
	}
	loc := result.Tools[0].SourceLocation
	if loc == nil || loc.StartLine != 3 || loc.StartColumn != 1 || loc.EndLine != 4 || loc.EndColumn != 20 {
		t.Fatalf("BOM/CRLF location = %+v", loc)
	}
}

func TestRepeatedDeclarationBudget(t *testing.T) {
	result := extract(t, map[string]string{
		"stacked.py": server + strings.Repeat("@app.tool()\n", 32) +
			"def hello():\n    \"" + strings.Repeat("x", 16<<10) + "\"\n",
		"imports.py": "from " + strings.Repeat("x", 16<<10) +
			" import a,b,c,d,e,f,g,h,i,j\n",
	})
	if len(result.Tools) != 0 || len(result.ParseErrors) != 2 {
		t.Fatalf("unexpected partial inventory or coverage: %+v", result)
	}
	for _, gap := range result.ParseErrors {
		if gap.Reason != "resource_limit" || gap.Engine != "tree-sitter" {
			t.Fatalf("unexpected gap: %+v", gap)
		}
	}
}
