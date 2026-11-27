package python

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Timatoot/telltale/internal/model"
)

func toolIDs(tools []model.ToolFact) []string {
	var ids []string
	for _, t := range tools {
		ids = append(ids, t.ToolID)
	}
	return ids
}

func TestImperativeRegistrations(t *testing.T) {
	result := extract(t, map[string]string{
		"a.py": server + `from typing import Annotated as A
def clean(value: A[str, "Input text"]):
    """Strip whitespace."""
    return value.strip()
A = object()
app.add_tool(clean)
@app.tool(name="clean")
def other(): pass
app.add_tool(fn=clean, name="clean", description="Override.", readOnlyHint=True)
@app.tool(name=make_name())
def computed(): pass
for fn in functions:
    app.add_tool(fn)
app.add_tool(clean, name=label)
clean = None
app.add_tool(clean)
`,
		"b.py": server + "@app.tool()\ndef clean(): pass\n",
	})
	ids := []string{"py:a.py:clean", "py:a.py:clean#2", "py:a.py:clean#3", "py:a.py:?1", "py:a.py:?2", "py:a.py:?3", "py:a.py:?4", "py:b.py:clean"}
	if len(result.ParseErrors) != 0 || !slices.Equal(toolIDs(result.Tools), ids) {
		t.Fatalf("inventory = %+v", result)
	}
	first, third := result.Tools[0], result.Tools[2]
	if first.SourceLocation.StartLine != 4 || first.SourceLocation.EndLine != 6 ||
		first.DeclaredDescription == nil || *first.DeclaredDescription != "Strip whitespace." ||
		len(first.Parameters) != 1 || first.Parameters[0].Name != "value" || first.Parameters[0].Description == nil ||
		*first.Parameters[0].Description != "Input text" || first.Parameters[0].DeclaredType != "str" ||
		third.DeclaredDescription == nil || *third.DeclaredDescription != "Override." ||
		third.Annotations.ReadOnlyHint == nil || !*third.Annotations.ReadOnlyHint {
		t.Fatalf("handler metadata = %+v, %+v", first, third)
	}
	gaps := []model.UnresolvedRegistration{
		{Path: "a.py", Line: 12, Reason: "computed_name"},
		{Path: "a.py", Line: 15, Reason: "loop_registration"},
		{Path: "a.py", Line: 16, Reason: "computed_name"},
		{Path: "a.py", Line: 18, Reason: "unresolved_handler"},
	}
	if !slices.Equal(result.UnresolvedRegistrations, gaps) {
		t.Fatalf("gaps = %+v", result.UnresolvedRegistrations)
	}
}

const lowServerImports = "from mcp.server.lowlevel import Server as S\nfrom mcp.types import Tool as T\nsrv = S('local')\n"

func TestLowLevelListingAndDispatch(t *testing.T) {
	result := extract(t, map[string]string{
		"tools.py": lowServerImports + `import helper
@srv.call_tool()
async def dispatch(key: str, arguments):
    if key == "first":
        if arguments:
            return helper.run()
    elif "second" == key:
        return []
    return handlers[key](arguments)

@srv.list_tools()
async def inventory():
    T(name="unused")
    def nested():
        return [T(name="nested")]
    return [T(name="first", description="One", inputSchema={"properties": {
                "text": {"type": "string", "description": "Input"}}}),
            T(name="second", description=message), T(name="opaque"), T(name=key)]
`, "helper.py": "def run(): pass",
	})
	ids := []string{"py:tools.py:first", "py:tools.py:second", "py:tools.py:opaque", "py:tools.py:?1"}
	if !slices.Equal(toolIDs(result.Tools), ids) || len(result.ParseErrors) != 0 {
		t.Fatalf("%+v", result)
	}
	first := result.Tools[0]
	desc := "Input"
	params := []model.Parameter{{Name: "text", DeclaredType: "string", Description: &desc, DescriptionResolved: true}}
	if first.Name != "first" || first.DeclaredDescription == nil || *first.DeclaredDescription != "One" ||
		!reflect.DeepEqual(first.Parameters, params) || first.SourceLocation.StartLine != 8 || first.SourceLocation.EndLine != 9 ||
		result.Tools[1].SourceLocation.StartLine != 11 || result.Tools[2].SourceLocation.StartLine != 21 {
		t.Fatalf("low-level facts = %+v, locations = %v, %v, %v", result.Tools, first.SourceLocation, result.Tools[1].SourceLocation, result.Tools[2].SourceLocation)
	}
	for _, reason := range []string{"computed_name", "unresolved_dispatch"} {
		gap := model.UnresolvedRegistration{Path: "tools.py", Line: 21, Reason: reason}
		if !slices.Contains(result.UnresolvedRegistrations, gap) {
			t.Errorf("missing %v in %+v", gap, result.UnresolvedRegistrations)
		}
	}
	if len(result.UnresolvedRegistrations) != 2 ||
		!slices.Equal(result.UnresolvedDescriptions, []model.UnresolvedDescription{{ToolID: ids[1], Field: "description"}}) ||
		!slices.Equal(result.CrossFileHelperCalls, []model.HelperCall{{ToolID: ids[0], CalleeModule: "helper"}}) {
		t.Fatalf("unexpected coverage %+v", result)
	}
}

func TestOpaqueListingsAndIndependentServers(t *testing.T) {
	result := extract(t, map[string]string{"s.py": lowServerImports + `
other = S("other")
@srv.list_tools()
def known():
    return [T(name="listed")]
@other.call_tool()
def dispatch(name, args):
    if name == "listed": return []
@other.list_tools()
def dynamic():
    return build_listing()
`})
	want := []model.UnresolvedRegistration{
		{Path: "s.py", Line: 14, Reason: "dynamic_listing"},
		{Path: "s.py", Line: 8, Reason: "unresolved_dispatch"},
	}
	if !slices.Equal(toolIDs(result.Tools), []string{"py:s.py:listed", "py:s.py:?1"}) ||
		!slices.Equal(result.UnresolvedRegistrations, want) {
		t.Fatalf("%+v", result)
	}
}

func TestLocalHelperCalls(t *testing.T) {
	files := map[string]string{
		"pkg/tools.py": server + `from .helper_mod import run as direct
import helper_mod as sibling
from . import other
import third_party
def unregistered(): other.run()
@app.tool()
def decorated():
    direct()
    sibling.run()
    direct()
    def nested(): other.run()
    return third_party.run()
def imperative(direct):
    direct()
    other.work()
    sibling = None
    return sibling.run()
app.add_tool(imperative)
`,
		"pkg/helper_mod.py": "def run(): pass", "pkg/other.py": "def work(): pass",
		"pkg/unrelated.py": "pass",
	}
	result := extract(t, files)
	want := []model.HelperCall{
		{ToolID: "py:pkg/tools.py:decorated", CalleeModule: "pkg.helper_mod"},
		{ToolID: "py:pkg/tools.py:imperative", CalleeModule: "pkg.other"},
	}
	if len(result.Tools) != 2 || len(result.ParseErrors)+len(result.UnresolvedRegistrations)+len(result.UnresolvedDescriptions) != 0 ||
		!slices.Equal(result.CrossFileHelperCalls, want) {
		t.Fatalf("%+v", result)
	}
}

func TestUnrelatedRegistrationPatterns(t *testing.T) {
	result := extract(t, map[string]string{"negative.py": server + `
from unrelated import Server
other = Server()
@other.list_tools()
def inventory(): return []
@other.call_tool()
def dispatch(name, args): pass
def nested(app):
    app.add_tool(dispatch)
other.add_tool(inventory)
app = other
app.add_tool(dispatch)
`})
	if len(result.Tools)+len(result.UnresolvedRegistrations)+len(result.ParseErrors) != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestRepeatedImperativeRegistrationBudget(t *testing.T) {
	result := extract(t, map[string]string{"many.py": server + "def large():\n    \"" + strings.Repeat("x", 16<<10) + "\"\n" + strings.Repeat("app.add_tool(large)\n", 32)})
	if len(result.Tools)+len(result.CrossFileHelperCalls)+len(result.UnresolvedRegistrations) != 0 ||
		len(result.ParseErrors) != 1 || result.ParseErrors[0].Reason != "resource_limit" {
		t.Fatalf("partial file: %+v", result.ParseErrors)
	}
}

func TestLiteralMatchDispatch(t *testing.T) {
	result := extract(t, map[string]string{"server.py": lowServerImports + `
@srv.list_tools()
def listing():
    return [T(name="text"), T(name="guarded")]
@srv.call_tool()
def dispatch(key, arguments):
    match key:
        case "text": return []
        case "guarded" if arguments: return []
        case _: return registry[key](arguments)
`})
	if len(result.Tools) != 2 || result.Tools[0].SourceLocation.StartLine != 11 ||
		!slices.Equal(result.UnresolvedRegistrations, []model.UnresolvedRegistration{{Path: "server.py", Line: 7, Reason: "unresolved_dispatch"}}) {
		t.Fatalf("%+v", result)
	}
}

func TestLargeDynamicListingBudget(t *testing.T) {
	source := lowServerImports + "@srv.list_tools()\ndef list_all(): return [" + strings.Repeat("x,", 4000) + "]\n"
	result := extract(t, map[string]string{"many.py": source})
	if len(result.Tools)+len(result.UnresolvedRegistrations) != 0 || len(result.ParseErrors) != 1 || result.ParseErrors[0].Reason != "resource_limit" {
		t.Fatalf("large listing: tools=%d, gaps=%d, errors=%+v", len(result.Tools), len(result.UnresolvedRegistrations), result.ParseErrors)
	}
}

func TestImperativeNameArguments(t *testing.T) {
	result := extract(t, map[string]string{"app.py": server + `def handler(): pass
app.add_tool(handler, "alias")
app.add_tool(handler, label)
app.add_tool(handler, **options)
app.add_tool(handler, name=None)
`})
	if !slices.Equal(toolIDs(result.Tools), []string{"py:app.py:alias", "py:app.py:?1", "py:app.py:?2", "py:app.py:handler"}) ||
		len(result.UnresolvedRegistrations) != 2 {
		t.Fatalf("%+v", result)
	}
}

func TestHelperGlobalsResolvedAfterDefinition(t *testing.T) {
	result := extract(t, map[string]string{
		"server.py": server + `from previous import run as rebound
@app.tool()
def late():
    rebound()
    return imported()
from helper import run as imported
rebound = None
`, "helper.py": "def run(): pass", "previous.py": "def run(): pass",
	})
	want := []model.HelperCall{{ToolID: "py:server.py:late", CalleeModule: "helper"}}
	if !slices.Equal(result.CrossFileHelperCalls, want) || len(result.UnresolvedRegistrations)+len(result.ParseErrors) != 0 {
		t.Fatalf("%+v", result)
	}
}
