package python

import (
	"context"
	"maps"
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/Timatoot/telltale/internal/model"
)

// These associations live only while the file's tree is open. The inventory
// is emitted in registration order, independently of the handlers' locations.
type walkState struct {
	loop bool
	body uintptr
	low  lowHandler
}

type lowServer struct {
	branches    map[string]*sitter.Node
	dispatchers int
}

type lowHandler struct {
	server *lowServer
	list   bool
	param  string
	body   uintptr
	loop   bool
}

type listedTool struct {
	index       int
	server      *lowServer
	declaration *sitter.Node
}

type handlerUse struct {
	index int
	body  uintptr
}

type functionDef struct {
	node   *sitter.Node
	params []model.Parameter
}

// Resolve annotation imports where the signature is defined. A later add_tool
// call can be in another scope or follow a reassignment of the import.
func (f *sourceFile) function(fn *sitter.Node, env *scope) *functionDef {
	def := &functionDef{node: fn}
	for param := range children(fn.ChildByFieldName("parameters")) {
		if ident := parameterName(param); ident != nil {
			def.params = append(def.params, f.parameter(f.text(ident), param, env))
		}
	}
	return def
}

func (f *sourceFile) decorator(dec *sitter.Node, env *scope, loop bool) bool {
	def := dec.Parent()
	fn := def.ChildByFieldName("definition")
	expr := firstChild(dec)
	if fn == nil || fn.Kind() != "function_definition" || expr == nil {
		return true
	}
	if expr.Kind() == "attribute" {
		receiver := env.lookup(f.text(expr.ChildByFieldName("object")))
		method := f.text(expr.ChildByFieldName("attribute"))
		if method == "tool" && receiver.qualified == serverInstance {
			return f.registerFunction(dec, def, f.function(fn, env), nil, env, loop)
		}
		return true
	}
	if expr.Kind() != "call" {
		return true
	}
	attr := expr.ChildByFieldName("function")
	if attr.Kind() != "attribute" {
		return true
	}
	receiver := env.lookup(f.text(attr.ChildByFieldName("object")))
	method := f.text(attr.ChildByFieldName("attribute"))
	if method == "tool" && receiver.qualified == serverInstance {
		return f.registerFunction(dec, def, f.function(fn, env), expr.ChildByFieldName("arguments"), env, loop)
	}
	if receiver.low == nil {
		return true
	}
	h := lowHandler{server: receiver.low, body: fn.ChildByFieldName("body").Id(), loop: loop}
	switch method {
	case "list_tools":
		h.list = true
	case "call_tool":
		h.server.dispatchers++
		if param := firstChild(fn.ChildByFieldName("parameters")); param != nil {
			h.param = f.text(parameterName(param))
		}
	default:
		return true
	}
	f.lowHandlers[fn.Id()] = h
	return true
}

func (f *sourceFile) addTool(call *sitter.Node, env *scope, loop bool) bool {
	attr := call.ChildByFieldName("function")
	if attr.Kind() != "attribute" || f.text(attr.ChildByFieldName("attribute")) != "add_tool" ||
		env.lookup(f.text(attr.ChildByFieldName("object"))).qualified != serverInstance {
		return true
	}
	args := call.ChildByFieldName("arguments")
	ref := f.keyword(args, "fn")
	if ref == nil {
		ref = firstChild(args)
	}
	var fn *functionDef
	if ref != nil && ref.Kind() == "identifier" {
		fn = env.lookup(f.text(ref)).fn
	}
	span := call
	if fn != nil {
		span = fn.node
	}
	return f.registerFunction(call, span, fn, args, env, loop)
}

func (f *sourceFile) registrationName(site, args *sitter.Node) *sitter.Node {
	if name := f.keyword(args, "name"); name != nil {
		return name
	}
	if site.Kind() == "decorator" {
		return keywordSplat(args)
	}
	// add_tool takes the callable first. A second positional argument or an
	// unpacked argument can supply the public name.
	if site.Kind() == "call" {
		haveHandler := false
		for arg := range children(args) {
			switch arg.Kind() {
			case "keyword_argument":
				continue
			case "dictionary_splat", "list_splat":
				return arg
			}
			if haveHandler {
				return arg
			}
			haveHandler = true
		}
	}
	return nil
}

// Even a single unknown expression in a returned list creates an inventory
// entry, location, ID and coverage record. Charge their fixed cost as well
// as repeated path bytes against the existing per-file expansion limit.
func (f *sourceFile) allowRegistration() bool {
	const recordBytes = 256
	return f.allowExpansion(recordBytes + len(f.path))
}

func (f *sourceFile) registerFunction(site, span *sitter.Node, fn *functionDef, args *sitter.Node, env *scope, loop bool) bool {
	var name *string
	reason := ""
	if !f.allowRegistration() {
		return false
	}
	if fn != nil {
		if !f.allowExpansion(int(fn.node.EndByte() - fn.node.StartByte())) {
			return false
		}
		defaultName := f.text(fn.node.ChildByFieldName("name"))
		name = &defaultName
	} else {
		reason = "unresolved_handler"
	}
	if explicit := f.registrationName(site, args); explicit != nil && explicit.Kind() != "none" {
		name = f.literal(explicit)
		if name == nil {
			reason = "computed_name"
		}
	}
	if loop {
		name, reason = nil, "loop_registration"
	}
	tool := f.newTool(name, site, span, reason)
	desc := f.keyword(args, "description")
	if desc == nil {
		desc = keywordSplat(args)
	}
	if desc == nil && fn != nil {
		desc = docstring(fn.node)
	}
	if desc != nil || fn != nil {
		tool.DeclaredDescription, tool.DescriptionResolved = f.description(tool.ToolID, "description", desc)
	}
	if fn != nil {
		tool.Parameters = slices.Clone(fn.params)
		for _, p := range tool.Parameters {
			if !p.DescriptionResolved {
				f.gaps = append(f.gaps, model.UnresolvedDescription{ToolID: tool.ToolID, Field: "param:" + p.Name + ".description"})
			}
		}
		f.handlers = append(f.handlers, handlerUse{len(f.tools), fn.node.ChildByFieldName("body").Id()})
	}
	tool.Annotations = f.readHints(tool.ToolID, args, env)
	f.tools = append(f.tools, tool)
	return true
}

func (f *sourceFile) newTool(name *string, site, span *sitter.Node, reason string) model.ToolFact {
	var tool model.ToolFact
	if name == nil {
		f.unknown++
		tool.ToolID = model.ToolID(f.path, nil, f.unknown)
	} else {
		f.ordinals[*name]++
		tool.Name = *name
		tool.ToolID = model.ToolID(f.path, name, f.ordinals[*name])
	}
	if reason != "" {
		f.registrationGap(site, reason)
	}
	tool.SourceLocation = f.location(span)
	return tool
}

func (f *sourceFile) registrationGap(n *sitter.Node, reason string) {
	f.registrations = append(f.registrations, model.UnresolvedRegistration{
		Path: f.path, Line: int(n.StartPosition().Row) + 1, Reason: reason,
	})
}

func (f *sourceFile) location(n *sitter.Node) *model.Location {
	start, end := n.StartPosition(), n.EndPosition()
	return &model.Location{Path: f.path, StartLine: int(start.Row) + 1, StartColumn: int(start.Column) + 1,
		EndLine: int(end.Row) + 1, EndColumn: int(end.Column) + 1}
}

// Only returned descriptors advertise tools. Calls elsewhere in the listing
// function (logging, temporaries, nested functions) do not declare entries.
func (f *sourceFile) listReturn(n *sitter.Node, env *scope, state walkState) bool {
	seq := firstChild(n)
	if seq == nil || (seq.Kind() != "list" && seq.Kind() != "tuple") {
		if !f.allowRegistration() {
			return false
		}
		f.tools = append(f.tools, f.newTool(nil, n, n, "dynamic_listing"))
		return true
	}
	for entry := range children(seq) {
		if !f.allowRegistration() {
			return false
		}
		if entry.Kind() != "call" || env.resolve(f.text(entry.ChildByFieldName("function"))) != "mcp.types.Tool" {
			f.tools = append(f.tools, f.newTool(nil, entry, entry, "dynamic_listing"))
			continue
		}
		args := entry.ChildByFieldName("arguments")
		name := f.literal(f.keyword(args, "name"))
		reason := ""
		if name == nil {
			reason = "computed_name"
		}
		if state.loop {
			name, reason = nil, "loop_registration"
		}
		tool := f.newTool(name, entry, entry, reason)
		desc := f.keyword(args, "description")
		if desc == nil {
			desc = keywordSplat(args)
		}
		tool.DeclaredDescription, tool.DescriptionResolved = f.description(tool.ToolID, "description", desc)
		tool.Annotations = f.readHints(tool.ToolID, args, env)
		tool.Parameters = f.schemaParameters(tool.ToolID, f.keyword(args, "inputSchema"))
		if name != nil {
			f.listings = append(f.listings, listedTool{len(f.tools), state.low.server, entry})
		}
		f.tools = append(f.tools, tool)
	}
	return true
}

func (f *sourceFile) dictValue(dict *sitter.Node, key string) *sitter.Node {
	if dict == nil || dict.Kind() != "dictionary" {
		return nil
	}
	for pair := range children(dict) {
		if pair.Kind() == "pair" {
			if k := f.literal(pair.ChildByFieldName("key")); k != nil && *k == key {
				return pair.ChildByFieldName("value")
			}
		}
	}
	return nil
}

func (f *sourceFile) schemaParameters(id string, schema *sitter.Node) []model.Parameter {
	properties := f.dictValue(schema, "properties")
	if properties == nil || properties.Kind() != "dictionary" {
		return nil
	}
	var params []model.Parameter
	for pair := range children(properties) {
		if pair.Kind() != "pair" {
			continue
		}
		name := f.literal(pair.ChildByFieldName("key"))
		if name == nil {
			continue
		}
		spec := pair.ChildByFieldName("value")
		p := model.Parameter{Name: *name}
		if typ := f.literal(f.dictValue(spec, "type")); typ != nil {
			p.DeclaredType = *typ
		}
		if spec.Kind() == "dictionary" {
			p.Description, p.DescriptionResolved = f.description(id, "param:"+*name+".description", f.dictValue(spec, "description"))
		} else {
			f.gaps = append(f.gaps, model.UnresolvedDescription{ToolID: id, Field: "param:" + *name + ".description"})
		}
		params = append(params, p)
	}
	return params
}

func (f *sourceFile) enterBlock(body *sitter.Node, state walkState, env *scope) walkState {
	parent := body.Parent()
	if parent.Kind() == "function_definition" {
		h := f.lowHandlers[parent.Id()]
		return walkState{body: body.Id(), low: h, loop: h.loop}
	}
	h := state.low
	if h.server == nil || h.list {
		return state
	}
	consequence := parent.ChildByFieldName("consequence")
	if consequence == nil || consequence.Id() != body.Id() {
		return state
	}
	if name := f.dispatchName(parent, h, env); name != nil {
		h.server.recordBranch(*name, body)
		state.body = body.Id()
	}
	return state
}

// Attribute only direct literal branches on the dispatch argument. Guarded
// patterns and opaque lookups retain the listing and an unresolved_dispatch gap.
func (f *sourceFile) dispatchName(clause *sitter.Node, h lowHandler, env *scope) *string {
	var arg, value *sitter.Node
	parent := clause.Parent()
	switch clause.Kind() {
	case "if_statement", "elif_clause":
		if clause.Kind() == "elif_clause" {
			parent = parent.Parent()
		}
		cond := clause.ChildByFieldName("condition")
		if cond.Kind() != "comparison_operator" || cond.ChildCount() != 3 || cond.Child(1).Kind() != "==" {
			return nil
		}
		arg, value = cond.Child(0), cond.Child(2)
		if arg.Kind() == "string" {
			arg, value = value, arg
		}
	case "case_clause":
		match := parent.Parent()
		// Exact arity also excludes guards, tuple subjects and sequence patterns.
		if match.Kind() != "match_statement" || match.ChildCount() != 4 || clause.ChildCount() != 4 {
			return nil
		}
		parent = match.Parent()
		arg, value = match.ChildByFieldName("subject"), firstChild(firstChild(clause))
	default:
		return nil
	}
	if parent.Id() != h.body || arg.Kind() != "identifier" || env.lookup(f.text(arg)).dispatch != h.server {
		return nil
	}
	return f.literal(value)
}

func (s *lowServer) recordBranch(name string, body *sitter.Node) {
	if _, duplicate := s.branches[name]; duplicate {
		s.branches[name] = nil
	} else {
		s.branches[name] = body
	}
}

func (f *sourceFile) finishHandlers(ctx context.Context) bool {
	for _, listing := range f.listings {
		if ctx.Err() != nil {
			return false
		}
		tool := &f.tools[listing.index]
		branch := listing.server.branches[tool.Name]
		if branch == nil || listing.server.dispatchers != 1 {
			f.registrationGap(listing.declaration, "unresolved_dispatch")
			continue
		}
		tool.SourceLocation = f.location(branch)
		f.handlers = append(f.handlers, handlerUse{listing.index, branch.Id()})
	}
	for _, h := range f.handlers {
		if ctx.Err() != nil {
			return false
		}
		for _, module := range slices.Sorted(maps.Keys(f.bodyModules[h.body])) {
			id := f.tools[h.index].ToolID
			if !f.allowExpansion(len(id) + len(module)) {
				return false
			}
			f.helperCalls = append(f.helperCalls, model.HelperCall{ToolID: id, CalleeModule: module})
		}
	}
	return true
}
