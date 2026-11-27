// Package python extracts static MCP tool metadata from an ingest snapshot.
package python

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	sitter "github.com/tree-sitter/go-tree-sitter"
	grammar "github.com/tree-sitter/tree-sitter-python/bindings/go"

	"github.com/Timatoot/telltale/internal/ingest"
	"github.com/Timatoot/telltale/internal/model"
)

const (
	maxDepth    = 512
	fileTimeout = 5 * time.Second
)

type Result struct {
	Tools                  []model.ToolFact
	ParseErrors            []model.ParseError
	UnresolvedDescriptions []model.UnresolvedDescription
}

// Extract reads only the bounded, private snapshot. A file that cannot be
// parsed contributes a coverage record and never publishes partial facts.
func Extract(ctx context.Context, snap *ingest.Snapshot) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	p := sitter.NewParser()
	defer p.Close()
	if err := p.SetLanguage(sitter.NewLanguage(grammar.Language())); err != nil {
		return Result{}, fmt.Errorf("initialize Python grammar: %w", err)
	}
	var result Result
	for _, path := range snap.Files {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		data, err := snap.Root().ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read snapshot %q: %w", path, err)
		}
		f := sourceFile{data: data, path: path}
		reason := f.parse(ctx, p)
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		if reason != "" {
			result.ParseErrors = append(result.ParseErrors, model.ParseError{
				Path: path, Engine: string(model.SourceTreeSitter), Reason: reason,
			})
			continue
		}
		result.Tools = append(result.Tools, f.tools...)
		result.UnresolvedDescriptions = append(result.UnresolvedDescriptions, f.gaps...)
	}
	return result, nil
}

type sourceFile struct {
	data     []byte
	path     string
	tools    []model.ToolFact
	gaps     []model.UnresolvedDescription
	ordinals map[string]int
	expanded int
}

func (f *sourceFile) parse(ctx context.Context, p *sitter.Parser) string {
	if !utf8.Valid(f.data) {
		return "invalid_utf8"
	}
	if bytes.IndexByte(f.data, 0) >= 0 {
		return "nul_byte"
	}
	ctx, cancel := context.WithTimeout(ctx, fileTimeout)
	defer cancel()
	// The native timeout also bounds error recovery between input reads.
	p.SetTimeoutMicros(uint64(fileTimeout / time.Microsecond))
	defer p.Reset()
	// The binding retains every input chunk until the parse returns.
	// Bound repeated reads as well as the original snapshot file.
	readBudget := 16 << 20
	tree := p.ParseWith(func(offset int, _ sitter.Point) []byte {
		if offset >= len(f.data) || ctx.Err() != nil {
			return nil
		}
		chunk := f.data[offset:min(offset+4096, len(f.data))]
		readBudget -= len(chunk)
		if readBudget < 0 {
			return nil
		}
		return chunk
	}, nil)
	if tree != nil {
		defer tree.Close()
	}
	if readBudget < 0 {
		return "resource_limit"
	}
	if tree == nil || ctx.Err() != nil {
		return "timeout"
	}
	root := tree.RootNode()
	if root.HasError() {
		return "syntax_error"
	}
	f.ordinals = make(map[string]int)
	cursor := root.Walk()
	defer cursor.Close()
	return f.walk(ctx, cursor, 0, &scope{names: make(map[string]string)})
}

// A group of imports can repeat a long module prefix, and stacked decorators
// can repeat a handler's entire signature and docstring in the inventory.
func (f *sourceFile) allowExpansion(size int) bool {
	f.expanded += size
	return f.expanded <= max(64<<10, 8*len(f.data))
}

// The cursor visits siblings in linear time and recursion stops at maxDepth.
func (f *sourceFile) walk(ctx context.Context, c *sitter.TreeCursor, depth int, env *scope) string {
	if depth > maxDepth {
		return "depth_exceeded"
	}
	if ctx.Err() != nil {
		return "timeout"
	}
	n := c.Node()
	switch n.Kind() {
	case "import_from_statement", "import_statement":
		if !f.bindImport(n, env) {
			return "resource_limit"
		}
	case "assignment":
		left := n.ChildByFieldName("left")
		if left.Kind() == "identifier" {
			var binding string
			right := n.ChildByFieldName("right")
			if right != nil && right.Kind() == "call" && isConstructor(env.resolve(f.text(right.ChildByFieldName("function")))) {
				binding = serverInstance
			}
			env.names[f.text(left)] = binding
		}
	case "decorated_definition":
		if !f.decorated(n, env) {
			return "resource_limit"
		}
	case "class_definition", "function_definition":
		env.names[f.text(n.ChildByFieldName("name"))] = ""
		env = &scope{parent: env, names: make(map[string]string)}
		if params := n.ChildByFieldName("parameters"); params != nil {
			for param := range children(params) {
				if name := parameterName(param); name != nil {
					env.names[f.text(name)] = ""
				}
			}
		}
	}
	if c.GotoFirstChild() {
		for {
			if reason := f.walk(ctx, c, depth+1, env); reason != "" {
				return reason
			}
			if !c.GotoNextSibling() {
				break
			}
		}
		c.GotoParent()
	}
	return ""
}

// Bind imported symbols to qualified names and invalidate a binding on
// reassignment. An unrelated object with a .tool method is not an MCP server.
type scope struct {
	names  map[string]string
	parent *scope
}

const serverInstance = "<MCP instance>"

func (s *scope) resolve(name string) string {
	first, rest, dotted := strings.Cut(name, ".")
	for ; s != nil; s = s.parent {
		if bound, ok := s.names[first]; ok {
			if dotted && bound != "" {
				return bound + "." + rest
			}
			return bound
		}
	}
	return ""
}

func isConstructor(name string) bool {
	last := name[strings.LastIndex(name, ".")+1:]
	return (last == "FastMCP" || last == "MCPServer") &&
		(strings.HasPrefix(name, "mcp.") || strings.HasPrefix(name, "fastmcp."))
}

func (f *sourceFile) bindImport(n *sitter.Node, env *scope) bool {
	module := n.ChildByFieldName("module_name")
	prefix := f.text(module)
	for child := range children(n) {
		if module != nil && child.StartByte() == module.StartByte() {
			continue
		}
		var name, alias string
		switch child.Kind() {
		case "aliased_import":
			name = f.text(child.ChildByFieldName("name"))
			alias = f.text(child.ChildByFieldName("alias"))
		case "dotted_name":
			name = f.text(child)
			alias, _, _ = strings.Cut(name, ".")
			if module == nil {
				name = alias
			}
		default:
			continue
		}
		if module != nil {
			if !f.allowExpansion(len(prefix)) {
				return false
			}
			name = prefix + "." + name
		}
		env.names[alias] = name
	}
	return true
}

func children(n *sitter.Node) iter.Seq[*sitter.Node] {
	return func(yield func(*sitter.Node) bool) {
		if n == nil {
			return
		}
		c := n.Walk()
		defer c.Close()
		for ok := c.GotoFirstChild(); ok; ok = c.GotoNextSibling() {
			child := c.Node()
			if child.IsNamed() && child.Kind() != "comment" && !yield(child) {
				return
			}
		}
	}
}

func firstChild(n *sitter.Node) *sitter.Node {
	for child := range children(n) {
		return child
	}
	return nil
}

func (f *sourceFile) text(n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(f.data)
}

func (f *sourceFile) keyword(args *sitter.Node, name string) *sitter.Node {
	for arg := range children(args) {
		if arg.Kind() == "keyword_argument" && f.text(arg.ChildByFieldName("name")) == name {
			return arg.ChildByFieldName("value")
		}
	}
	return nil
}

func (f *sourceFile) decorated(n *sitter.Node, env *scope) bool {
	fn := n.ChildByFieldName("definition")
	if fn.Kind() != "function_definition" {
		return true
	}
	for dec := range children(n) {
		if dec.Kind() != "decorator" {
			continue
		}
		call := firstChild(dec)
		if call.Kind() != "call" {
			continue
		}
		attr := call.ChildByFieldName("function")
		if attr.Kind() != "attribute" || f.text(attr.ChildByFieldName("attribute")) != "tool" ||
			env.resolve(f.text(attr.ChildByFieldName("object"))) != serverInstance {
			continue
		}
		if !f.allowExpansion(int(fn.EndByte() - fn.StartByte())) {
			return false
		}
		args := call.ChildByFieldName("arguments")
		name := f.text(fn.ChildByFieldName("name"))
		if explicit := f.keyword(args, "name"); explicit != nil {
			literal := f.literal(explicit)
			if literal == nil {
				continue // Computed-name registrations are handled in Slice 5.
			}
			name = *literal
		}
		f.ordinals[name]++
		tool := model.ToolFact{Name: name, ToolID: model.ToolID(f.path, &name, f.ordinals[name])}
		start, end := n.StartPosition(), fn.EndPosition()
		tool.SourceLocation = &model.Location{Path: f.path, StartLine: int(start.Row) + 1,
			StartColumn: int(start.Column) + 1, EndLine: int(end.Row) + 1, EndColumn: int(end.Column) + 1}
		desc := f.keyword(args, "description")
		if desc == nil {
			desc = keywordSplat(args) // Unpacked keywords can supply a description.
		}
		if desc == nil {
			desc = docstring(fn)
		}
		tool.DeclaredDescription, tool.DescriptionResolved = f.description(tool.ToolID, "description", desc)
		for param := range children(fn.ChildByFieldName("parameters")) {
			if name := parameterName(param); name != nil {
				tool.Parameters = append(tool.Parameters, f.parameter(tool.ToolID, f.text(name), param, env))
			}
		}
		tool.Annotations = f.readHints(tool.ToolID, args, env)
		f.tools = append(f.tools, tool)
	}
	return true
}

func docstring(fn *sitter.Node) *sitter.Node {
	statement := firstChild(fn.ChildByFieldName("body"))
	if statement == nil || statement.Kind() != "expression_statement" {
		return nil
	}
	expr := firstChild(statement)
	switch expr.Kind() {
	case "string", "concatenated_string", "parenthesized_expression":
		return expr
	default:
		return nil
	}
}

func (f *sourceFile) description(id, field string, expr *sitter.Node) (*string, bool) {
	if expr == nil {
		return nil, true // Known absence, distinct from an unevaluable expression.
	}
	s := f.literal(expr)
	if s == nil {
		f.gaps = append(f.gaps, model.UnresolvedDescription{ToolID: id, Field: field})
	}
	return s, s != nil
}

func parameterName(n *sitter.Node) *sitter.Node {
	if name := n.ChildByFieldName("name"); name != nil {
		return name
	}
	if n.Kind() == "typed_parameter" {
		n = firstChild(n)
	}
	if n.Kind() == "list_splat_pattern" || n.Kind() == "dictionary_splat_pattern" {
		n = firstChild(n)
	}
	if n.Kind() == "identifier" {
		return n
	}
	return nil // Positional-only and keyword-only separators have no name.
}

func (f *sourceFile) parameter(id, name string, n *sitter.Node, env *scope) model.Parameter {
	typ := n.ChildByFieldName("type")
	param := model.Parameter{Name: name, DeclaredType: f.text(typ), DescriptionResolved: true}
	generic := firstChild(typ)
	if generic == nil {
		return param
	}
	var items iter.Seq[*sitter.Node]
	var head *sitter.Node
	switch generic.Kind() {
	case "generic_type":
		head = generic.NamedChild(0)
		items = children(generic.NamedChild(1))
	case "subscript":
		head = generic.ChildByFieldName("value")
		items = children(generic)
	default:
		return param
	}
	symbol := env.resolve(f.text(head))
	if symbol != "typing.Annotated" && symbol != "typing_extensions.Annotated" {
		return param
	}
	first := true
	for item := range items {
		if item.StartByte() == head.StartByte() {
			continue
		}
		if first {
			param.DeclaredType = f.text(item)
			first = false
			continue
		}
		expr := item
		if expr.Kind() == "type" {
			expr = firstChild(expr)
		}
		if expr.Kind() == "call" {
			if env.resolve(f.text(expr.ChildByFieldName("function"))) != "pydantic.Field" {
				continue
			}
			expr = f.keyword(expr.ChildByFieldName("arguments"), "description")
			if expr == nil {
				continue
			}
		}
		param.Description, param.DescriptionResolved = f.description(id, "param:"+name+".description", expr)
		break
	}
	return param
}

// literal accepts one Unicode string. Dynamic expressions and unsupported
// escapes stay unresolved so downstream rules only see known text.
func (f *sourceFile) literal(n *sitter.Node) *string {
	for depth := 0; n != nil && n.Kind() == "parenthesized_expression"; depth++ {
		if depth >= maxDepth {
			return nil
		}
		n = firstChild(n)
	}
	if n == nil || n.Kind() != "string" {
		return nil
	}
	start := n.NamedChild(0)
	end := n.NamedChild(n.NamedChildCount() - 1)
	prefix := strings.TrimRight(strings.ToLower(f.text(start)), "'\"")
	body := strings.ReplaceAll(string(f.data[start.EndByte():end.StartByte()]), "\r\n", "\n")
	body = strings.ReplaceAll(body, "\r", "\n")
	switch prefix {
	case "r":
		return &body
	case "", "u":
		return decodeEscapes(body)
	default:
		return nil
	}
}

func decodeEscapes(s string) *string {
	var out strings.Builder
	for {
		before, rest, found := strings.Cut(s, "\\")
		out.WriteString(before)
		if !found {
			break
		}
		if rest == "" {
			return nil
		}
		ch := rest[0]
		s = rest[1:]
		switch ch {
		case '\n':
		case '\\', '\'', '"':
			out.WriteByte(ch)
		case 'a', 'b', 'f', 'n', 'r', 't', 'v':
			out.WriteByte("\a\b\f\n\r\t\v"[strings.IndexByte("abfnrtv", ch)])
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[ch]
			if len(s) < width {
				return nil
			}
			value, err := strconv.ParseUint(s[:width], 16, 32)
			if err != nil || value > utf8.MaxRune || !utf8.ValidRune(rune(value)) {
				return nil
			}
			out.WriteRune(rune(value))
			s = s[width:]
		case 'N':
			return nil // Unicode character names require a separate database.
		case '0', '1', '2', '3', '4', '5', '6', '7':
			length := 1
			for length < min(3, len(rest)) && rest[length] >= '0' && rest[length] <= '7' {
				length++
			}
			value, _ := strconv.ParseUint(rest[:length], 8, 16)
			out.WriteRune(rune(value))
			s = rest[length:]
		default:
			out.WriteByte('\\') // Python preserves unrecognized escapes.
			out.WriteByte(ch)
		}
	}
	value := out.String()
	return &value
}
