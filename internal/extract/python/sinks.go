package python

import (
	"context"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/Timatoot/telltale/internal/model"
	"github.com/Timatoot/telltale/internal/opengrep"
)

type indexedSink struct {
	match       opengrep.SinkMatch
	argumentKey string
}

func spanNode(root *sitter.Node, s model.Location) *sitter.Node {
	if s.StartLine < 1 || s.EndLine < s.StartLine || s.StartColumn < 1 || s.EndColumn < 1 {
		return nil
	}
	start := sitter.NewPoint(uint(s.StartLine-1), uint(s.StartColumn-1))
	end := sitter.NewPoint(uint(s.EndLine-1), uint(s.EndColumn-1))
	n := root.NamedDescendantForPointRange(start, end)
	if n == nil || n.StartPosition() != start || n.EndPosition() != end {
		return nil
	}
	return n
}

// Mutation/network rules select the call. The FS rule focuses on the path
// argument or receiver, which can itself be a call (e.g. Path(name).open()).
func (f *sourceFile) indexSinks(ctx context.Context, root *sitter.Node) string {
	if len(f.rawSinks) == 0 {
		return ""
	}
	f.callSinks = make(map[uintptr][]indexedSink)
	f.bodySinks = make(map[uintptr][]opengrep.SinkMatch)
	for _, m := range f.rawSinks {
		if ctx.Err() != nil {
			return "timeout"
		}
		node := spanNode(root, m.Span)
		if node == nil {
			f.sinkSpanGap = true
			continue
		}
		indexed := indexedSink{match: m}
		if m.RuleID == "fs-read" {
			// A dispatcher accepts one arguments dictionary. Recover a public
			// parameter only from literal keys on that taint source.
			if propagated := spanNode(root, m.PathValueSpan); propagated != nil {
				indexed.argumentKey = f.extractArgumentKey(propagated, m.TaintedParameter)
			}
			if indexed.argumentKey == "" {
				indexed.argumentKey = f.extractArgumentKey(node, m.TaintedParameter)
			}
			for depth := 0; node != nil; depth++ {
				if depth > maxDepth {
					return "depth_exceeded"
				}
				node = node.Parent()
				if node != nil && node.Kind() == "call" {
					break
				}
			}
		}
		if node == nil || node.Kind() != "call" {
			f.sinkSpanGap = true
			continue
		}
		f.callSinks[node.Id()] = append(f.callSinks[node.Id()], indexed)
	}
	return ""
}

func (f *sourceFile) extractArgumentKey(expr *sitter.Node, param string) string {
	if expr == nil || param == "" {
		return ""
	}
	keys := make(map[string]struct{})
	f.collectArgumentKeys(expr, param, 0, keys)
	if len(keys) != 1 {
		return ""
	}
	for k := range keys {
		return k
	}
	return ""
}

func (f *sourceFile) collectArgumentKeys(n *sitter.Node, param string, depth int, keys map[string]struct{}) {
	if n == nil || depth > maxDepth || len(keys) > 1 {
		return
	}
	switch n.Kind() {
	case "subscript":
		if f.text(n.ChildByFieldName("value")) == param {
			if key := f.literal(n.ChildByFieldName("subscript")); key != nil {
				keys[*key] = struct{}{}
			}
		}
	case "call":
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "attribute" &&
			f.text(fn.ChildByFieldName("object")) == param &&
			f.text(fn.ChildByFieldName("attribute")) == "get" {
			if first := firstChild(n.ChildByFieldName("arguments")); first != nil &&
				first.Kind() != "keyword_argument" && first.Kind() != "dictionary_splat" && first.Kind() != "list_splat" {
				if key := f.literal(first); key != nil {
					keys[*key] = struct{}{}
				}
			}
		}
	}
	for child := range children(n) {
		f.collectArgumentKeys(child, param, depth+1, keys)
	}
}

func (f *sourceFile) observeSinks(call *sitter.Node, env *scope, state walkState) bool {
	hits := f.callSinks[call.Id()]
	if state.body == 0 || len(hits) == 0 {
		return true
	}
	name := f.calleeName(call.ChildByFieldName("function"), env, 0)
	span := *f.location(call)
	for _, indexed := range hits {
		hit := indexed.match
		if hit.RuleID == "fs-read" && state.low.server != nil && !state.low.list {
			// The dispatch selector cannot carry a schema parameter.
			if hit.TaintedParameter == state.low.param {
				continue
			}
			hit.TaintedParameter = indexed.argumentKey
		}
		if !f.allowExpansion(len(name)) {
			return false
		}
		hit.NormalizedCallee, hit.CallSpan = name, span
		f.bodySinks[state.body] = append(f.bodySinks[state.body], hit)
	}
	return true
}

// Retain identifiers and attribute names, resolving imported aliases; omit
// receiver arguments, which can contain sensitive or unstable source text.
func (f *sourceFile) calleeName(n *sitter.Node, env *scope, depth int) string {
	if n == nil || depth > maxDepth {
		return ""
	}
	switch n.Kind() {
	case "identifier":
		name := f.text(n)
		if bound := env.lookup(name).qualified; bound != "" && bound != serverInstance {
			return bound
		}
		return name
	case "attribute":
		method := f.text(n.ChildByFieldName("attribute"))
		base := f.calleeName(n.ChildByFieldName("object"), env, depth+1)
		if base == "" {
			return method
		}
		return base + "." + method
	case "call":
		return f.calleeName(n.ChildByFieldName("function"), env, depth+1)
	case "parenthesized_expression":
		return f.calleeName(firstChild(n), env, depth+1)
	}
	return ""
}

func (f *sourceFile) joinSinks(ctx context.Context) bool {
	for _, h := range f.handlers {
		hits := f.bodySinks[h.body]
		if len(hits) == 0 {
			continue
		}
		t := f.tools[h.index]
		params := make(map[string]bool, len(t.Parameters))
		for _, p := range t.Parameters {
			params[p.Name] = true
		}
		for _, m := range hits {
			if ctx.Err() != nil || !f.allowExpansion(256+len(m.NormalizedCallee)+len(t.ToolID)) {
				return false
			}
			if m.RuleID == "fs-read" && (m.TaintedParameter == "" || !params[m.TaintedParameter]) {
				f.taintGap = true
				m.TaintedParameter = ""
			}
			m.ToolID, m.HandlerSpan = t.ToolID, *t.SourceLocation
			f.matches = append(f.matches, m)
		}
	}
	return true
}
