package python

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/Timatoot/telltale/internal/model"
)

var hintKeys = [...]string{"readOnlyHint", "destructiveHint", "openWorldHint"}

// A missing hint stays nil. An unevaluable hint also gets a coverage record.
func (f *sourceFile) readHints(toolID string, args *sitter.Node, env *scope) model.Annotations {
	var hints model.Annotations
	values := [...]**bool{&hints.ReadOnlyHint, &hints.DestructiveHint, &hints.OpenWorldHint}
	annotation := f.keyword(args, "annotations")
	var nested *sitter.Node
	if annotation != nil && annotation.Kind() == "call" {
		class := env.resolve(f.text(annotation.ChildByFieldName("function")))
		if strings.HasPrefix(class, "mcp.") && strings.HasSuffix(class, ".ToolAnnotations") {
			nested = annotation.ChildByFieldName("arguments")
		}
	}
	opaque := keywordSplat(args) != nil || keywordSplat(nested) != nil || (annotation != nil && annotation.Kind() != "none" && nested == nil)
	for i, key := range hintKeys {
		value := f.keyword(args, key)
		if value == nil {
			value = f.keyword(nested, key)
		}
		if !opaque {
			if value == nil || value.Kind() == "none" {
				continue
			}
			switch value.Kind() {
			case "true", "false":
				b := value.Kind() == "true"
				*values[i] = &b
				continue
			}
		}
		f.gaps = append(f.gaps, model.UnresolvedDescription{ToolID: toolID, Field: "annotation:" + key})
	}
	return hints
}

func keywordSplat(args *sitter.Node) *sitter.Node {
	for arg := range children(args) {
		if arg.Kind() == "dictionary_splat" {
			return arg
		}
	}
	return nil
}
