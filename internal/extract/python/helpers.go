package python

import (
	"context"
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Index module filenames from the snapshot manifest. Import resolution never
// consults Python, sys.path, the live checkout or installed packages.
func snapshotModules(files []string) map[string]string {
	modules := make(map[string]string, len(files))
	for _, file := range files {
		stem := strings.TrimSuffix(file, ".py")
		if strings.Contains(stem, ".") {
			continue
		}
		stem = strings.TrimSuffix(stem, "/__init__")
		modules[strings.ReplaceAll(stem, "/", ".")] = file
	}
	return modules
}

func (f *sourceFile) localModule(module string) string {
	dir := path.Dir(f.path)
	if dir == "." {
		dir = ""
	}
	tail := strings.TrimLeft(module, ".")
	if len(tail) == len(module) {
		if file, ok := f.modules[module]; ok {
			if file == f.path {
				return ""
			}
			return module
		}
	} else {
		// One leading dot refers to the containing directory.
		for up := len(module) - len(tail) - 1; up > 0; up-- {
			if dir == "" {
				return ""
			}
			dir = path.Dir(dir)
			if dir == "." {
				dir = ""
			}
		}
	}
	if dir != "" {
		tail = strings.ReplaceAll(dir, "/", ".") + "." + tail
	}
	if file, ok := f.modules[tail]; ok && file != f.path {
		return tail
	}
	return ""
}

type helperReference struct {
	body         uintptr
	root, suffix string
	scope        *scope
}

func (f *sourceFile) observeHelper(call *sitter.Node, env *scope, body uintptr) bool {
	if body == 0 {
		return true
	}
	callee := call.ChildByFieldName("function")
	if callee.Kind() != "identifier" && callee.Kind() != "attribute" {
		return true
	}
	if !f.allowExpansion(int(callee.EndByte() - callee.StartByte())) {
		return false
	}
	name := f.text(callee)
	root, _, _ := strings.Cut(name, ".")
	ref := helperReference{body: body, root: root, suffix: name[len(root):], scope: env}
	if bound, local := env.names[root]; local {
		return f.recordHelper(ref, bound.qualified)
	}
	// A handler looks up globals when called, even for imports below its
	// definition. Delay enclosing-scope lookup until the file has been read.
	f.helperRefs = append(f.helperRefs, ref)
	return true
}

func (f *sourceFile) resolveHelpers(ctx context.Context) bool {
	for _, ref := range f.helperRefs {
		if ctx.Err() != nil {
			return false
		}
		if _, local := ref.scope.names[ref.root]; local {
			continue
		}
		if !f.recordHelper(ref, ref.scope.parent.lookup(ref.root).qualified) {
			return false
		}
	}
	return true
}

func (f *sourceFile) recordHelper(ref helperReference, bound string) bool {
	if bound == "" || bound == serverInstance {
		return true
	}
	if !f.allowExpansion(len(bound)) {
		return false
	}
	qualified := bound + ref.suffix
	for dot := strings.LastIndexByte(qualified, '.'); dot > 0; dot = strings.LastIndexByte(qualified[:dot], '.') {
		if module := f.localModule(qualified[:dot]); module != "" {
			if f.bodyModules[ref.body] == nil {
				f.bodyModules[ref.body] = make(map[string]struct{})
			}
			f.bodyModules[ref.body][module] = struct{}{}
			return true
		}
	}
	return true
}
