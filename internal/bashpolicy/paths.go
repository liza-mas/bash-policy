package bashpolicy

import (
	"path/filepath"
	"strings"
)

func (ev evaluator) safeDir(path string, cwd string) (string, bool) {
	abs := absFrom(path, cwd)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	resolved = filepath.Clean(resolved)
	if !ev.insideAnyRoot(resolved) {
		return "", false
	}
	return resolved, true
}

func (ev evaluator) safePath(path string, cwd string) bool {
	if unsafePathPattern(path) || LooksSensitive(path) {
		return false
	}
	abs := absFrom(path, cwd)
	resolved := resolveExistingOrClean(abs)
	return ev.insideAnyRoot(resolved)
}

func (ev evaluator) safeExistingPath(path string, cwd string) bool {
	if unsafePathPattern(path) || LooksSensitive(path) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(absFrom(path, cwd))
	if err != nil {
		return false
	}
	return ev.insideAnyRoot(filepath.Clean(resolved))
}

func (ev evaluator) insideAnyRoot(path string) bool {
	if len(ev.roots) == 0 {
		return false
	}
	for _, root := range ev.roots {
		if pathInsideRoot(path, root) {
			return true
		}
	}
	return false
}

func canonicalRoot(path string) string {
	abs := absFrom(path, "")
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(abs)
}

func absFrom(path string, cwd string) string {
	if strings.HasPrefix(path, "~") {
		return path
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	if cwd == "" {
		cwd = "."
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

func resolveExistingOrClean(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	parent := filepath.Dir(path)
	if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Clean(filepath.Join(resolvedParent, filepath.Base(path)))
	}
	return filepath.Clean(path)
}

func pathInsideRoot(path string, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func unsafePathPattern(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func gitObjectPathOperand(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") {
		return "", false
	}
	_, path, ok := strings.Cut(value, ":")
	if !ok || path == "" {
		return "", false
	}
	return path, true
}

func gitObjectPathPathSensitive(path string) bool {
	return LooksSensitive(path)
}

func gitObjectPathPathSafe(path string) bool {
	if gitObjectPathPathSensitive(path) || unsafePathPattern(path) {
		return false
	}
	normalized := strings.ReplaceAll(path, "\\", "/")
	if normalized == "" ||
		normalized == "." ||
		normalized == ".." ||
		strings.HasPrefix(normalized, "/") ||
		strings.HasPrefix(normalized, "~") ||
		strings.HasPrefix(normalized, "./") ||
		strings.HasPrefix(normalized, "../") ||
		strings.Contains(normalized, "/../") ||
		strings.HasSuffix(normalized, "/..") {
		return false
	}
	return true
}

func argLooksPathLike(arg string) bool {
	if arg == "" || strings.Contains(arg, "://") {
		return false
	}
	return strings.HasPrefix(arg, "/") ||
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "~") ||
		strings.ContainsAny(arg, `/\`)
}
