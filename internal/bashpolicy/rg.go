package bashpolicy

import (
	"path/filepath"
	"strings"
)

func (ev evaluator) evalRGSafetyFloor(args []string, cwd string, original []string) Result {
	if cwd == "" && len(ev.roots) > 0 {
		cwd = ev.roots[0]
	}
	if cwd == "" || !ev.insideAnyRoot(filepath.Clean(cwd)) {
		return result(DecisionManual, "rg requires a safe root", original)
	}
	filesMode := false
	patternSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if rgFlagIsForbidden(arg) {
			return result(DecisionManual, "rg flag can execute helpers or read broad inputs", original)
		}
		if arg == "--" {
			for _, pathArg := range args[i+1:] {
				if !ev.safePath(pathArg, cwd) {
					return result(DecisionManual, "rg path is outside the safe roots or uses unsafe patterns", original)
				}
			}
			return Result{}
		}
		if arg == "--files" {
			filesMode = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if rgFlagNeedsValue(arg) {
				i++
				if i >= len(args) || LooksSensitive(args[i]) {
					return result(DecisionManual, "rg flag value is not safe", original)
				}
			}
			continue
		}
		if !filesMode && !patternSeen {
			if LooksSensitive(arg) {
				return result(DecisionDeny, "rg search pattern looks credential-related", original)
			}
			patternSeen = true
			continue
		}
		if !ev.safePath(arg, cwd) {
			return result(DecisionManual, "rg path is outside the safe roots or uses unsafe patterns", original)
		}
	}
	return Result{}
}

func rgPatternValueFlag(arg string) bool {
	return arg == "--regexp" || arg == "-e"
}

func rgInlinePatternFlag(arg string) bool {
	return strings.HasPrefix(arg, "--regexp=") || strings.HasPrefix(arg, "-e=")
}

func (ev evaluator) evalRG(args []string, cwd string, original []string) Result {
	if cwd == "" && len(ev.roots) > 0 {
		cwd = ev.roots[0]
	}
	if cwd == "" || !ev.insideAnyRoot(filepath.Clean(cwd)) {
		return result(DecisionManual, "rg requires a safe root", original)
	}

	filesMode := false
	patternSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if rgFlagIsForbidden(arg) {
			return result(DecisionManual, "rg flag can execute helpers or read broad inputs", original)
		}
		if arg == "--" {
			for _, pathArg := range args[i+1:] {
				if !ev.safePath(pathArg, cwd) {
					return result(DecisionManual, "rg path is outside the safe roots or uses unsafe patterns", original)
				}
			}
			res := result(DecisionAllow, "read-only rg search", original)
			res.CommandShape = ev.commandShape(original, cwd)
			return res
		}
		if arg == "--files" {
			filesMode = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !rgFlagIsAllowed(arg) {
				return result(DecisionManual, "rg flag is not in the read-only allow profile", original)
			}
			if rgFlagNeedsValue(arg) {
				i++
				if i >= len(args) || LooksSensitive(args[i]) {
					return result(DecisionManual, "rg flag value is not safe", original)
				}
			}
			continue
		}
		if !filesMode && !patternSeen {
			if LooksSensitive(arg) {
				return result(DecisionDeny, "rg search pattern looks credential-related", original)
			}
			patternSeen = true
			continue
		}
		if !ev.safePath(arg, cwd) {
			return result(DecisionManual, "rg path is outside the safe roots or uses unsafe patterns", original)
		}
	}
	if !filesMode && !patternSeen {
		return result(DecisionManual, "rg search pattern is required", original)
	}
	res := result(DecisionAllow, "read-only rg search", original)
	res.CommandShape = ev.commandShape(original, cwd)
	return res
}

func rgFlagIsForbidden(arg string) bool {
	forbidden := []string{
		"--pre", "--pre-glob", "--hostname-bin", "--search-zip", "--file",
		"-z", "-f",
	}
	for _, item := range forbidden {
		if arg == item || strings.HasPrefix(arg, item+"=") {
			return true
		}
	}
	if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
		shorts := strings.TrimPrefix(arg, "-")
		return strings.Contains(shorts, "z") || strings.Contains(shorts, "f")
	}
	return false
}

func rgFlagIsAllowed(arg string) bool {
	if strings.HasPrefix(arg, "--glob=") || strings.HasPrefix(arg, "-g=") ||
		strings.HasPrefix(arg, "--type=") || strings.HasPrefix(arg, "--type-not=") ||
		strings.HasPrefix(arg, "--regexp=") || strings.HasPrefix(arg, "-e=") ||
		strings.HasPrefix(arg, "--max-count=") || strings.HasPrefix(arg, "-m=") ||
		strings.HasPrefix(arg, "--context=") || strings.HasPrefix(arg, "-C=") ||
		strings.HasPrefix(arg, "--before-context=") || strings.HasPrefix(arg, "-B=") ||
		strings.HasPrefix(arg, "--after-context=") || strings.HasPrefix(arg, "-A=") {
		return true
	}
	allowed := map[string]bool{
		"--files": true, "--json": true, "--line-number": true, "-n": true,
		"--no-heading": true, "--with-filename": true, "--count": true,
		"--fixed-strings": true, "-F": true, "--ignore-case": true, "-i": true,
		"--glob": true, "-g": true, "--type": true, "-t": true,
		"--type-not": true, "-T": true, "--regexp": true, "-e": true,
		"--max-count": true, "-m": true, "--context": true, "-C": true,
		"--before-context": true, "-B": true, "--after-context": true, "-A": true,
	}
	return allowed[arg]
}

func rgFlagNeedsValue(arg string) bool {
	needs := map[string]bool{
		"--glob": true, "-g": true, "--type": true, "-t": true,
		"--type-not": true, "-T": true, "--regexp": true, "-e": true,
		"--max-count": true, "-m": true, "--context": true, "-C": true,
		"--before-context": true, "-B": true, "--after-context": true, "-A": true,
	}
	return needs[arg]
}
