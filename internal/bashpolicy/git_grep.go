package bashpolicy

import "strings"

func (ev evaluator) evalGitGrepSafetyFloor(args []string, cwd string, original []string) Result {
	patternSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			for _, pathspec := range args[i+1:] {
				if !ev.safeGitPathspec(pathspec, cwd) {
					return result(DecisionManual, "git grep pathspec is outside the safe roots or uses unsafe patterns", original)
				}
			}
			return Result{}
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if gitGrepShortClusterNeedsManual(arg) {
				return result(DecisionManual, "git grep short option cluster with embedded pattern, pattern file, or pager flag is not safe", original)
			}
			switch {
			case gitGrepPagerFlag(arg):
				return result(DecisionManual, "git grep pager execution flag is not safe", original)
			case grepInlinePatternFlag(arg):
				patternSeen = true
			case grepInlinePatternFileFlag(arg):
				if !ev.safePath(gitGrepInlineFlagValue(arg), cwd) {
					return result(DecisionManual, "git grep pattern file is outside the safe roots or uses unsafe patterns", original)
				}
				patternSeen = true
			case grepPatternValueFlag(arg):
				i++
				if i >= len(args) || LooksSensitive(args[i]) {
					return result(DecisionManual, "git grep pattern value is not safe", original)
				}
				patternSeen = true
			case grepPatternFileFlag(arg):
				i++
				if i >= len(args) || !ev.safePath(args[i], cwd) {
					return result(DecisionManual, "git grep pattern file is outside the safe roots or uses unsafe patterns", original)
				}
				patternSeen = true
			case gitGrepFlagNeedsValue(arg):
				i++
				if i >= len(args) || LooksSensitive(args[i]) {
					return result(DecisionManual, "git grep flag value is not safe", original)
				}
			}
			continue
		}
		if !patternSeen {
			if LooksSensitive(arg) {
				return result(DecisionDeny, "git grep search pattern looks credential-related", original)
			}
			patternSeen = true
			continue
		}
		if !ev.safeGitPathspec(arg, cwd) {
			return result(DecisionManual, "git grep pathspec is outside the safe roots or uses unsafe patterns", original)
		}
	}
	return Result{}
}

func (ev evaluator) gitGrepCommandArgsShape(args []string, cwd string) ([]string, bool) {
	out := make([]string, 0, len(args))
	patternSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, arg)
			for _, pathspec := range args[i+1:] {
				out = append(out, ev.renderGitPathspecShapeArg(pathspec, cwd))
			}
			return out, true
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			if gitGrepShortClusterNeedsManual(arg) || gitGrepPagerFlag(arg) {
				return nil, false
			}
			switch {
			case grepInlinePatternFlag(arg):
				out = append(out, renderGrepInlinePatternFlag(arg))
				patternSeen = true
			case grepInlinePatternFileFlag(arg):
				out = append(out, ev.renderGrepInlinePathFlag(arg, cwd))
				patternSeen = true
			case grepPatternValueFlag(arg):
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
				i++
				if i < len(args) {
					out = append(out, renderCommandShapePattern(args[i]))
					patternSeen = true
				}
			case grepPatternFileFlag(arg):
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
				i++
				if i < len(args) {
					out = append(out, ev.renderCommandShapeArg(args[i], cwd, true))
					patternSeen = true
				}
			case gitGrepFlagNeedsValue(arg):
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
				i++
				if i < len(args) {
					out = append(out, ev.renderCommandShapeArg(args[i], cwd, false))
				}
			default:
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
			}
			continue
		}
		if !patternSeen {
			out = append(out, renderCommandShapePattern(arg))
			patternSeen = true
			continue
		}
		out = append(out, ev.renderGitPathspecShapeArg(arg, cwd))
	}
	return out, true
}

func gitGrepPagerFlag(arg string) bool {
	return arg == "-O" || strings.HasPrefix(arg, "-O") ||
		arg == "--open-files-in-pager" || strings.HasPrefix(arg, "--open-files-in-pager=")
}

func gitGrepShortClusterNeedsManual(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) <= 2 {
		return false
	}
	for i, flag := range strings.TrimPrefix(arg, "-") {
		switch flag {
		case 'e', 'f':
			return i > 0
		case 'O':
			return true
		}
	}
	return false
}

func gitGrepFlagNeedsValue(arg string) bool {
	return grepFlagNeedsValue(arg) || arg == "--threads"
}

func gitGrepInlineFlagValue(arg string) string {
	if value, ok := strings.CutPrefix(arg, "--file="); ok {
		return value
	}
	if value, ok := strings.CutPrefix(arg, "--regexp="); ok {
		return value
	}
	if strings.HasPrefix(arg, "-f") || strings.HasPrefix(arg, "-e") {
		return arg[2:]
	}
	return ""
}
