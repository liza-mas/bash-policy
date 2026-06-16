package bashpolicy

import (
	"strings"
)

func evalGrepSafetyFloor(args []string, original []string) Result {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if grepShortClusterHasEmbeddedPatternArg(arg) {
			return result(DecisionManual, "grep short option cluster with embedded pattern or file operand is not safe", original)
		}
	}
	return Result{}
}

// Grep is not a built-in allow family, so exported grep rules collapse search
// terms to <pattern>. rg keeps literal patterns to preserve its existing
// allow-profile command surface.
func (ev evaluator) grepCommandShape(argv []string, cwd string) string {
	out := []string{argv[0]}
	optionsDone := false
	patternSeen := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if !optionsDone && arg == "--" {
			optionsDone = true
			out = append(out, arg)
			continue
		}
		if !optionsDone && strings.HasPrefix(arg, "-") && arg != "-" {
			if grepShortClusterHasEmbeddedPatternArg(arg) {
				return ""
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
				if i < len(argv) {
					out = append(out, renderCommandShapePattern(argv[i]))
					patternSeen = true
				}
			case grepPatternFileFlag(arg):
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
				i++
				if i < len(argv) {
					out = append(out, ev.renderCommandShapeArg(argv[i], cwd, true))
					patternSeen = true
				}
			case grepFlagNeedsValue(arg):
				out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
				i++
				if i < len(argv) {
					out = append(out, ev.renderCommandShapeArg(argv[i], cwd, false))
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
		out = append(out, ev.renderCommandShapeArg(arg, cwd, true))
	}
	return strings.Join(out, " ")
}

func grepPatternValueFlag(arg string) bool {
	return arg == "-e" || arg == "--regexp"
}

func grepPatternFileFlag(arg string) bool {
	return arg == "-f" || arg == "--file"
}

func grepInlinePatternFlag(arg string) bool {
	return strings.HasPrefix(arg, "--regexp=") ||
		(strings.HasPrefix(arg, "-e") && !strings.HasPrefix(arg, "--") && len(arg) > len("-e"))
}

func grepInlinePatternFileFlag(arg string) bool {
	return strings.HasPrefix(arg, "--file=") ||
		(strings.HasPrefix(arg, "-f") && !strings.HasPrefix(arg, "--") && len(arg) > len("-f"))
}

func grepShortClusterHasEmbeddedPatternArg(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) <= 2 {
		return false
	}
	for i, flag := range strings.TrimPrefix(arg, "-") {
		if i > 0 && (flag == 'e' || flag == 'f') {
			return true
		}
	}
	return false
}

func renderGrepInlinePatternFlag(arg string) string {
	if value, ok := strings.CutPrefix(arg, "--regexp="); ok {
		return "--regexp=" + renderCommandShapePattern(value)
	}
	return "-e" + renderCommandShapePattern(strings.TrimPrefix(arg, "-e"))
}

func (ev evaluator) renderGrepInlinePathFlag(arg string, cwd string) string {
	if value, ok := strings.CutPrefix(arg, "--file="); ok {
		return "--file=" + ev.renderCommandShapeArg(value, cwd, true)
	}
	return "-f" + ev.renderCommandShapeArg(strings.TrimPrefix(arg, "-f"), cwd, true)
}

func grepFlagNeedsValue(arg string) bool {
	// Keep this list conservative: missing a value-taking grep option can
	// shift later operands and make a path look like the search pattern.
	switch arg {
	case "-A", "-B", "-C", "-D", "-d", "-m",
		"--after-context", "--before-context", "--binary-files", "--context",
		"--devices", "--directories", "--exclude", "--exclude-dir",
		"--include", "--include-dir", "--label", "--max-count":
		return true
	default:
		return false
	}
}

func renderCommandShapePattern(arg string) string {
	if LooksSensitive(arg) {
		return "<redacted>"
	}
	return "<pattern>"
}
