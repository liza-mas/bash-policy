package bashpolicy

import "strings"

func (ev evaluator) sedCommandShape(argv []string, cwd string) string {
	if len(argv) < 4 || argv[1] != "-n" {
		return ev.genericCommandShape(argv, cwd)
	}
	script, ok := sedRangePrintScriptShape(argv[2])
	if !ok {
		return ev.genericCommandShape(argv, cwd)
	}
	out := []string{argv[0], argv[1], script}
	for _, path := range argv[3:] {
		if strings.HasPrefix(path, "-") || !ev.safePath(path, cwd) {
			return ev.genericCommandShape(argv, cwd)
		}
		out = append(out, "<safe-path>")
	}
	return strings.Join(out, " ")
}

func evalSedSafetyFloor(args []string, original []string) Result {
	scriptSeen := false
	optionsDone := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !optionsDone && arg == "--" {
			optionsDone = true
			continue
		}
		if !optionsDone && strings.HasPrefix(arg, "-") && arg != "-" {
			switch {
			case sedUnsafeOption(arg):
				return result(DecisionManual, "sed option can execute scripts, read scripts, or write files", original)
			case sedOptionNeedsValue(arg):
				i++
			}
			continue
		}
		if !scriptSeen {
			if sedScriptLooksUnsafe(arg) {
				return result(DecisionManual, "sed script can execute commands or read/write files", original)
			}
			scriptSeen = true
		}
	}
	return Result{}
}

func sedRangePrintScriptShape(script string) (string, bool) {
	body, ok := strings.CutSuffix(script, "p")
	if !ok {
		return "", false
	}
	start, end, ok := strings.Cut(body, ",")
	if !ok || !isInteger(start) || !isInteger(end) {
		return "", false
	}
	return "<number>,<number>p", true
}

func sedUnsafeOption(arg string) bool {
	return arg == "-e" || strings.HasPrefix(arg, "-e") ||
		arg == "--expression" || strings.HasPrefix(arg, "--expression=") ||
		arg == "-f" || strings.HasPrefix(arg, "-f") ||
		arg == "--file" || strings.HasPrefix(arg, "--file=") ||
		arg == "-i" || strings.HasPrefix(arg, "-i") ||
		arg == "--in-place" || strings.HasPrefix(arg, "--in-place=")
}

func sedOptionNeedsValue(arg string) bool {
	return arg == "-l" || arg == "--line-length"
}

func sedScriptLooksUnsafe(script string) bool {
	return strings.ContainsAny(script, "ewWrR")
}
