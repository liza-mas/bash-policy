package bashpolicy

import (
	"strconv"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

type commandShapeLeaf struct {
	shape string
	argv  []string
	cwd   string
}

func (ev evaluator) compoundCommandParts(stmts []*syntax.Stmt, cwd string) (string, []commandShapeLeaf, bool, Result) {
	parts := make([]string, 0, len(stmts))
	leaves := []commandShapeLeaf{}
	nextCWD := cwd
	for _, stmt := range stmts {
		shape, stmtLeaves, updatedCWD, ok, floor := ev.stmtCommandParts(stmt, nextCWD)
		if floor.Decision != "" {
			return "", nil, false, floor
		}
		if !ok || shape == "" {
			return "", nil, false, Result{}
		}
		parts = append(parts, shape)
		leaves = append(leaves, stmtLeaves...)
		nextCWD = updatedCWD
	}
	return strings.Join(parts, " ; "), leaves, true, Result{}
}

func commandShapeLeavesForCommand(command string, projectRoot string, safeRoots []string) []string {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(file.Stmts) == 0 {
		return nil
	}
	ev := newEvaluator(Request{ProjectRoot: projectRoot, SafeRoots: safeRoots})
	_, leaves, ok, floor := ev.compoundCommandParts(file.Stmts, ev.defaultCWD)
	if !ok || floor.Decision != "" {
		return nil
	}
	identities := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		if leaf.shape != "" {
			identities = append(identities, leaf.shape)
		}
	}
	return identities
}

func (ev evaluator) stmtCommandParts(stmt *syntax.Stmt, cwd string) (string, []commandShapeLeaf, string, bool, Result) {
	if stmt == nil || stmt.Cmd == nil {
		return "", nil, cwd, false, Result{}
	}
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return "", nil, cwd, false, result(DecisionManual, "shell control modifiers are not auto-allowed", nil)
	}
	if len(stmt.Redirs) > 0 {
		return "", nil, cwd, false, result(DecisionManual, "shell redirections are not auto-allowed", nil)
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		argv, ok := literalArgs(cmd.Args)
		if !ok {
			return "", nil, cwd, false, result(DecisionManual, "dynamic command or argument is not auto-allowed", nil)
		}
		if floor := ev.evalSafetyFloor(argv, cwd); floor.Decision != "" {
			return "", nil, cwd, false, floor
		}
		nextCWD := cwd
		if len(argv) == 2 && argv[0] == "cd" {
			dir, ok := ev.safeDir(argv[1], cwd)
			if !ok {
				return "", nil, cwd, false, result(DecisionManual, "cd target is outside the safe roots", argv)
			}
			nextCWD = dir
		}
		shape := ev.policyCommandShape(argv, cwd)
		if shape == "" {
			return "", nil, cwd, false, Result{}
		}
		leaf := commandShapeLeaf{shape: shape, argv: argv, cwd: cwd}
		return shape, []commandShapeLeaf{leaf}, nextCWD, true, Result{}
	case *syntax.BinaryCmd:
		return ev.binaryCommandParts(cmd, cwd)
	default:
		return "", nil, cwd, false, Result{}
	}
}

func (ev evaluator) binaryCommandParts(cmd *syntax.BinaryCmd, cwd string) (string, []commandShapeLeaf, string, bool, Result) {
	op, ok := binaryCommandOperator(cmd.Op)
	if !ok {
		return "", nil, cwd, false, Result{}
	}
	left, leftLeaves, leftCWD, ok, floor := ev.stmtCommandParts(cmd.X, cwd)
	if floor.Decision != "" {
		return "", nil, cwd, false, floor
	}
	if !ok || left == "" {
		return "", nil, cwd, false, Result{}
	}
	rightCWD := cwd
	nextCWD := cwd
	if cmd.Op == syntax.AndStmt {
		rightCWD = leftCWD
	}
	right, rightLeaves, updatedCWD, ok, floor := ev.stmtCommandParts(cmd.Y, rightCWD)
	if floor.Decision != "" {
		return "", nil, cwd, false, floor
	}
	if !ok || right == "" {
		return "", nil, cwd, false, Result{}
	}
	if cmd.Op == syntax.AndStmt {
		nextCWD = updatedCWD
	}
	leaves := append(leftLeaves, rightLeaves...)
	return left + " " + op + " " + right, leaves, nextCWD, true, Result{}
}

func binaryCommandOperator(op syntax.BinCmdOperator) (string, bool) {
	switch op {
	case syntax.AndStmt:
		return "&&", true
	case syntax.OrStmt:
		return "||", true
	case syntax.Pipe:
		return "|", true
	default:
		return "", false
	}
}

func (ev evaluator) withCommandShape(res Result, argv []string, cwd string) Result {
	if res.CommandShape != "" || res.Decision == DecisionNoOp || len(argv) == 0 {
		return res
	}
	res.CommandShape = ev.policyCommandShape(argv, cwd)
	return res
}

func (ev evaluator) policyCommandShape(argv []string, cwd string) string {
	if len(argv) == 1 && argv[0] == "rtk" {
		return ""
	}
	if len(argv) > 1 && argv[0] == "rtk" {
		argv = argv[1:]
	}
	if len(argv) > 0 && argv[0] == "env" {
		_, wrapped, res, ok := parseEnvLauncher(argv[1:], argv)
		if res.Decision != "" || !ok {
			return ""
		}
		argv = wrapped
	}
	return ev.commandShape(argv, cwd)
}

func (ev evaluator) commandShape(argv []string, cwd string) string {
	if len(argv) == 0 {
		return ""
	}
	switch argv[0] {
	case "git":
		return ev.gitCommandShape(argv, cwd)
	case "rg":
		return ev.rgCommandShape(argv, cwd)
	case "grep":
		return ev.grepCommandShape(argv, cwd)
	case "sed":
		return ev.sedCommandShape(argv, cwd)
	case "cd":
		if len(argv) == 2 {
			return strings.Join([]string{argv[0], ev.renderCommandShapeArg(argv[1], cwd, true)}, " ")
		}
	default:
		if profile, ok := readOnlyUnixProfiles[argv[0]]; ok && profile.operandsArePaths {
			return ev.pathOperandUnixCommandShape(argv, cwd, profile)
		}
	}
	return ev.genericCommandShape(argv, cwd)
}

func (ev evaluator) genericCommandShape(argv []string, cwd string) string {
	if len(argv) == 0 {
		return ""
	}
	out := make([]string, 0, len(argv))
	afterDashDash := false
	for _, arg := range argv {
		if arg == "--" {
			afterDashDash = true
			out = append(out, arg)
			continue
		}
		out = append(out, ev.renderCommandShapeArg(arg, cwd, afterDashDash || argLooksPathLike(arg)))
	}
	return strings.Join(out, " ")
}

func (ev evaluator) pathOperandUnixCommandShape(argv []string, cwd string, profile readOnlyUnixProfile) string {
	out := make([]string, 0, len(argv))
	out = append(out, argv[0])
	afterDashDash := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" && !afterDashDash {
			afterDashDash = true
			out = append(out, arg)
			continue
		}
		if !afterDashDash && strings.HasPrefix(arg, "-") && arg != "-" {
			out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
			if profile.valueFlags[arg] {
				i++
				if i < len(argv) {
					out = append(out, ev.renderCommandShapeArg(argv[i], cwd, false))
				}
			}
			continue
		}
		out = append(out, ev.renderCommandShapeArg(arg, cwd, true))
	}
	return strings.Join(out, " ")
}

func (ev evaluator) gitCommandShape(argv []string, cwd string) string {
	out := []string{argv[0]}
	args := argv[1:]
	nextCWD := cwd
	for len(args) >= 2 && args[0] == "-C" {
		out = append(out, args[0])
		if dir, ok := ev.safeDir(args[1], nextCWD); ok {
			out = append(out, "<safe-path>")
			nextCWD = dir
		} else {
			out = append(out, ev.renderCommandShapeArg(args[1], nextCWD, false))
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return strings.Join(out, " ")
	}
	subcommand := args[0]
	out = append(out, subcommand)
	rest := args[1:]
	switch subcommand {
	case "status", "check-ignore":
		out = append(out, ev.pathspecCommandArgsShape(rest, nextCWD, gitFlagNeedsValueForShape, false)...)
	case "diff":
		out = append(out, ev.pathspecCommandArgsShape(rest, nextCWD, gitFlagNeedsValueForShape, true)...)
	case "grep":
		grepArgs, ok := ev.gitGrepCommandArgsShape(rest, nextCWD)
		if !ok {
			return ""
		}
		out = append(out, grepArgs...)
	case "log", "show":
		out = append(out, ev.gitLogShowCommandArgsShape(rest, nextCWD)...)
	default:
		out = append(out, ev.genericCommandShapeArgs(rest, nextCWD)...)
	}
	return strings.Join(out, " ")
}

func (ev evaluator) pathspecCommandArgsShape(args []string, cwd string, flagNeedsValue func(string) bool, ambiguousBareArgs bool) []string {
	out := make([]string, 0, len(args))
	afterDashDash := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" && !afterDashDash {
			afterDashDash = true
			out = append(out, arg)
			continue
		}
		if !afterDashDash && strings.HasPrefix(arg, "-") && arg != "-" {
			out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
			if flagNeedsValue(arg) {
				i++
				if i < len(args) {
					out = append(out, ev.renderCommandShapeArg(args[i], cwd, false))
				}
			}
			continue
		}
		if afterDashDash || !ambiguousBareArgs {
			out = append(out, ev.renderGitPathspecShapeArg(arg, cwd))
		} else {
			out = append(out, ev.renderAmbiguousPathspecArg(arg, cwd))
		}
	}
	return out
}

func gitFlagNeedsValueForShape(arg string) bool {
	switch arg {
	case "-C", "-U", "--unified", "--inter-hunk-context", "--output",
		"--relative", "--src-prefix", "--dst-prefix", "--word-diff-regex",
		"--color-moved-ws", "--diff-filter", "-G", "-S", "-O",
		"--exclude", "--exclude-from", "--exclude-per-directory":
		return true
	default:
		return false
	}
}

func (ev evaluator) gitLogShowCommandArgsShape(args []string, cwd string) []string {
	out := make([]string, 0, len(args))
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" && !afterDashDash {
			afterDashDash = true
			out = append(out, arg)
			continue
		}
		if afterDashDash {
			out = append(out, ev.renderCommandShapeArg(arg, cwd, true))
			continue
		}
		if objectPath, ok := gitObjectPathOperand(arg); ok {
			if gitObjectPathPathSensitive(objectPath) {
				out = append(out, "<redacted>")
			} else {
				out = append(out, renderCommandShapeToken(arg))
			}
			continue
		}
		out = append(out, ev.renderCommandShapeArg(arg, cwd, argLooksPathLike(arg)))
	}
	return out
}

func (ev evaluator) rgCommandShape(argv []string, cwd string) string {
	out := []string{argv[0]}
	filesMode := false
	patternSeen := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			out = append(out, arg)
			for _, pathArg := range argv[i+1:] {
				out = append(out, ev.renderCommandShapeArg(pathArg, cwd, true))
			}
			return strings.Join(out, " ")
		}
		if arg == "--files" {
			filesMode = true
			out = append(out, arg)
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
			if rgInlinePatternFlag(arg) {
				patternSeen = true
			}
			if rgFlagNeedsValue(arg) {
				i++
				if i < len(argv) {
					out = append(out, ev.renderCommandShapeArg(argv[i], cwd, false))
					if rgPatternValueFlag(arg) {
						patternSeen = true
					}
				}
			}
			continue
		}
		if !filesMode && !patternSeen {
			patternSeen = true
			out = append(out, ev.renderCommandShapeArg(arg, cwd, false))
			continue
		}
		out = append(out, ev.renderCommandShapeArg(arg, cwd, true))
	}
	return strings.Join(out, " ")
}

func (ev evaluator) genericCommandShapeArgs(args []string, cwd string) []string {
	out := make([]string, 0, len(args))
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" {
			afterDashDash = true
			out = append(out, arg)
			continue
		}
		out = append(out, ev.renderCommandShapeArg(arg, cwd, afterDashDash || argLooksPathLike(arg)))
	}
	return out
}

func (ev evaluator) renderCommandShapeArg(arg string, cwd string, pathOperand bool) string {
	switch {
	case pathOperand && ev.safePath(arg, cwd):
		return "<safe-path>"
	case isInteger(arg):
		return "<number>"
	case looksFieldList(arg):
		return "<fields>"
	case LooksSensitive(arg):
		return "<redacted>"
	default:
		return renderCommandShapeToken(arg)
	}
}

func (ev evaluator) renderGitPathspecShapeArg(arg string, cwd string) string {
	if ev.safeGitPathspec(arg, cwd) {
		return "<safe-path>"
	}
	return ev.renderCommandShapeArg(arg, cwd, true)
}

func (ev evaluator) renderAmbiguousPathspecArg(arg string, cwd string) string {
	if ev.safePath(arg, cwd) && (argLooksPathLike(arg) || ev.safeExistingPath(arg, cwd)) {
		return "<safe-path>"
	}
	return ev.renderCommandShapeArg(arg, cwd, false)
}

func renderCommandShapeToken(value string) string {
	if !commandShapeTokenNeedsQuote(value) {
		return value
	}
	return strconv.Quote(value)
}

func commandShapeTokenNeedsQuote(value string) bool {
	if value == "" || shellOperatorToken(value) || strings.Contains(value, `"`) {
		return true
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

type commandShapeToken struct {
	value  string
	quoted bool
}

func commandShapeFields(identity string) ([]string, bool) {
	tokens, ok := commandShapeTokens(identity)
	if !ok {
		return nil, false
	}
	fields := make([]string, 0, len(tokens))
	for _, token := range tokens {
		fields = append(fields, token.value)
	}
	return fields, true
}

func commandShapeTokens(identity string) ([]commandShapeToken, bool) {
	identity = strings.TrimSpace(identity)
	tokens := []commandShapeToken{}
	for i := 0; i < len(identity); {
		for i < len(identity) && unicode.IsSpace(rune(identity[i])) {
			i++
		}
		if i >= len(identity) {
			break
		}
		if identity[i] == '"' {
			start := i
			i++
			escaped := false
			for i < len(identity) {
				c := identity[i]
				if escaped {
					escaped = false
					i++
					continue
				}
				if c == '\\' {
					escaped = true
					i++
					continue
				}
				if c == '"' {
					i++
					break
				}
				i++
			}
			if i > len(identity) || identity[i-1] != '"' {
				return nil, false
			}
			value, err := strconv.Unquote(identity[start:i])
			if err != nil {
				return nil, false
			}
			if i < len(identity) && !unicode.IsSpace(rune(identity[i])) {
				return nil, false
			}
			tokens = append(tokens, commandShapeToken{value: value, quoted: true})
			continue
		}
		start := i
		for i < len(identity) && !unicode.IsSpace(rune(identity[i])) {
			if identity[i] == '"' {
				return nil, false
			}
			i++
		}
		tokens = append(tokens, commandShapeToken{value: identity[start:i]})
	}
	return tokens, true
}

func joinCommandShapeFields(fields []string) string {
	rendered := make([]string, 0, len(fields))
	for _, field := range fields {
		rendered = append(rendered, renderCommandShapeToken(field))
	}
	return strings.Join(rendered, " ")
}
