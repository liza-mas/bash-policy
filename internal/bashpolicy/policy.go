// Package bashpolicy evaluates provider Bash hook commands against a fail-closed
// allow profile. The evaluator rejects globally unsafe shell shapes before
// consulting project policy, then auto-allows only the hardcoded read-only
// inspection profiles listed below.
//
// Built-in top-level command families:
//   - common Unix inspection commands: basename, cat, cd, cut, date, diff,
//     dirname, echo, file, head, ls, pwd, realpath, sha256sum, sort, tail, tr,
//     tree, uniq, wc, which.
//   - rtk: unwrap and evaluate the wrapped command; rtk proxy is denied.
//   - git: allow only modeled read-only subcommands and safe path forms.
//   - rg: allow modeled read-only ripgrep searches.
//   - printenv/env: always deny environment dumps.
//
// Hardcoded read-only git subcommands:
//   - status
//   - diff
//   - rev-parse
//   - branch
//   - log/show
//   - worktree list

package bashpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
)

type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionDeny   Decision = "deny"
	DecisionManual Decision = "manual"
	DecisionNoOp   Decision = "no-op"
)

type Request struct {
	Command            string
	ProjectRoot        string
	SafeRoots          []string
	PolicyArtifactRoot string
	Policy             *Policy
}

type Result struct {
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason"`
	Summary       string   `json:"summary"`
	CommandFamily string   `json:"command_family,omitempty"`
	CommandShape  string   `json:"command_shape,omitempty"`
}

func Evaluate(req Request) Result {
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return result(DecisionNoOp, "empty command", nil)
	}

	ev := newEvaluator(req)
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return result(DecisionManual, "shell parse failed", []string{command})
	}
	if len(file.Stmts) == 0 {
		return result(DecisionNoOp, "empty command", nil)
	}
	var res Result
	if len(file.Stmts) != 1 {
		res = ev.evalCompoundStmts(file.Stmts, ev.defaultCWD, "multiple shell statements are not auto-allowed")
	} else {
		res = ev.evalStmt(file.Stmts[0], ev.defaultCWD)
	}
	if res.Summary == "" && res.Decision != DecisionNoOp {
		res.Summary = sanitizeSummary(command)
	}
	return res
}

func CommandFromHookPayload(data []byte) (string, error) {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("parse hook payload: %w", err)
	}
	if command, ok := findCommandField(payload); ok && strings.TrimSpace(command) != "" {
		return command, nil
	}
	return "", errors.New("hook payload does not contain a command string")
}

func findCommandField(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["command"]; ok {
			if command, ok := raw.(string); ok {
				return command, true
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if command, ok := findCommandField(typed[key]); ok {
				return command, true
			}
		}
	case []any:
		for _, item := range typed {
			if command, ok := findCommandField(item); ok {
				return command, true
			}
		}
	}
	return "", false
}

type evaluator struct {
	roots      []string
	defaultCWD string
	policy     *Policy
}

type readOnlyUnixProfile struct {
	reason                string
	minOperands           int
	maxOperands           int
	operandsArePaths      bool
	dateFormatOperandOnly bool
	allowedFlags          map[string]bool
	valueFlags            map[string]bool
	inlineValuePrefixes   []string
	forbiddenFlags        map[string]bool
	forbiddenPrefixes     []string
	shortFlagCluster      string
	flagsMayBeOperands    bool
	freeFormOperands      bool
}

var readOnlyUnixProfiles = map[string]readOnlyUnixProfile{
	"basename":  {reason: "read-only basename", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-a", "-z"), valueFlags: stringSet("-s")},
	"cat":       {reason: "read-only cat", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-n", "--number", "-b", "--number-nonblank", "-s", "--squeeze-blank", "-A", "--show-all", "-e", "-t", "-v"), shortFlagCluster: "nbsAetv"},
	"cut":       {reason: "read-only cut", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-s", "--only-delimited", "--complement"), valueFlags: stringSet("-b", "-c", "-d", "-f", "--bytes", "--characters", "--delimiter", "--fields"), inlineValuePrefixes: []string{"-b", "-c", "-d", "-f", "--bytes=", "--characters=", "--delimiter=", "--fields="}},
	"date":      {reason: "read-only date", maxOperands: 1, dateFormatOperandOnly: true, allowedFlags: stringSet("-u", "--utc", "--iso-8601"), valueFlags: stringSet("--date", "-d", "--rfc-3339"), inlineValuePrefixes: []string{"--date=", "--rfc-3339="}, forbiddenFlags: stringSet("-s", "--set"), forbiddenPrefixes: []string{"--set="}},
	"diff":      {reason: "read-only diff", minOperands: 2, maxOperands: 2, operandsArePaths: true, allowedFlags: stringSet("-u", "--unified", "-q", "--brief", "-r", "--recursive", "--color", "--no-color"), valueFlags: stringSet("-U", "--label"), inlineValuePrefixes: []string{"-U", "--unified=", "--label=", "--color="}, forbiddenFlags: stringSet("-o", "--output"), forbiddenPrefixes: []string{"--output="}},
	"dirname":   {reason: "read-only dirname", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-z")},
	"echo":      {reason: "read-only echo", maxOperands: -1, allowedFlags: stringSet("-n", "-e", "-E"), flagsMayBeOperands: true, freeFormOperands: true},
	"file":      {reason: "read-only file", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-b", "--brief", "-L", "--dereference", "-h", "--no-dereference", "-i", "--mime", "--mime-type", "--mime-encoding"), forbiddenFlags: stringSet("-f", "--files-from", "-m", "--magic-file"), forbiddenPrefixes: []string{"--files-from=", "--magic-file="}},
	"head":      {reason: "read-only head", minOperands: 1, maxOperands: -1, operandsArePaths: true, valueFlags: stringSet("-n", "--lines", "-c", "--bytes"), inlineValuePrefixes: []string{"-n", "-c", "--lines=", "--bytes="}},
	"ls":        {reason: "read-only ls", maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("--all", "--almost-all", "--long", "--human-readable", "--recursive", "--directory", "--color", "--no-color"), inlineValuePrefixes: []string{"--color="}, shortFlagCluster: "1AadfhlRrSt"},
	"pwd":       {reason: "read-only pwd", allowedFlags: stringSet("-L", "-P")},
	"realpath":  {reason: "read-only realpath", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-e", "-m", "-s", "--canonicalize-existing", "--canonicalize-missing", "--strip", "--no-symlinks")},
	"sha256sum": {reason: "read-only sha256sum", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-b", "--binary", "-t", "--text"), forbiddenFlags: stringSet("-c", "--check")},
	"sort":      {reason: "read-only sort", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-u", "--unique", "-n", "--numeric-sort", "-r", "--reverse", "-f", "--ignore-case", "-V", "--version-sort"), valueFlags: stringSet("-k", "--key", "-t", "--field-separator"), inlineValuePrefixes: []string{"-k", "-t", "--key=", "--field-separator="}, forbiddenFlags: stringSet("-o", "--output", "--files0-from"), forbiddenPrefixes: []string{"--output=", "--files0-from="}},
	"tail":      {reason: "read-only tail", minOperands: 1, maxOperands: -1, operandsArePaths: true, valueFlags: stringSet("-n", "--lines", "-c", "--bytes"), inlineValuePrefixes: []string{"-n", "-c", "--lines=", "--bytes="}, forbiddenFlags: stringSet("-f", "-F", "--follow")},
	"tr":        {reason: "read-only tr", minOperands: 1, maxOperands: 2, allowedFlags: stringSet("-c", "-C", "-d", "-s"), shortFlagCluster: "cCds"},
	"tree":      {reason: "read-only tree", maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-a", "-d", "-f", "--dirsfirst"), valueFlags: stringSet("-L", "-I"), inlineValuePrefixes: []string{"-L", "-I"}},
	"uniq":      {reason: "read-only uniq", minOperands: 1, maxOperands: 1, operandsArePaths: true, allowedFlags: stringSet("-c", "--count", "-d", "--repeated", "-u", "--unique", "-i", "--ignore-case"), valueFlags: stringSet("-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"), inlineValuePrefixes: []string{"-f", "-s", "-w", "--skip-fields=", "--skip-chars=", "--check-chars="}},
	"wc":        {reason: "read-only wc", minOperands: 1, maxOperands: -1, operandsArePaths: true, allowedFlags: stringSet("-l", "--lines", "-w", "--words", "-c", "--bytes", "-m", "--chars", "-L", "--max-line-length"), forbiddenFlags: stringSet("--files0-from"), forbiddenPrefixes: []string{"--files0-from="}, shortFlagCluster: "lwcmL"},
	"which":     {reason: "read-only which", minOperands: 1, maxOperands: -1, allowedFlags: stringSet("-a", "-s")},
}

var gitStatusAllowedFlags = stringSet(
	"--short", "-s", "--porcelain", "--porcelain=v1", "--porcelain=v2",
	"--branch", "-b", "--ignored", "--untracked-files=no", "-uno",
)

var gitDiffAllowedFlags = stringSet(
	"--stat", "--name-only", "--name-status", "--cached", "--staged",
	"--check", "--exit-code", "--color", "--no-color",
)

var gitLogShowAllowedFlags = stringSet(
	"--stat", "--name-only", "--oneline", "--decorate", "--no-patch",
	"-s", "--",
)

func newEvaluator(req Request) evaluator {
	var roots []string
	addRoot := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		roots = append(roots, canonicalRoot(path))
	}
	addRoot(req.ProjectRoot)
	for _, root := range req.SafeRoots {
		addRoot(root)
	}
	roots = uniqueStrings(roots)
	defaultCWD := ""
	if len(roots) > 0 {
		defaultCWD = roots[0]
	}
	return evaluator{roots: roots, defaultCWD: defaultCWD, policy: req.Policy}
}

func (ev evaluator) evalStmt(stmt *syntax.Stmt, cwd string) Result {
	if stmt == nil || stmt.Cmd == nil {
		return result(DecisionNoOp, "empty statement", nil)
	}
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return result(DecisionManual, "shell control modifiers are not auto-allowed", nil)
	}
	if len(stmt.Redirs) > 0 {
		return result(DecisionManual, "shell redirections are not auto-allowed", nil)
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		argv, ok := literalArgs(cmd.Args)
		if !ok {
			return result(DecisionManual, "dynamic command or argument is not auto-allowed", nil)
		}
		return ev.evalArgv(argv, cwd)
	case *syntax.BinaryCmd:
		return ev.evalCompoundStmts([]*syntax.Stmt{stmt}, cwd, "compound shell command is not auto-allowed")
	default:
		return result(DecisionManual, "compound shell command is not auto-allowed", nil)
	}
}

func (ev evaluator) evalCompoundStmts(stmts []*syntax.Stmt, cwd string, reason string) Result {
	shape, leaves, ok, floor := ev.compoundCommandParts(stmts, cwd)
	if floor.Decision != "" {
		return floor
	}
	if !ok || shape == "" || len(leaves) == 0 {
		return result(DecisionManual, reason, nil)
	}
	for _, leaf := range leaves {
		leafResult := ev.evalArgv(leaf.argv, leaf.cwd)
		if leafResult.Decision == DecisionAllow || leafResult.Decision == DecisionNoOp {
			continue
		}
		if leafResult.Decision == DecisionDeny {
			res := result(DecisionDeny, leafResult.Reason, nil)
			res.CommandShape = shape
			return res
		}
		leafReason := strings.TrimSpace(leafResult.Reason)
		if leafReason == "" {
			leafReason = reason
		}
		res := result(DecisionManual, "compound shell command contains manual command: "+leafReason, nil)
		res.CommandShape = shape
		return res
	}
	res := result(DecisionAllow, "compound shell command with allowed commands", nil)
	res.CommandShape = shape
	return res
}

func (ev evaluator) evalArgv(argv []string, cwd string) Result {
	if len(argv) == 0 {
		return result(DecisionNoOp, "empty command", argv)
	}
	if argvHasSensitiveValue(argv) {
		return result(DecisionDeny, "credential path or secret-looking argument is not safe", argv)
	}
	if floor := ev.evalSafetyFloor(argv, cwd); floor.Decision != "" {
		return floor
	}
	if policyResult, ok := ev.evalConfiguredPolicy(argv, cwd); ok {
		return policyResult
	}

	var res Result
	switch argv[0] {
	case "rtk":
		res = ev.evalRTK(argv, cwd)
	case "git":
		res = ev.evalGit(argv[1:], cwd, argv)
	case "rg":
		res = ev.evalRG(argv[1:], cwd, argv)
	case "printenv", "env":
		res = result(DecisionDeny, "environment dump commands are not safe", argv)
	default:
		if readOnlyResult, ok := ev.evalReadOnlyUnix(argv, cwd); ok {
			res = readOnlyResult
			break
		}
		res = result(DecisionManual, "command is not in the safe allow profiles", argv)
	}
	return ev.withCommandShape(res, argv, cwd)
}

func (ev evaluator) evalSafetyFloor(argv []string, cwd string) Result {
	if len(argv) == 0 {
		return Result{}
	}
	switch argv[0] {
	case "printenv", "env":
		return result(DecisionDeny, "environment dump commands are not safe", argv)
	case "bash", "sh", "zsh", "fish":
		return result(DecisionManual, "shell wrapper commands are not auto-allowed", argv)
	case "rtk":
		if len(argv) >= 2 && argv[1] == "proxy" {
			return result(DecisionDeny, "rtk proxy bypass is not safe", argv)
		}
		if len(argv) >= 2 {
			return ev.evalSafetyFloor(argv[1:], cwd)
		}
		return Result{}
	case "git":
		nextCWD, rest, ok := ev.consumeGitCwd(argv[1:], cwd, argv)
		if !ok {
			return result(DecisionManual, "git -C path is outside the safe roots", argv)
		}
		if len(rest) > 0 && gitSubcommandIsDestructive(rest[0], rest[1:]) {
			return result(DecisionDeny, "destructive git command is not safe", argv)
		}
		if argvHasSensitiveValue(rest) {
			return result(DecisionDeny, "git path targets a credential or secret location", argv)
		}
		for _, arg := range rest[1:] {
			if path, ok := gitObjectPathOperand(arg); ok {
				if gitObjectPathPathSensitive(path) {
					return result(DecisionDeny, "git object path targets a credential or secret location", argv)
				}
				if !gitObjectPathPathSafe(path) {
					return result(DecisionManual, "git object path is outside the read-only allow profile", argv)
				}
				continue
			}
			if !argLooksPathLike(arg) {
				continue
			}
			if !ev.safePath(arg, nextCWD) {
				return result(DecisionManual, "git path argument is outside the safe roots or uses unsafe patterns", argv)
			}
		}
		return Result{}
	case "rg":
		return ev.evalRGSafetyFloor(argv[1:], cwd, argv)
	}
	for _, arg := range argv[1:] {
		if !argLooksPathLike(arg) {
			continue
		}
		if !ev.safePath(arg, cwd) {
			return result(DecisionManual, "path argument is outside the safe roots or uses unsafe patterns", argv)
		}
	}
	return Result{}
}

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

func (ev evaluator) evalRTK(argv []string, cwd string) Result {
	if len(argv) < 2 {
		return result(DecisionManual, "rtk wrapper has no command to evaluate", argv)
	}
	if argv[1] == "proxy" {
		return result(DecisionDeny, "rtk proxy bypass is not safe", argv)
	}
	wrapped := argv[1:]
	wrappedResult := ev.evalArgv(wrapped, cwd)
	wrappedResult.CommandFamily = "rtk"
	if wrappedResult.Summary != "" {
		wrappedResult.Summary = "rtk " + wrappedResult.Summary
	}
	if wrappedResult.Decision == DecisionAllow {
		wrappedResult.Reason = "rtk wrapper around " + wrappedResult.Reason
	}
	return wrappedResult
}

func (ev evaluator) evalReadOnlyUnix(argv []string, cwd string) (Result, bool) {
	if len(argv) == 0 {
		return Result{}, false
	}
	if argv[0] == "cd" {
		return ev.evalReadOnlyCD(argv, cwd), true
	}
	profile, ok := readOnlyUnixProfiles[argv[0]]
	if !ok {
		return Result{}, false
	}
	if cwd == "" && len(ev.roots) > 0 {
		cwd = ev.roots[0]
	}
	operands, parseResult := parseReadOnlyUnixArgs(argv[1:], profile, argv)
	if parseResult.Decision != "" {
		return parseResult, true
	}
	if len(operands) < profile.minOperands {
		return result(DecisionManual, "read-only command requires an explicit operand", argv), true
	}
	if profile.maxOperands >= 0 && len(operands) > profile.maxOperands {
		return result(DecisionManual, "read-only command has too many operands for auto-allow", argv), true
	}
	if profile.dateFormatOperandOnly {
		for _, operand := range operands {
			if !strings.HasPrefix(operand, "+") {
				return result(DecisionManual, "date operand is not in the read-only allow profile", argv), true
			}
		}
	}
	if profile.operandsArePaths {
		if cwd == "" || !ev.insideAnyRoot(filepath.Clean(cwd)) {
			return result(DecisionManual, "read-only command requires a safe root", argv), true
		}
		for _, operand := range operands {
			if operand == "-" || !ev.safePath(operand, cwd) {
				return result(DecisionManual, "read-only command path is outside the safe roots or uses unsafe patterns", argv), true
			}
		}
	}
	res := result(DecisionAllow, profile.reason, argv)
	res.CommandShape = ev.commandShape(argv, cwd)
	return res, true
}

func (ev evaluator) evalReadOnlyCD(argv []string, cwd string) Result {
	if len(argv) != 2 {
		return result(DecisionManual, "cd requires exactly one safe directory", argv)
	}
	if LooksSensitive(argv[1]) {
		return result(DecisionDeny, "credential path is not safe", argv)
	}
	if _, ok := ev.safeDir(argv[1], cwd); !ok {
		return result(DecisionManual, "cd target is outside the safe roots", argv)
	}
	res := result(DecisionAllow, "read-only cd to safe directory", argv)
	res.CommandShape = ev.commandShape(argv, cwd)
	return res
}

func parseReadOnlyUnixArgs(args []string, profile readOnlyUnixProfile, original []string) ([]string, Result) {
	var operands []string
	afterDashDash := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" && !afterDashDash {
			afterDashDash = true
			continue
		}
		if profile.flagsMayBeOperands {
			operands = append(operands, arg)
			continue
		}
		if !afterDashDash && strings.HasPrefix(arg, "-") && arg != "-" {
			if profile.flagForbidden(arg) {
				return nil, result(DecisionManual, "read-only command flag can write, follow, or read broad inputs", original)
			}
			if strings.Contains(arg, "<redacted>") {
				return nil, result(DecisionManual, "read-only command flag value is not safe", original)
			}
			if profile.allowedFlags[arg] || profile.shortClusterAllowed(arg) || profile.inlineValueAllowed(arg) {
				continue
			}
			if profile.valueFlags[arg] {
				i++
				if i >= len(args) || strings.Contains(args[i], "<redacted>") || LooksSensitive(args[i]) {
					return nil, result(DecisionManual, "read-only command flag value is not safe", original)
				}
				continue
			}
			return nil, result(DecisionManual, "read-only command flag is not in the allow profile", original)
		}
		operands = append(operands, arg)
	}
	return operands, Result{}
}

func (profile readOnlyUnixProfile) flagForbidden(arg string) bool {
	if profile.forbiddenFlags[arg] {
		return true
	}
	for _, prefix := range profile.forbiddenPrefixes {
		if strings.HasPrefix(arg, prefix) {
			return true
		}
	}
	return false
}

func (profile readOnlyUnixProfile) inlineValueAllowed(arg string) bool {
	for _, prefix := range profile.inlineValuePrefixes {
		if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
			value := strings.TrimPrefix(arg, prefix)
			return !strings.Contains(value, "<redacted>") && !LooksSensitive(value)
		}
	}
	return false
}

func (profile readOnlyUnixProfile) shortClusterAllowed(arg string) bool {
	if profile.shortFlagCluster == "" || !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") || len(arg) < 2 {
		return false
	}
	for _, r := range strings.TrimPrefix(arg, "-") {
		if !strings.ContainsRune(profile.shortFlagCluster, r) {
			return false
		}
	}
	return true
}

func (ev evaluator) evalConfiguredPolicy(argv []string, cwd string) (Result, bool) {
	shape := ev.policyCommandShape(argv, cwd)
	if shape == "" {
		return Result{}, false
	}
	return ev.evalConfiguredCommandShape(shape, argv)
}

func (ev evaluator) evalConfiguredCommandShape(shape string, argv []string) (Result, bool) {
	if ev.policy == nil {
		return Result{}, false
	}
	rule, ok := ev.policy.CommandRule(shape)
	if !ok {
		return Result{}, false
	}
	switch rule.Decision {
	case DecisionAllow, DecisionDeny, DecisionManual:
		res := result(rule.Decision, "project bash policy command-shape rule", argv)
		res.CommandShape = shape
		return res, true
	default:
		return Result{}, false
	}
}

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
	return ev.commandShape(argv, cwd)
}

func (ev evaluator) commandShape(argv []string, cwd string) string {
	if len(argv) == 0 {
		return ""
	}
	isGitCommand := argv[0] == "git"
	out := make([]string, 0, len(argv))
	afterDashDash := false
	for _, arg := range argv {
		if isGitCommand {
			if objectPath, ok := gitObjectPathOperand(arg); ok {
				if gitObjectPathPathSensitive(objectPath) {
					out = append(out, "<redacted>")
				} else {
					out = append(out, renderCommandShapeToken(arg))
				}
				continue
			}
		}
		switch {
		case arg == "--":
			afterDashDash = true
			out = append(out, arg)
		case (afterDashDash || argLooksPathLike(arg)) && ev.safePath(arg, cwd):
			out = append(out, "<safe-path>")
		case isInteger(arg):
			out = append(out, "<number>")
		case looksFieldList(arg):
			out = append(out, "<fields>")
		case LooksSensitive(arg):
			out = append(out, "<redacted>")
		default:
			out = append(out, renderCommandShapeToken(arg))
		}
	}
	return strings.Join(out, " ")
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

func (ev evaluator) evalGit(args []string, cwd string, original []string) Result {
	cwd, args, ok := ev.consumeGitCwd(args, cwd, original)
	if !ok {
		return result(DecisionManual, "git -C path is outside the safe roots", original)
	}
	if len(args) == 0 {
		return result(DecisionManual, "git subcommand is required", original)
	}
	subcommand := args[0]
	rest := args[1:]

	if gitSubcommandIsDestructive(subcommand, rest) {
		return result(DecisionDeny, "destructive git command is not safe", original)
	}
	if argvHasSensitiveValue(rest) {
		return result(DecisionDeny, "git path targets a credential or secret location", original)
	}

	switch subcommand {
	case "status":
		return ev.evalGitStatus(rest, cwd, original)
	case "diff":
		return ev.evalGitDiff(rest, cwd, original)
	case "rev-parse":
		return allowIfOnly(rest, original, "read-only git rev-parse", "--show-toplevel", "--show-current", "--git-dir", "--short", "HEAD")
	case "branch":
		return ev.evalGitBranch(rest, original)
	case "log", "show":
		return ev.evalGitReadOnlyWithOptionalPaths(rest, cwd, original, "read-only git "+subcommand)
	case "worktree":
		return ev.evalGitWorktree(rest, original)
	default:
		return result(DecisionManual, "git subcommand is not in the read-only allow profile", original)
	}
}

func (ev evaluator) consumeGitCwd(args []string, cwd string, original []string) (string, []string, bool) {
	for len(args) >= 2 && args[0] == "-C" {
		if LooksSensitive(args[1]) {
			return "", args, false
		}
		next, ok := ev.safeDir(args[1], cwd)
		if !ok {
			return "", args, false
		}
		cwd = next
		args = args[2:]
	}
	if cwd == "" && len(ev.roots) > 0 {
		cwd = ev.roots[0]
	}
	return cwd, args, true
}

func (ev evaluator) evalGitStatus(args []string, cwd string, original []string) Result {
	return ev.evalFlagsAndOptionalPathspecs(args, cwd, original, "read-only git status", gitStatusAllowedFlags)
}

func (ev evaluator) evalGitDiff(args []string, cwd string, original []string) Result {
	return ev.evalFlagsAndOptionalPathspecs(args, cwd, original, "read-only git diff", gitDiffAllowedFlags)
}

func (ev evaluator) evalGitBranch(args []string, original []string) Result {
	for _, arg := range args {
		if arg == "-D" || arg == "-d" || arg == "-m" || arg == "-M" || arg == "--delete" || arg == "--move" {
			return result(DecisionDeny, "destructive git branch command is not safe", original)
		}
	}
	return allowIfOnly(args, original, "read-only git branch", "--show-current", "--list", "-a", "-r")
}

func (ev evaluator) evalGitWorktree(args []string, original []string) Result {
	if len(args) == 0 || args[0] != "list" {
		return result(DecisionManual, "git worktree command is not in the read-only allow profile", original)
	}
	return allowIfOnly(args[1:], original, "read-only git worktree list", "--porcelain")
}

func (ev evaluator) evalGitReadOnlyWithOptionalPaths(args []string, cwd string, original []string, reason string) Result {
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" {
			afterDashDash = true
			continue
		}
		if afterDashDash {
			if objectPath, ok := gitObjectPathOperand(arg); ok && gitObjectPathPathSensitive(objectPath) {
				return result(DecisionDeny, "git pathspec targets a credential or secret location", original)
			}
			if !ev.safePath(arg, cwd) {
				return result(DecisionManual, "git pathspec is outside the safe roots or uses unsafe patterns", original)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !gitLogShowAllowedFlags[arg] {
				return result(DecisionManual, "git flag is not in the read-only allow profile", original)
			}
			continue
		}
		if objectPath, ok := gitObjectPathOperand(arg); ok {
			if gitObjectPathPathSensitive(objectPath) {
				return result(DecisionDeny, "git object path targets a credential or secret location", original)
			}
			if !gitObjectPathPathSafe(objectPath) {
				return result(DecisionManual, "git object path is outside the read-only allow profile", original)
			}
			continue
		}
		if argLooksPathLike(arg) {
			if !ev.safePath(arg, cwd) {
				return result(DecisionManual, "git path argument is outside the safe roots or uses unsafe patterns", original)
			}
			continue
		}
		if !gitRevisionOperandCovered(arg) {
			return result(DecisionManual, "git revision argument is not in the read-only allow profile", original)
		}
	}
	res := result(DecisionAllow, reason, original)
	res.CommandShape = ev.commandShape(original, cwd)
	return res
}

func (ev evaluator) evalFlagsAndOptionalPathspecs(args []string, cwd string, original []string, reason string, allowedFlags map[string]bool) Result {
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" {
			afterDashDash = true
			continue
		}
		if afterDashDash {
			if !ev.safePath(arg, cwd) {
				return result(DecisionManual, "git pathspec is outside the safe roots or uses unsafe patterns", original)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !allowedFlags[arg] {
				return result(DecisionManual, "git flag is not in the read-only allow profile", original)
			}
			continue
		}
		return result(DecisionManual, "git positional argument requires an explicit -- pathspec", original)
	}
	res := result(DecisionAllow, reason, original)
	res.CommandShape = ev.commandShape(original, cwd)
	return res
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

func allowIfOnly(args []string, original []string, reason string, allowed ...string) Result {
	allowedSet := map[string]bool{}
	for _, item := range allowed {
		allowedSet[item] = true
	}
	for _, arg := range args {
		if !allowedSet[arg] {
			return result(DecisionManual, "git argument is not in the read-only allow profile", original)
		}
	}
	return result(DecisionAllow, reason, original)
}

func gitSubcommandIsDestructive(subcommand string, args []string) bool {
	switch subcommand {
	case "push", "reset", "clean", "commit", "merge", "rebase", "checkout", "switch", "restore", "add", "rm", "mv", "tag":
		return true
	case "branch":
		for _, arg := range args {
			if arg == "-D" || arg == "-d" || arg == "--delete" || arg == "-m" || arg == "-M" || arg == "--move" {
				return true
			}
		}
	case "remote":
		if len(args) > 0 && (args[0] == "add" || args[0] == "remove" || args[0] == "rm" || args[0] == "set-url" || args[0] == "rename") {
			return true
		}
	}
	return false
}

func literalArgs(words []*syntax.Word) ([]string, bool) {
	args := make([]string, 0, len(words))
	for _, word := range words {
		lit, ok := literalWord(word)
		if !ok {
			return nil, false
		}
		args = append(args, lit)
	}
	return args, true
}

func literalWord(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var builder strings.Builder
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			builder.WriteString(typed.Value)
		case *syntax.SglQuoted:
			builder.WriteString(typed.Value)
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				builder.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return builder.String(), true
}

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

func result(decision Decision, reason string, argv []string) Result {
	summary := redactedSummary(argv)
	family := ""
	if len(argv) > 0 {
		family = argv[0]
	}
	return Result{Decision: decision, Reason: reason, Summary: summary, CommandFamily: family}
}

func isInteger(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksFieldList(value string) bool {
	if value == "" || strings.ContainsAny(value, "/\\") {
		return false
	}
	fields := strings.Split(value, ",")
	if len(fields) < 2 {
		return false
	}
	for _, field := range fields {
		if field == "" {
			return false
		}
		for _, r := range field {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

func gitRevisionOperandCovered(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" || value == "<redacted>" || value == "<fields>" {
		return false
	}
	if value == "<number>" {
		return true
	}
	if objectPath, ok := gitObjectPathOperand(value); ok {
		return gitObjectPathPathSafe(objectPath)
	}
	return !LooksSensitive(value) && !unsafePathPattern(value)
}

func builtInReadOnlyUnixFamily(family string) bool {
	if family == "cd" {
		return true
	}
	_, ok := readOnlyUnixProfiles[family]
	return ok
}

func stringSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
