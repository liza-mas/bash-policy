package bashpolicy

import (
	"path/filepath"
	"strings"
)

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

func builtInReadOnlyUnixFamily(family string) bool {
	if family == "cd" {
		return true
	}
	_, ok := readOnlyUnixProfiles[family]
	return ok
}
