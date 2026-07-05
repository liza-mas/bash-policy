package bashpolicy

import (
	"strings"
)

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

	if ev.gitSubcommandIsDestructive(subcommand, rest, cwd) {
		return result(DecisionDeny, "non-reversible git command is not safe", original)
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
			if !ev.safeGitPathspec(arg, cwd) {
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

func (ev evaluator) gitSubcommandIsDestructive(subcommand string, args []string, cwd string) bool {
	switch subcommand {
	case "push":
		return gitPushDeletesOrForces(args)
	case "reset":
		return gitResetDiscardsWorktree(args)
	case "clean":
		return !gitHasDryRun(args)
	case "restore":
		return gitRestoreDiscardsWorktree(args)
	case "checkout":
		return ev.gitCheckoutDiscardsWorktree(args, cwd)
	case "switch":
		return gitSwitchDiscardsWorktree(args)
	case "rm":
		return gitRMDiscardsWorktree(args)
	}
	return false
}

func gitPushDeletesOrForces(args []string) bool {
	if gitHasDryRun(args) {
		return false
	}
	for _, arg := range args {
		if arg == "--force" || arg == "--force-with-lease" || strings.HasPrefix(arg, "--force-with-lease=") ||
			arg == "--force-if-includes" || arg == "--delete" || arg == "--mirror" || arg == "--prune" {
			return true
		}
		if shortGitFlagContainsAny(arg, "df") {
			return true
		}
		if strings.HasPrefix(arg, "+") || strings.HasPrefix(arg, ":") {
			return true
		}
	}
	return false
}

func gitResetDiscardsWorktree(args []string) bool {
	for _, arg := range args {
		if arg == "--hard" || arg == "--merge" {
			return true
		}
	}
	return false
}

func gitRestoreDiscardsWorktree(args []string) bool {
	staged := false
	worktree := false
	for _, arg := range args {
		if arg == "--staged" || shortGitFlagContainsAny(arg, "S") {
			staged = true
		}
		if arg == "--worktree" || shortGitFlagContainsAny(arg, "W") {
			worktree = true
		}
	}
	return worktree || !staged
}

func (ev evaluator) gitCheckoutDiscardsWorktree(args []string, cwd string) bool {
	positionals := []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return len(args) > i+1
		}
		if arg == "--force" || arg == "--pathspec-from-file" || strings.HasPrefix(arg, "--pathspec-from-file=") ||
			shortGitFlagContainsAny(arg, "f") {
			return true
		}
		if strings.HasPrefix(arg, "-") {
			if gitCheckoutFlagNeedsValue(arg) {
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if len(positionals) > 1 {
		return true
	}
	return len(positionals) == 1 && ev.gitCheckoutOperandLooksPathspec(positionals[0], cwd)
}

func gitCheckoutFlagNeedsValue(arg string) bool {
	switch arg {
	case "-b", "-B", "--orphan", "--conflict":
		return true
	default:
		return false
	}
}

func (ev evaluator) gitCheckoutOperandLooksPathspec(arg string, cwd string) bool {
	if arg == "" || arg == "-" {
		return false
	}
	return arg == "." ||
		strings.HasPrefix(arg, "./") ||
		strings.HasPrefix(arg, "../") ||
		strings.HasPrefix(arg, "/") ||
		strings.HasPrefix(arg, "~") ||
		ev.safeExistingPath(arg, cwd)
}

func gitSwitchDiscardsWorktree(args []string) bool {
	for _, arg := range args {
		if arg == "--force" || arg == "--discard-changes" || shortGitFlagContainsAny(arg, "f") {
			return true
		}
	}
	return false
}

func gitRMDiscardsWorktree(args []string) bool {
	for _, arg := range args {
		if arg == "--force" || shortGitFlagContainsAny(arg, "f") {
			return true
		}
	}
	return false
}

func gitHasDryRun(args []string) bool {
	for _, arg := range args {
		if arg == "--dry-run" || shortGitFlagContainsAny(arg, "n") {
			return true
		}
	}
	return false
}

func shortGitFlagContainsAny(arg string, flags string) bool {
	return strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1 && strings.ContainsAny(arg[1:], flags)
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
