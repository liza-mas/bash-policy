package bashpolicy

func (ev evaluator) evalSafetyFloor(argv []string, cwd string) Result {
	if len(argv) == 0 {
		return Result{}
	}
	switch argv[0] {
	case "printenv":
		return result(DecisionDeny, "environment dump commands are not safe", argv)
	case "env":
		return ev.evalEnvSafetyFloor(argv[1:], cwd, argv)
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
		if len(rest) > 0 && ev.gitSubcommandIsDestructive(rest[0], rest[1:], nextCWD) {
			return result(DecisionDeny, "non-reversible git command is not safe", argv)
		}
		if argvHasSensitiveValue(rest) {
			return result(DecisionDeny, "git path targets a credential or secret location", argv)
		}
		if len(rest) > 0 && rest[0] == "grep" {
			if floor := ev.evalGitGrepSafetyFloor(rest[1:], nextCWD, argv); floor.Decision != "" {
				return floor
			}
			return Result{}
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
	case "grep":
		if floor := evalGrepSafetyFloor(argv[1:], argv); floor.Decision != "" {
			return floor
		}
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
