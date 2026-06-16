package bashpolicy

import (
	"strings"
)

func (ev evaluator) evalEnvSafetyFloor(args []string, cwd string, original []string) Result {
	_, wrapped, res, ok := parseEnvLauncher(args, original)
	if res.Decision != "" || !ok {
		return res
	}
	return ev.evalSafetyFloor(wrapped, cwd)
}

func (ev evaluator) evalEnv(argv []string, cwd string) Result {
	assignments, wrapped, res, ok := parseEnvLauncher(argv[1:], argv)
	if res.Decision != "" || !ok {
		return res
	}
	wrappedResult := ev.evalArgv(wrapped, cwd)
	wrappedResult.CommandFamily = "env"
	if wrappedResult.Summary != "" {
		wrappedResult.Summary = redactedSummary(append(append([]string{"env"}, assignments...), wrapped...))
	}
	if wrappedResult.Decision == DecisionAllow {
		wrappedResult.Reason = "env launcher around " + wrappedResult.Reason
	}
	return wrappedResult
}

func parseEnvLauncher(args []string, original []string) ([]string, []string, Result, bool) {
	if len(args) == 0 {
		return nil, nil, result(DecisionDeny, "environment dump commands are not safe", original), false
	}
	assignments := []string{}
	for len(args) > 0 {
		name, value, ok := envAssignment(args[0])
		if !ok {
			break
		}
		if LooksSensitive(name) || LooksSensitive(value) {
			return assignments, nil, result(DecisionDeny, "env assignment looks credential-related", original), false
		}
		if dangerousEnvLauncherAssignment(name) {
			return assignments, nil, result(DecisionDeny, "env assignment can alter command loading or configuration", original), false
		}
		if !safeEnvLauncherAssignment(name) {
			return assignments, nil, result(DecisionManual, "env assignment is not in the safe launcher profile", original), false
		}
		assignments = append(assignments, args[0])
		args = args[1:]
	}
	if len(args) == 0 {
		return assignments, nil, result(DecisionDeny, "environment dump commands are not safe", original), false
	}
	if strings.HasPrefix(args[0], "-") {
		return assignments, nil, result(DecisionManual, "env options are not in the safe launcher profile", original), false
	}
	return assignments, args, Result{}, true
}

func envAssignment(arg string) (string, string, bool) {
	name, value, ok := strings.Cut(arg, "=")
	if !ok || !validEnvName(name) {
		return "", "", false
	}
	return name, value, true
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func safeEnvLauncherAssignment(name string) bool {
	switch name {
	case "GOCACHE", "GOMODCACHE":
		return true
	default:
		return false
	}
}

func dangerousEnvLauncherAssignment(name string) bool {
	switch name {
	case "PATH", "IFS",
		"LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
		"DYLD_FRAMEWORK_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
		"BASH_ENV", "ENV",
		"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_SSH_COMMAND":
		return true
	default:
		return false
	}
}
