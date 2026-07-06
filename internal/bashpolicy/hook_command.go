package bashpolicy

import "strings"

type HookCommand struct {
	Provider           string
	Activation         string
	PolicyArtifactRoot string
	SafeRoot           string
	Legacy             bool
}

func ParseHookCommand(command string) (HookCommand, bool) {
	// strings.Fields is enough for token presence checks here, but it is not
	// shell-quote-aware. Path-like values are presence-checked only.
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return HookCommand{}, false
	}
	if info, ok := parseStandaloneHookCommand(fields); ok {
		return info, true
	}
	return parseLegacyHookCommand(command, fields)
}

func RewriteHookCommandActivation(command string, activation string) (string, bool) {
	activation, err := NormalizeActivation(activation)
	if err != nil {
		return "", false
	}
	info, ok := ParseHookCommand(command)
	if !ok {
		return "", false
	}
	if info.Legacy {
		return replaceHookToken(command, info.Provider+" "+info.Activation, info.Provider+" "+activation)
	}
	return replaceHookFlagValue(command, "--mode", info.Activation, activation)
}

func parseStandaloneHookCommand(fields []string) (HookCommand, bool) {
	if !hookHasField(fields, "evaluate") {
		return HookCommand{}, false
	}
	info := HookCommand{
		Provider:           hookFlagValue(fields, "--provider"),
		Activation:         hookFlagValue(fields, "--mode"),
		PolicyArtifactRoot: hookFlagValue(fields, "--policy-artifact-root"),
		SafeRoot:           hookFlagValue(fields, "--safe-root"),
	}
	if !isHookProvider(info.Provider) || !isHookActivation(info.Activation) {
		return HookCommand{}, false
	}
	if info.PolicyArtifactRoot == "" || info.SafeRoot == "" {
		return HookCommand{}, false
	}
	return info, true
}

func parseLegacyHookCommand(command string, fields []string) (HookCommand, bool) {
	if !strings.Contains(command, "bash-policy.sh") {
		return HookCommand{}, false
	}
	for i, field := range fields {
		provider := trimHookToken(field)
		if !isHookProvider(provider) || i+1 >= len(fields) {
			continue
		}
		activation := trimHookToken(fields[i+1])
		if !isHookActivation(activation) {
			continue
		}
		return HookCommand{Provider: provider, Activation: activation, Legacy: true}, true
	}
	return HookCommand{}, false
}

func hookHasField(fields []string, want string) bool {
	for _, field := range fields {
		if trimHookToken(field) == want {
			return true
		}
	}
	return false
}

func hookFlagValue(fields []string, flag string) string {
	for i, field := range fields {
		field = trimHookToken(field)
		if field == flag && i+1 < len(fields) {
			return hookValueToken(fields[i+1])
		}
		if strings.HasPrefix(field, flag+"=") {
			return hookValueToken(strings.TrimPrefix(field, flag+"="))
		}
	}
	return ""
}

func hookValueToken(value string) string {
	value = trimHookToken(value)
	if value == "" || strings.HasPrefix(value, "--") {
		return ""
	}
	return value
}

func replaceHookFlagValue(command string, flag string, oldValue string, newValue string) (string, bool) {
	for _, old := range hookValueSpellings(oldValue) {
		if strings.Contains(command, flag+" "+old) {
			return strings.Replace(command, flag+" "+old, flag+" "+newValue, 1), true
		}
		if strings.Contains(command, flag+"="+old) {
			return strings.Replace(command, flag+"="+old, flag+"="+newValue, 1), true
		}
	}
	return "", false
}

func replaceHookToken(command string, oldToken string, newToken string) (string, bool) {
	if strings.Contains(command, oldToken) {
		return strings.Replace(command, oldToken, newToken, 1), true
	}
	return "", false
}

func hookValueSpellings(value string) []string {
	return []string{value, `"` + value + `"`, `'` + value + `'`}
}

func isHookProvider(value string) bool {
	return value == "claude" || value == "codex" || value == "cursor"
}

func isHookActivation(value string) bool {
	switch value {
	case ActivationOn, ActivationDryRun, ActivationOff:
		return true
	default:
		return false
	}
}

func trimHookToken(value string) string {
	value = strings.Trim(value, `"'`)
	value = strings.TrimSuffix(value, ";")
	return value
}
