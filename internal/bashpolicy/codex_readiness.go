package bashpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	ReadinessNotConfigured = "not-configured"
	ReadinessOff           = "off"
	ReadinessDegraded      = "degraded"
	ReadinessLogOnly       = "log-only"
	ReadinessBlockingReady = "blocking-ready"
)

type CodexReadiness struct {
	Status           string           `json:"status"`
	BlockingVerified bool             `json:"blocking_verified"`
	Checks           []ReadinessCheck `json:"checks"`
}

type ReadinessCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func AssessCodexReadiness(projectRoot string) CodexReadiness {
	readiness := CodexReadiness{Status: ReadinessLogOnly}
	add := func(name string, ok bool, message string) {
		readiness.Checks = append(readiness.Checks, ReadinessCheck{Name: name, OK: ok, Message: message})
	}

	codexDir := filepath.Join(projectRoot, ".codex")
	if _, err := os.Stat(codexDir); os.IsNotExist(err) {
		return CodexReadiness{
			Status: ReadinessNotConfigured,
			Checks: []ReadinessCheck{{
				Name:    "codex_project_layer",
				OK:      false,
				Message: ".codex directory is not configured",
			}},
		}
	}

	configPath := filepath.Join(codexDir, "config.toml")
	configContent, err := os.ReadFile(configPath)
	if err != nil {
		add("hooks_feature_enabled", false, "cannot read .codex/config.toml")
	} else {
		add("hooks_feature_enabled", codexHooksFeatureEnabled(string(configContent)), "project config must contain [features] hooks = true")
	}

	hooksPath := filepath.Join(codexDir, "hooks.json")
	hooksContent, err := os.ReadFile(hooksPath)
	if err != nil {
		add("hooks_json_present", false, "cannot read .codex/hooks.json")
	} else {
		add("hooks_json_present", true, ".codex/hooks.json is present")
		if codexHooksJSONHasBashPolicyOff(hooksContent) {
			readiness.Status = ReadinessOff
			add("bash_policy_activation", true, "Codex Bash policy activation is explicitly off")
			return readiness
		}
		add("bash_policy_hook_wired", codexHooksJSONHasExpectedCommands(hooksContent), "hooks.json must wire bash-policy evaluate with explicit provider, activation, policy-artifact-root, and safe-root")
	}

	add("blocking_contract_verified", false, "Codex hook blocking semantics are not verified yet; status remains log-only/degraded")

	allInstallChecksOK := true
	for _, check := range readiness.Checks {
		if strings.HasPrefix(check.Name, "blocking_contract") {
			continue
		}
		if !check.OK {
			allInstallChecksOK = false
			break
		}
	}
	if !allInstallChecksOK {
		readiness.Status = ReadinessDegraded
		return readiness
	}
	if readiness.BlockingVerified {
		readiness.Status = ReadinessBlockingReady
		return readiness
	}
	readiness.Status = ReadinessLogOnly
	return readiness
}

func codexHooksFeatureEnabled(content string) bool {
	inFeatures := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(stripTOMLComment(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inFeatures = trimmed == "[features]"
			continue
		}
		if inFeatures && trimmed == "hooks = true" {
			return true
		}
	}
	return false
}

func stripTOMLComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func codexHooksJSONHasExpectedCommands(content []byte) bool {
	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		return false
	}
	for _, command := range preToolUseHookCommands(doc) {
		if info, ok := ParseHookCommand(command); ok && info.Provider == "codex" && !info.Legacy {
			return true
		}
	}
	return false
}

func codexHooksJSONHasBashPolicyOff(content []byte) bool {
	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		return false
	}
	return valueContainsBashPolicyOff(doc)
}

func valueContainsBashPolicyOff(value any) bool {
	for _, command := range preToolUseHookCommands(value) {
		if info, ok := ParseHookCommand(command); ok && info.Provider == "codex" && info.Activation == ActivationOff {
			return true
		}
	}
	return false
}

func preToolUseHookCommands(value any) []string {
	doc, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return nil
	}
	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return nil
	}
	var commands []string
	for _, entry := range preToolUse {
		entryMap, ok := entry.(map[string]any)
		if !ok || !preToolUseEntryMatchesBash(entryMap) {
			continue
		}
		hookList, ok := entryMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, hook := range hookList {
			hookMap, ok := hook.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hookMap["command"].(string); ok {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

func preToolUseEntryMatchesBash(entry map[string]any) bool {
	matcher, ok := entry["matcher"].(string)
	if !ok || strings.TrimSpace(matcher) == "" {
		return true
	}
	matcher = strings.TrimSpace(matcher)
	if matcher == "*" {
		return true
	}
	re, err := regexp.Compile(matcher)
	if err != nil {
		return false
	}
	return re.MatchString("Bash")
}
