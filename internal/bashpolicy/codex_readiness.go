package bashpolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
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
		add("expected_hooks_wired", codexHooksJSONHasExpectedCommands(hooksContent), "hooks.json must wire session-context, enforce-init, git-guard, rtk-guard, bash-policy, and worktree-path-guard")
	}

	hooksDir := filepath.Join(codexDir, "hooks")
	for _, name := range []string{"enforce-init.sh", "session-context.sh", "git-guard.sh", "rtk-guard.sh", "bash-policy.sh", "worktree-path-guard.sh"} {
		path := filepath.Join(hooksDir, name)
		info, err := os.Stat(path)
		ok := err == nil && !info.IsDir() && info.Mode()&0111 != 0
		add("hook_file_"+name, ok, name+" must exist and be executable")
	}

	add("blocking_contract_verified", false, "Codex hook blocking semantics are not verified by Liza yet; status remains log-only/degraded")

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
	text := string(content)
	for _, want := range []string{"session-context.sh", "enforce-init.sh", "git-guard.sh", "rtk-guard.sh", "bash-policy.sh", "worktree-path-guard.sh"} {
		if !strings.Contains(text, want) {
			return false
		}
	}
	return true
}

func codexHooksJSONHasBashPolicyOff(content []byte) bool {
	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		return false
	}
	return valueContainsBashPolicyOff(doc)
}

func valueContainsBashPolicyOff(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if command, ok := typed["command"].(string); ok {
			return strings.Contains(command, "bash-policy.sh") &&
				strings.Contains(command, " codex off")
		}
		for _, child := range typed {
			if valueContainsBashPolicyOff(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if valueContainsBashPolicyOff(child) {
				return true
			}
		}
	}
	return false
}
