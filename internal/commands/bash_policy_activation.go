package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liza-mas/bash-policy/internal/bashpolicy"
	"github.com/liza-mas/bash-policy/internal/embedded"
)

func updateClaudeBashPolicyActivation(projectRoot string, policyRoot string, hookCommand string, activation string, commandOverride bool) error {
	settingsPath := filepath.Join(projectRoot, ".claude", "settings.json")
	doc, err := readJSONObject(settingsPath)
	if err != nil {
		return err
	}
	command := embedded.ProviderHookCommand(hookCommand, "claude", activation, policyRoot)
	upsertHookCommand(doc, "PreToolUse", "Bash", "claude", activation, command, commandOverride, "Evaluating Bash command policy")
	return writeJSONObject(settingsPath, doc)
}

func updateCodexBashPolicyActivation(projectRoot string, policyRoot string, hookCommand string, activation string, commandOverride bool) error {
	hooksPath := filepath.Join(projectRoot, ".codex", "hooks.json")
	doc, err := readJSONObject(hooksPath)
	if err != nil {
		return err
	}
	command := embedded.ProviderHookCommand(hookCommand, "codex", activation, policyRoot)
	upsertHookCommand(doc, "PreToolUse", "^Bash$", "codex", activation, command, commandOverride, "Evaluating Bash command policy")
	return writeJSONObject(hooksPath, doc)
}

func updateCursorBashPolicyActivation(projectRoot string, policyRoot string, hookCommand string, activation string, commandOverride bool) error {
	hooksPath := filepath.Join(projectRoot, ".cursor", "hooks.json")
	doc, err := readJSONObject(hooksPath)
	if err != nil {
		return err
	}
	command := embedded.ProviderHookCommand(hookCommand, "cursor", activation, policyRoot)
	upsertCursorHookCommand(doc, "beforeShellExecution", "cursor", activation, command, commandOverride)
	return writeJSONObject(hooksPath, doc)
}

func readJSONObject(path string) (map[string]any, error) {
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}

func writeJSONObject(path string, doc map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s directory: %w", path, err)
	}
	content, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	return os.WriteFile(path, append(content, '\n'), 0o644)
}

func upsertHookCommand(doc map[string]any, event string, matcher string, provider string, activation string, command string, commandOverride bool, statusMessage string) {
	if replaceExistingHookActivation(doc, provider, activation, command, commandOverride) {
		return
	}
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	entries, _ := hooks[event].([]any)
	entry := map[string]any{
		"matcher": matcher,
		"hooks": []any{map[string]any{
			"command":       command,
			"statusMessage": statusMessage,
			"timeout":       float64(5),
			"type":          "command",
		}},
	}
	entries = append(entries, entry)
	hooks[event] = entries
}

func upsertCursorHookCommand(doc map[string]any, event string, provider string, activation string, command string, commandOverride bool) {
	if replaceExistingHookActivation(doc, provider, activation, command, commandOverride) {
		pruneLegacyCursorHookCommands(doc)
		return
	}
	pruneLegacyCursorHookCommands(doc)
	hooks, _ := doc["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
		doc["hooks"] = hooks
	}
	entries, _ := hooks[event].([]any)
	entries = append(entries, map[string]any{
		"command":    command,
		"failClosed": true,
	})
	hooks[event] = entries
}

func replaceExistingHookActivation(value any, provider string, activation string, command string, commandOverride bool) bool {
	replaced := false
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			if raw, ok := typed["command"].(string); ok && isBashPolicyProviderCommand(raw, provider) {
				if commandOverride {
					typed["command"] = command
				} else {
					typed["command"] = replaceProviderActivation(raw, provider, activation)
				}
				replaced = true
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return replaced
}

func pruneLegacyCursorHookCommands(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if list, ok := child.([]any); ok {
				filtered := make([]any, 0, len(list))
				for _, item := range list {
					if !containsLegacyCursorHookCommand(item) {
						filtered = append(filtered, item)
					}
				}
				typed[key] = filtered
				continue
			}
			pruneLegacyCursorHookCommands(child)
		}
	case []any:
		for _, child := range typed {
			pruneLegacyCursorHookCommands(child)
		}
	}
}

func containsLegacyCursorHookCommand(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		if command, ok := typed["command"].(string); ok && isLegacyCursorHookCommand(command) {
			return true
		}
		for _, child := range typed {
			if containsLegacyCursorHookCommand(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsLegacyCursorHookCommand(child) {
				return true
			}
		}
	}
	return false
}

func isLegacyCursorHookCommand(command string) bool {
	return strings.Contains(command, ".cursor/hooks/cursor-bash-policy.sh")
}

func isBashPolicyProviderCommand(command string, provider string) bool {
	info, ok := bashpolicy.ParseHookCommand(command)
	return ok && info.Provider == provider
}

func replaceProviderActivation(command string, provider string, activation string) string {
	info, ok := bashpolicy.ParseHookCommand(command)
	if !ok || info.Provider != provider {
		return command
	}
	if rewritten, ok := bashpolicy.RewriteHookCommandActivation(command, activation); ok {
		return rewritten
	}
	return command
}
