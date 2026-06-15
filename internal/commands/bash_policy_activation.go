package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func updateClaudeBashPolicyActivation(projectRoot string, activation string) error {
	settingsPath := filepath.Join(projectRoot, ".claude", "settings.json")
	doc, err := readJSONObject(settingsPath)
	if err != nil {
		return err
	}
	command := `bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude ` + activation
	upsertHookCommand(doc, "PreToolUse", "Bash", "claude", activation, command, "Evaluating Bash command policy")
	return writeJSONObject(settingsPath, doc)
}

func updateCodexBashPolicyActivation(projectRoot string, activation string) error {
	hooksPath := filepath.Join(projectRoot, ".codex", "hooks.json")
	doc, err := readJSONObject(hooksPath)
	if err != nil {
		return err
	}
	command := `root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0; hook="$root/.codex/hooks/bash-policy.sh"; [ -x "$hook" ] || { echo "Missing Liza Codex hook: $hook. Run 'liza init --codex' to repair project hooks, or remove .codex/hooks.json to disable them." >&2; exit 1; }; bash "$hook" codex ` + activation
	upsertHookCommand(doc, "PreToolUse", "^Bash$", "codex", activation, command, "Evaluating Bash command policy")
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

func upsertHookCommand(doc map[string]any, event string, matcher string, provider string, activation string, command string, statusMessage string) {
	if replaceExistingHookActivation(doc, provider, activation) {
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

func replaceExistingHookActivation(value any, provider string, activation string) bool {
	replaced := false
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			if raw, ok := typed["command"].(string); ok && isBashPolicyProviderCommand(raw, provider) {
				typed["command"] = replaceProviderActivation(raw, provider, activation)
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

func isBashPolicyProviderCommand(command string, provider string) bool {
	return strings.Contains(command, "bash-policy.sh") && strings.Contains(command, " "+provider)
}

func replaceProviderActivation(command string, provider string, activation string) string {
	for _, old := range []string{"audit", "allow", "dry-run", "on", "off"} {
		needle := " " + provider + " " + old
		if strings.Contains(command, needle) {
			return strings.Replace(command, needle, " "+provider+" "+activation, 1)
		}
	}
	if strings.HasSuffix(command, " "+provider) {
		return command + " " + activation
	}
	return command
}
