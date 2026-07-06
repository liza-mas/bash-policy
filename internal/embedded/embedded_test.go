package embedded

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestWriteClaudeSettingsInstallsOnlyBashPolicyAssets(t *testing.T) {
	projectRoot := t.TempDir()

	if err := WriteClaudeSettings(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	settingsContent, err := os.ReadFile(filepath.Join(projectRoot, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(settingsContent, &settings); err != nil {
		t.Fatalf("settings JSON is invalid: %v\n%s", err, string(settingsContent))
	}
	assertOnlyBashPolicyCommands(t, settings)
}

func TestWriteClaudeSettingsMergesExistingHookActivation(t *testing.T) {
	projectRoot := t.TempDir()
	settingsPath := filepath.Join(projectRoot, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh\" claude off","timeout":5}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteClaudeSettings(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("y\n"))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	content, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "--mode off") {
		t.Fatalf("existing activation was not preserved:\n%s", text)
	}
	if strings.Contains(text, "bash-policy.sh") {
		t.Fatalf("legacy wrapper hook was not migrated:\n%s", text)
	}
	if strings.Count(text, "bash-policy evaluate") != 1 {
		t.Fatalf("bash-policy hook should not be duplicated:\n%s", text)
	}
}

func TestWriteClaudeSettingsExcludesBashPolicyArtifacts(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepoForEmbeddedTest(t, projectRoot)

	if err := WriteClaudeSettings(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, projectRoot)
}

func TestWriteClaudeSettingsExcludesArtifactsAtPolicyRoot(t *testing.T) {
	projectRoot := t.TempDir()
	policyRoot := t.TempDir()
	initGitRepoForEmbeddedTest(t, policyRoot)

	if err := WriteClaudeSettings(projectRoot, policyRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, policyRoot)
}

func TestWriteCodexProjectHooksInstallsOnlyBashPolicyAssets(t *testing.T) {
	projectRoot := t.TempDir()

	if err := WriteCodexProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteCodexProjectHooks failed: %v", err)
	}

	configContent, err := os.ReadFile(filepath.Join(projectRoot, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(configContent) != "[features]\nhooks = true\n" {
		t.Fatalf("unexpected Codex config:\n%s", string(configContent))
	}

	hooksContent, err := os.ReadFile(filepath.Join(projectRoot, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks map[string]any
	if err := json.Unmarshal(hooksContent, &hooks); err != nil {
		t.Fatalf("hooks JSON is invalid: %v\n%s", err, string(hooksContent))
	}
	text := string(hooksContent)
	if !strings.Contains(text, "bash-policy evaluate") || !strings.Contains(text, `"matcher": "^Bash$"`) {
		t.Fatalf("hooks JSON missing bash-policy hook:\n%s", text)
	}
	assertOnlyBashPolicyCommands(t, hooks)
}

func TestWriteCodexProjectHooksMergesExistingFiles(t *testing.T) {
	projectRoot := t.TempDir()
	codexDir := filepath.Join(projectRoot, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("model = \"gpt-5\"\n[features]\nother = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	existingHooks := `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}`
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(existingHooks), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCodexProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("y\ny\n"))); err != nil {
		t.Fatalf("WriteCodexProjectHooks failed: %v", err)
	}

	configContent, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"model = \"gpt-5\"", "[features]", "other = true", "hooks = true"} {
		if !strings.Contains(string(configContent), want) {
			t.Fatalf("config missing %q:\n%s", want, string(configContent))
		}
	}

	hooksContent, err := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(hooksContent)
	for _, want := range []string{"echo done", "bash-policy evaluate"} {
		if !strings.Contains(text, want) {
			t.Fatalf("hooks JSON missing %q:\n%s", want, text)
		}
	}
}

func TestWriteCodexProjectHooksDeclineLeavesFilesUntouched(t *testing.T) {
	projectRoot := t.TempDir()
	codexDir := filepath.Join(projectRoot, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	originalConfig := "model = \"gpt-5\"\n"
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(originalConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCodexProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("n\n"))); err != nil {
		t.Fatalf("WriteCodexProjectHooks failed: %v", err)
	}

	configContent, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(configContent) != originalConfig {
		t.Fatalf("config changed despite declined merge:\n%s", string(configContent))
	}
	if _, err := os.Stat(filepath.Join(codexDir, "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("hooks.json should not be written, stat err: %v", err)
	}
}

func TestWriteCodexProjectHooksExcludesBashPolicyArtifacts(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepoForEmbeddedTest(t, projectRoot)

	if err := WriteCodexProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteCodexProjectHooks failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, projectRoot)
}

func TestWriteCursorProjectHooksInstallsOnlyBashPolicyAssets(t *testing.T) {
	projectRoot := t.TempDir()

	if err := WriteCursorProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteCursorProjectHooks failed: %v", err)
	}

	hooksContent, err := os.ReadFile(filepath.Join(projectRoot, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hooks map[string]any
	if err := json.Unmarshal(hooksContent, &hooks); err != nil {
		t.Fatalf("hooks JSON is invalid: %v\n%s", err, string(hooksContent))
	}
	text := string(hooksContent)
	for _, want := range []string{"beforeShellExecution", "bash-policy evaluate", "--provider cursor", "--mode dry-run", `"failClosed": true`} {
		if !strings.Contains(text, want) {
			t.Fatalf("Cursor hooks JSON missing %q:\n%s", want, text)
		}
	}
	assertOnlyBashPolicyCommands(t, hooks)
}

func TestWriteCursorProjectHooksMergesExistingHooksAndMigratesLegacyWrapper(t *testing.T) {
	projectRoot := t.TempDir()
	cursorDir := filepath.Join(projectRoot, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existingHooks := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"./hooks/allow.sh"},{"command":"bash .cursor/hooks/cursor-bash-policy.sh","failClosed":true}],"afterShellExecution":[{"command":"./hooks/cleanup.sh"}]}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "hooks.json"), []byte(existingHooks), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCursorProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("y\n"))); err != nil {
		t.Fatalf("WriteCursorProjectHooks failed: %v", err)
	}

	hooksContent, err := os.ReadFile(filepath.Join(cursorDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(hooksContent)
	for _, want := range []string{"./hooks/allow.sh", "./hooks/cleanup.sh", "--provider cursor", "--mode dry-run"} {
		if !strings.Contains(text, want) {
			t.Fatalf("merged Cursor hooks JSON missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "cursor-bash-policy.sh") {
		t.Fatalf("legacy Cursor wrapper should be replaced by direct bash-policy hook:\n%s", text)
	}
}

func TestWriteCursorProjectHooksPreservesExistingActivation(t *testing.T) {
	projectRoot := t.TempDir()
	cursorDir := filepath.Join(projectRoot, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	existingHooks := `{"version":1,"hooks":{"beforeShellExecution":[{"command":"/opt/wrapper evaluate --provider cursor --mode on --policy-artifact-root /project --safe-root \"$PWD\"","failClosed":true}]}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "hooks.json"), []byte(existingHooks), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCursorProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("y\n"))); err != nil {
		t.Fatalf("WriteCursorProjectHooks failed: %v", err)
	}

	hooksContent, err := os.ReadFile(filepath.Join(cursorDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(hooksContent)
	if !strings.Contains(text, "/usr/local/bin/bash-policy evaluate") || !strings.Contains(text, "--provider cursor") || !strings.Contains(text, "--mode on") {
		t.Fatalf("existing Cursor activation should be preserved on managed command:\n%s", text)
	}
	if strings.Contains(text, "/opt/wrapper") {
		t.Fatalf("renamed Cursor command should be migrated to managed command:\n%s", text)
	}
}

func TestWriteCursorProjectHooksDeclineLeavesFileUntouched(t *testing.T) {
	projectRoot := t.TempDir()
	cursorDir := filepath.Join(projectRoot, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	originalHooks := `{"version":1,"hooks":{}}`
	if err := os.WriteFile(filepath.Join(cursorDir, "hooks.json"), []byte(originalHooks), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCursorProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader("n\n"))); err != nil {
		t.Fatalf("WriteCursorProjectHooks failed: %v", err)
	}

	hooksContent, err := os.ReadFile(filepath.Join(cursorDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(hooksContent) != originalHooks {
		t.Fatalf("Cursor hooks changed despite declined merge:\n%s", string(hooksContent))
	}
}

func TestWriteCursorProjectHooksExcludesBashPolicyArtifacts(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepoForEmbeddedTest(t, projectRoot)

	if err := WriteCursorProjectHooks(projectRoot, projectRoot, "/usr/local/bin/bash-policy", bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteCursorProjectHooks failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, projectRoot)
}

func TestMergeSettingsDeduplicatesBashPolicyHookActivation(t *testing.T) {
	managed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`/usr/local/bin/bash-policy evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`)},
		},
	}
	existing := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude on`)},
		},
	}

	merged := mergeSettings(managed, existing)
	entries := merged["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1: %+v", len(entries), entries)
	}
	if got := hookCommands(entries[0])[0]; !strings.Contains(got, "--mode on") || strings.Contains(got, "bash-policy.sh") {
		t.Fatalf("existing activation should win, got %q", got)
	}
}

func TestMergeSettingsDeduplicatesRenamedBashPolicyCommand(t *testing.T) {
	managed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`/usr/local/bin/bash-policy evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`)},
		},
	}
	existing := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`/opt/wrapper evaluate --provider claude --mode on --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`)},
		},
	}

	merged := mergeSettings(managed, existing)
	entries := merged["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1: %+v", len(entries), entries)
	}
	got := hookCommands(entries[0])[0]
	if !strings.Contains(got, "bash-policy evaluate") || !strings.Contains(got, "--mode on") || strings.Contains(got, "/opt/wrapper") {
		t.Fatalf("managed command should be deduplicated with existing renamed activation, got %q", got)
	}
}

func TestMergeSettingsPreservesUnrelatedEvaluateProviderHook(t *testing.T) {
	managed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`/usr/local/bin/bash-policy evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`)},
		},
	}
	existing := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`/opt/tool evaluate --provider claude --mode on`)},
		},
	}

	merged := mergeSettings(managed, existing)
	entries := merged["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want managed and unrelated hooks: %+v", len(entries), entries)
	}
	commands := append(hookCommands(entries[0]), hookCommands(entries[1])...)
	if !slices.Contains(commands, `/opt/tool evaluate --provider claude --mode on`) {
		t.Fatalf("unrelated provider hook missing after merge: %+v", commands)
	}
}

func hookEntry(command string) map[string]any {
	return map[string]any{
		"matcher": "Bash",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
			"timeout": float64(5),
		}},
	}
}

func assertOnlyBashPolicyCommands(t *testing.T, value any) {
	t.Helper()
	commands := collectHookCommands(value)
	if len(commands) == 0 {
		t.Fatal("no hook commands found")
	}
	for _, command := range commands {
		for _, want := range []string{"bash-policy evaluate", "--policy-artifact-root", "--safe-root"} {
			if !strings.Contains(command, want) {
				t.Fatalf("bash-policy hook command missing %q: %s", want, command)
			}
		}
		if strings.Contains(command, "bash-policy.sh") {
			t.Fatalf("unexpected non-bash-policy hook command: %s", command)
		}
	}
}

func collectHookCommands(value any) []string {
	switch typed := value.(type) {
	case map[string]any:
		var commands []string
		if command, ok := typed["command"].(string); ok {
			commands = append(commands, command)
		}
		for _, child := range typed {
			commands = append(commands, collectHookCommands(child)...)
		}
		return commands
	case []any:
		var commands []string
		for _, child := range typed {
			commands = append(commands, collectHookCommands(child)...)
		}
		return commands
	default:
		return nil
	}
}

func initGitRepoForEmbeddedTest(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("git", "init")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init failed: %v\n%s", err, string(output))
	}
}

func assertBashPolicyArtifactsExcluded(t *testing.T, projectRoot string) {
	t.Helper()
	excludePath := filepath.Join(projectRoot, ".git", "info", "exclude")
	content, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("read git exclude: %v", err)
	}
	text := string(content)
	for _, want := range []string{
		".bash-policy-dry-run.jsonl",
		".bash-policy-dry-run.jsonl.lock",
		".bash-policy-dry-run.jsonl.lock.owner.json",
		".bash-policy-candidates.yaml",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("git exclude missing %q:\n%s", want, text)
		}
	}
}
