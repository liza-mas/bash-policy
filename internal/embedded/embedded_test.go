package embedded

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteClaudeSettingsInstallsOnlyBashPolicyAssets(t *testing.T) {
	projectRoot := t.TempDir()

	if err := WriteClaudeSettings(projectRoot, bufio.NewReader(strings.NewReader(""))); err != nil {
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
	assertHookScripts(t, filepath.Join(projectRoot, ".claude", "hooks"))
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

	if err := WriteClaudeSettings(projectRoot, bufio.NewReader(strings.NewReader("y\n"))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	content, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, " claude off") {
		t.Fatalf("existing activation was not preserved:\n%s", text)
	}
	if strings.Count(text, "bash-policy.sh") != 1 {
		t.Fatalf("bash-policy hook should not be duplicated:\n%s", text)
	}
}

func TestWriteClaudeSettingsExcludesBashPolicyArtifacts(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepoForEmbeddedTest(t, projectRoot)

	if err := WriteClaudeSettings(projectRoot, bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteClaudeSettings failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, projectRoot)
}

func TestWriteHooksOverwritesOnlyBashPolicyHook(t *testing.T) {
	projectRoot := t.TempDir()
	hooksDir := filepath.Join(projectRoot, ".claude", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "bash-policy.sh"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := WriteHooks(projectRoot); err != nil {
		t.Fatalf("WriteHooks failed: %v", err)
	}

	assertHookScripts(t, hooksDir)
	assertOnlyHookNames(t, hooksDir, "bash-policy.sh")
}

func TestWriteCodexProjectHooksInstallsOnlyBashPolicyAssets(t *testing.T) {
	projectRoot := t.TempDir()

	if err := WriteCodexProjectHooks(projectRoot, bufio.NewReader(strings.NewReader(""))); err != nil {
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
	if !strings.Contains(text, ".codex/hooks/bash-policy.sh") || !strings.Contains(text, `"matcher": "^Bash$"`) {
		t.Fatalf("hooks JSON missing bash-policy hook:\n%s", text)
	}
	assertOnlyBashPolicyCommands(t, hooks)
	assertHookScripts(t, filepath.Join(projectRoot, ".codex", "hooks"))
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

	if err := WriteCodexProjectHooks(projectRoot, bufio.NewReader(strings.NewReader("y\ny\n"))); err != nil {
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
	for _, want := range []string{"echo done", ".codex/hooks/bash-policy.sh"} {
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

	if err := WriteCodexProjectHooks(projectRoot, bufio.NewReader(strings.NewReader("n\n"))); err != nil {
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

	if err := WriteCodexProjectHooks(projectRoot, bufio.NewReader(strings.NewReader(""))); err != nil {
		t.Fatalf("WriteCodexProjectHooks failed: %v", err)
	}

	assertBashPolicyArtifactsExcluded(t, projectRoot)
}

func TestWriteCodexHooksOverwritesOnlyBashPolicyHook(t *testing.T) {
	projectRoot := t.TempDir()
	hooksDir := filepath.Join(projectRoot, ".codex", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, "bash-policy.sh"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := WriteCodexHooks(projectRoot); err != nil {
		t.Fatalf("WriteCodexHooks failed: %v", err)
	}

	assertHookScripts(t, hooksDir)
	assertOnlyHookNames(t, hooksDir, "bash-policy.sh")
}

func TestMergeSettingsDeduplicatesBashPolicyHookActivation(t *testing.T) {
	managed := map[string]any{
		"hooks": map[string]any{
			"PreToolUse": []any{hookEntry(`bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude dry-run`)},
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
	if got := hookCommands(entries[0])[0]; !strings.Contains(got, " claude on") {
		t.Fatalf("existing activation should win, got %q", got)
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

func assertHookScripts(t *testing.T, hooksDir string) {
	t.Helper()
	for name, wantContent := range hookScriptContents() {
		hookPath := filepath.Join(hooksDir, name)
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Fatalf("hook file %s not found: %v", name, err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("hook file %s is not executable: %v", name, info.Mode())
		}
		content, err := os.ReadFile(hookPath)
		if err != nil {
			t.Fatalf("failed to read hook %s: %v", name, err)
		}
		if !bytes.Equal(content, wantContent) {
			t.Fatalf("hook %s content does not match embedded source", name)
		}
	}
}

func assertOnlyHookNames(t *testing.T, hooksDir string, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool)
	for _, name := range names {
		want[name] = true
	}
	if len(entries) != len(want) {
		t.Fatalf("hook count = %d, want %d", len(entries), len(want))
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			t.Fatalf("unexpected hook file %q", entry.Name())
		}
	}
}

func assertOnlyBashPolicyCommands(t *testing.T, value any) {
	t.Helper()
	commands := collectHookCommands(value)
	if len(commands) == 0 {
		t.Fatal("no hook commands found")
	}
	for _, command := range commands {
		if !strings.Contains(command, "bash-policy.sh") {
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
