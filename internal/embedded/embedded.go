// Package embedded provides bash-policy hook and settings assets.
package embedded

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
)

//go:embed "claude-settings.json"
var claudeSettingsContent []byte

//go:embed "codex-hooks.json"
var codexHooksContent []byte

//go:embed "hooks/bash-policy.sh"
var bashPolicyHookContent []byte

const (
	dryRunLogFileName  = ".bash-policy-dry-run.jsonl"
	candidatesFileName = ".bash-policy-candidates.yaml"
)

// WriteClaudeSettings writes bash-policy Claude settings and installs the
// managed Claude hook script. Existing settings are merged only after user
// confirmation.
func WriteClaudeSettings(projectRoot string, reader *bufio.Reader) error {
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	claudeDir := filepath.Join(projectRoot, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")

	var existingSettings map[string]any
	if existingData, err := os.ReadFile(settingsPath); err == nil {
		ok, err := confirmMerge("Should bash-policy settings be merged into the existing Claude settings file? (y/n): ", reader)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if err := json.Unmarshal(existingData, &existingSettings); err != nil {
			return fmt.Errorf("failed to parse existing Claude settings: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read Claude settings: %w", err)
	}

	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		return fmt.Errorf("failed to create .claude directory: %w", err)
	}

	var managedSettings map[string]any
	if err := json.Unmarshal(claudeSettingsContent, &managedSettings); err != nil {
		return fmt.Errorf("failed to parse embedded Claude settings: %w", err)
	}

	finalSettings := managedSettings
	if existingSettings != nil {
		finalSettings = mergeSettings(managedSettings, existingSettings)
	}

	output, err := json.MarshalIndent(finalSettings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Claude settings: %w", err)
	}
	if err := os.WriteFile(settingsPath, append(output, '\n'), 0o644); err != nil {
		return fmt.Errorf("failed to write Claude settings: %w", err)
	}
	if err := WriteHooks(projectRoot); err != nil {
		return fmt.Errorf("failed to write Claude hooks: %w", err)
	}
	if err := ensureBashPolicyArtifactExcludes(projectRoot); err != nil {
		return fmt.Errorf("failed to exclude Bash policy artifacts: %w", err)
	}
	return nil
}

// WriteCodexProjectHooks writes project-local Codex hook configuration and the
// managed bash-policy hook script. Existing config and hooks are merged only
// after user confirmation.
func WriteCodexProjectHooks(projectRoot string, reader *bufio.Reader) error {
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	codexDir := filepath.Join(projectRoot, ".codex")
	if err := ensureCodexDir(codexDir); err != nil {
		return fmt.Errorf("failed to create .codex directory: %w", err)
	}

	configPath := filepath.Join(codexDir, "config.toml")
	install, configContent, err := prepareCodexHooksFeature(configPath, reader)
	if err != nil {
		return err
	}
	if !install {
		return nil
	}

	hooksOutput, installed, err := renderCodexHooksJSON(filepath.Join(codexDir, "hooks.json"), reader)
	if err != nil {
		return err
	}
	if !installed {
		return nil
	}
	if err := WriteCodexHooks(projectRoot); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), hooksOutput, 0o644); err != nil {
		return fmt.Errorf("failed to write Codex hooks.json: %w", err)
	}
	if configContent != "" {
		if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
			return fmt.Errorf("failed to write Codex project config: %w", err)
		}
	}
	if err := ensureBashPolicyArtifactExcludes(projectRoot); err != nil {
		return fmt.Errorf("failed to exclude Bash policy artifacts: %w", err)
	}
	return nil
}

// WriteHooks writes managed bash-policy hook scripts to .claude/hooks.
func WriteHooks(projectRoot string) error {
	return writeHookScripts(filepath.Join(projectRoot, ".claude", "hooks"))
}

// WriteCodexHooks writes managed bash-policy hook scripts to .codex/hooks.
func WriteCodexHooks(projectRoot string) error {
	return writeHookScripts(filepath.Join(projectRoot, ".codex", "hooks"))
}

func writeHookScripts(hooksDir string) error {
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}
	for name, content := range hookScriptContents() {
		if err := os.WriteFile(filepath.Join(hooksDir, name), content, 0o755); err != nil {
			return fmt.Errorf("failed to write %s: %w", name, err)
		}
	}
	return nil
}

func hookScriptContents() map[string][]byte {
	return map[string][]byte{
		"bash-policy.sh": bashPolicyHookContent,
	}
}

func confirmMerge(prompt string, reader *bufio.Reader) (bool, error) {
	fmt.Print(prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("failed to read user input: %w", err)
	}
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes", nil
}

func ensureBashPolicyArtifactExcludes(projectRoot string) error {
	excludePath, err := gitExcludePath(projectRoot)
	if err != nil || excludePath == "" {
		return err
	}
	return appendMissingExcludeEntries(excludePath, []string{
		dryRunLogFileName,
		dryRunLogFileName + ".lock",
		dryRunLogFileName + ".lock.owner.json",
		candidatesFileName,
	})
}

func gitExcludePath(projectRoot string) (string, error) {
	gitPath := filepath.Join(projectRoot, ".git")
	info, err := os.Lstat(gitPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return filepath.Join(gitPath, "info", "exclude"), nil
	}

	content, err := os.ReadFile(gitPath)
	if err != nil {
		return "", fmt.Errorf("read .git file: %w", err)
	}
	raw := strings.TrimSpace(string(content))
	if !strings.HasPrefix(raw, "gitdir:") {
		return "", fmt.Errorf(".git is not a directory or gitdir file")
	}
	gitDir := strings.TrimSpace(strings.TrimPrefix(raw, "gitdir:"))
	if gitDir == "" {
		return "", fmt.Errorf(".git file has empty gitdir")
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(projectRoot, gitDir)
	}
	return filepath.Join(filepath.Clean(gitDir), "info", "exclude"), nil
}

func appendMissingExcludeEntries(excludePath string, entries []string) error {
	if err := os.MkdirAll(filepath.Dir(excludePath), 0o755); err != nil {
		return fmt.Errorf("create git exclude directory: %w", err)
	}
	content, err := os.ReadFile(excludePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read git exclude: %w", err)
	}
	existing := make(map[string]bool)
	for _, line := range strings.Split(string(content), "\n") {
		existing[strings.TrimSpace(line)] = true
	}
	next := append([]byte(nil), content...)
	for _, entry := range entries {
		if existing[entry] {
			continue
		}
		if len(next) > 0 && next[len(next)-1] != '\n' {
			next = append(next, '\n')
		}
		next = append(next, entry...)
		next = append(next, '\n')
	}
	return os.WriteFile(excludePath, next, 0o644)
}

func ensureCodexDir(codexDir string) error {
	info, err := os.Lstat(codexDir)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			targetInfo, targetErr := os.Stat(codexDir)
			if targetErr == nil && targetInfo.IsDir() {
				return nil
			}
			if targetErr != nil {
				return fmt.Errorf("%s exists as symlink: %w", codexDir, targetErr)
			}
			return fmt.Errorf("%s exists as symlink and is not a directory", codexDir)
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode().IsRegular() && info.Size() == 0 {
			if err := os.Remove(codexDir); err != nil {
				return err
			}
			return os.MkdirAll(codexDir, 0o755)
		}
		return fmt.Errorf("%s exists and is not a directory", codexDir)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(codexDir, 0o755)
}

func prepareCodexHooksFeature(configPath string, reader *bufio.Reader) (bool, string, error) {
	existing, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return true, "[features]\nhooks = true\n", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("failed to read Codex project config: %w", err)
	}

	merged, changed := mergeCodexHooksFeature(string(existing))
	if !changed {
		return true, "", nil
	}

	ok, err := confirmMerge("Should bash-policy enable Codex hooks in .codex/config.toml? (y/n): ", reader)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, "", nil
	}
	return true, merged, nil
}

func mergeCodexHooksFeature(content string) (string, bool) {
	lines := strings.Split(content, "\n")
	sectionStart, sectionEnd := findTomlSection(lines, "features")
	if sectionStart == -1 {
		return appendTomlBlock(content, "[features]\nhooks = true\n"), true
	}

	lineStart, lineEnd := findTomlAssignment(lines, sectionStart+1, sectionEnd, "hooks")
	if lineStart == -1 {
		updated := insertLines(lines, sectionEnd, []string{"hooks = true"})
		return ensureTrailingNewline(strings.Join(updated, "\n")), true
	}

	assignment := strings.TrimSpace(stripTomlLineComment(strings.Join(lines[lineStart:lineEnd+1], "\n")))
	if assignment == "hooks = true" {
		return content, false
	}

	lines[lineStart] = "hooks = true"
	if lineEnd > lineStart {
		lines = append(lines[:lineStart+1], lines[lineEnd+1:]...)
	}
	return ensureTrailingNewline(strings.Join(lines, "\n")), true
}

func renderCodexHooksJSON(hooksPath string, reader *bufio.Reader) ([]byte, bool, error) {
	var managedHooks map[string]any
	if err := json.Unmarshal(codexHooksContent, &managedHooks); err != nil {
		return nil, false, fmt.Errorf("failed to parse embedded Codex hooks: %w", err)
	}

	finalHooks := managedHooks
	if existingData, err := os.ReadFile(hooksPath); err == nil {
		ok, err := confirmMerge("Should bash-policy hooks be merged into .codex/hooks.json? (y/n): ", reader)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			return nil, false, nil
		}

		var existingHooks map[string]any
		if err := json.Unmarshal(existingData, &existingHooks); err != nil {
			return nil, false, fmt.Errorf("failed to parse existing Codex hooks: %w", err)
		}
		finalHooks = mergeSettings(managedHooks, existingHooks)
	} else if err != nil && !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("failed to read Codex hooks: %w", err)
	}

	output, err := json.MarshalIndent(finalHooks, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("failed to marshal Codex hooks: %w", err)
	}
	return append(output, '\n'), true, nil
}

func mergeSettings(managed, existing map[string]any) map[string]any {
	result := make(map[string]any)
	maps.Copy(result, managed)

	for key, value := range existing {
		switch key {
		case "permissions":
			managedPerms, managedOK := managed[key].(map[string]any)
			existingPerms, existingOK := value.(map[string]any)
			if managedOK && existingOK {
				result[key] = mergePermissions(managedPerms, existingPerms)
			} else {
				result[key] = value
			}
		case "hooks":
			managedHooks, managedOK := managed[key].(map[string]any)
			existingHooks, existingOK := value.(map[string]any)
			if managedOK && existingOK {
				result[key] = mergeHooks(managedHooks, existingHooks)
			} else {
				result[key] = value
			}
		case "additionalDirectories":
			result[key] = value
		default:
			result[key] = value
		}
	}

	mergeTopLevelAdditionalDirectories(result, managed["additionalDirectories"])
	mergeTopLevelAdditionalDirectories(result, existing["additionalDirectories"])
	delete(result, "additionalDirectories")
	return result
}

func mergePermissions(managed, existing map[string]any) map[string]any {
	result := make(map[string]any)
	maps.Copy(result, managed)

	for key, value := range existing {
		switch key {
		case "allow", "additionalDirectories":
			managedAllow, managedOK := managed[key].([]any)
			existingAllow, existingOK := value.([]any)
			if managedOK && existingOK {
				result[key] = unionStringArrays(managedAllow, existingAllow)
			} else if existingOK {
				result[key] = value
			}
		default:
			result[key] = value
		}
	}
	return result
}

func mergeTopLevelAdditionalDirectories(result map[string]any, value any) {
	dirs, ok := value.([]any)
	if !ok {
		return
	}

	perms, ok := result["permissions"].(map[string]any)
	if !ok {
		perms = make(map[string]any)
		result["permissions"] = perms
	}
	existingDirs, _ := perms["additionalDirectories"].([]any)
	perms["additionalDirectories"] = unionStringArrays(existingDirs, dirs)
}

func mergeHooks(managed, existing map[string]any) map[string]any {
	result := make(map[string]any)
	maps.Copy(result, managed)
	maps.Copy(result, existing)

	for event, managedValue := range managed {
		existingValue, ok := existing[event]
		if !ok {
			continue
		}
		managedEntries, managedOK := managedValue.([]any)
		existingEntries, existingOK := existingValue.([]any)
		if !managedOK || !existingOK {
			continue
		}
		result[event] = unionHookEntries(managedEntries, existingEntries)
	}
	return result
}

func unionHookEntries(managed, existing []any) []any {
	existingCommands := make(map[string]bool)
	for _, entry := range existing {
		for _, command := range hookCommands(entry) {
			existingCommands[canonicalHookCommand(command)] = true
		}
	}

	result := make([]any, 0, len(managed)+len(existing))
	for _, entry := range managed {
		collides := false
		for _, command := range hookCommands(entry) {
			if existingCommands[canonicalHookCommand(command)] {
				collides = true
				break
			}
		}
		if !collides {
			result = append(result, entry)
		}
	}
	result = append(result, existing...)
	return result
}

func hookCommands(entry any) []string {
	entryMap, ok := entry.(map[string]any)
	if !ok {
		return nil
	}
	hooks, ok := entryMap["hooks"].([]any)
	if !ok {
		return nil
	}
	commands := make([]string, 0, len(hooks))
	for _, hook := range hooks {
		hookMap, ok := hook.(map[string]any)
		if !ok {
			continue
		}
		if command, ok := hookMap["command"].(string); ok {
			commands = append(commands, command)
		}
	}
	return commands
}

func canonicalHookCommand(command string) string {
	if !strings.Contains(command, "bash-policy.sh") {
		return command
	}
	for _, provider := range []string{" claude ", " codex "} {
		if !strings.Contains(command, provider) {
			continue
		}
		for _, activation := range []string{"audit", "allow", "dry-run", "on", "off"} {
			needle := provider + activation
			if strings.Contains(command, needle) {
				return strings.Replace(command, needle, provider+"<activation>", 1)
			}
		}
	}
	return command
}

func unionStringArrays(a, b []any) []any {
	seen := make(map[string]bool)
	result := []any{}
	for _, item := range append(a, b...) {
		value, ok := item.(string)
		if !ok || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, item)
	}
	return result
}

func findTomlSection(lines []string, name string) (int, int) {
	start := -1
	for i, line := range lines {
		header, ok := tomlHeaderName(line)
		if !ok {
			continue
		}
		if start == -1 {
			if header == name {
				start = i
			}
			continue
		}
		return start, i
	}
	if start == -1 {
		return -1, -1
	}
	return start, len(lines)
}

func tomlHeaderName(line string) (string, bool) {
	trimmed := strings.TrimSpace(stripTomlLineComment(line))
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") || strings.HasPrefix(trimmed, "[[") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")), true
}

func findTomlAssignment(lines []string, start, end int, key string) (int, int) {
	for i := start; i < end; i++ {
		trimmed := strings.TrimSpace(stripTomlLineComment(lines[i]))
		if !strings.HasPrefix(trimmed, key) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, key))
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		arrayEnd := i
		if strings.Contains(rest, "[") && !strings.Contains(rest, "]") {
			for arrayEnd+1 < end {
				arrayEnd++
				if strings.Contains(stripTomlLineComment(lines[arrayEnd]), "]") {
					break
				}
			}
		}
		return i, arrayEnd
	}
	return -1, -1
}

func stripTomlLineComment(line string) string {
	inString := false
	escaped := false
	for i, char := range line {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && inString {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == '#' && !inString {
			return line[:i]
		}
	}
	return line
}

func insertLines(lines []string, index int, insert []string) []string {
	updated := make([]string, 0, len(lines)+len(insert))
	updated = append(updated, lines[:index]...)
	updated = append(updated, insert...)
	updated = append(updated, lines[index:]...)
	return updated
}

func appendTomlBlock(content, block string) string {
	if strings.TrimSpace(content) == "" {
		return ensureTrailingNewline(block)
	}
	return ensureTrailingNewline(content) + "\n" + ensureTrailingNewline(block)
}

func ensureTrailingNewline(content string) string {
	if strings.HasSuffix(content, "\n") {
		return content
	}
	return content + "\n"
}
