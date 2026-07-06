package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liza-mas/bash-policy/internal/bashpolicy"
)

func isolateClaudeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func writeClaudeSettings(t *testing.T, root string, settings string) {
	t.Helper()
	claudeDir := filepath.Join(root, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0644); err != nil {
		t.Fatal(err)
	}
}

func evaluateClaudeJSON(t *testing.T, policyRoot string, command string) bashpolicy.Result {
	t.Helper()
	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"`+command+`"}`), &output, BashPolicyEvaluateOptions{
		Provider:           "claude",
		Mode:               "on",
		PolicyArtifactRoot: policyRoot,
		SafeRoots:          []string{policyRoot},
		JSON:               true,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}
	var result bashpolicy.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid result JSON: %v\n%s", err, output.String())
	}
	return result
}

func TestBashPolicyEvaluateCommandJSON(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	payload := `{"tool_input":{"command":"git -C ` + root + ` status --short"}}`

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(payload), &output, BashPolicyEvaluateOptions{
		Provider:           "claude",
		Mode:               "dry-run",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
		JSON:               true,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var result bashpolicy.Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid result JSON: %v\n%s", err, output.String())
	}
	if result.Decision != bashpolicy.DecisionAllow {
		t.Fatalf("decision = %s, want allow; result=%+v", result.Decision, result)
	}
}

func TestBashPolicyEvaluateCommandClaudeAllowOutput(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	payload := `{"command":"cd ` + root + ` && git status --short"}`

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(payload), &output, BashPolicyEvaluateOptions{
		Provider:           "claude",
		Mode:               "on",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Claude hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["hookSpecificOutput"]["permissionDecision"]; got != "allow" {
		t.Fatalf("permissionDecision = %v, want allow; output=%s", got, output.String())
	}
}

func TestBashPolicyEvaluateCommandCursorDryRunAllowsAndLogs(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	payload := `{"command":"rm -rf ` + root + `/tmp"}`

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(payload), &output, BashPolicyEvaluateOptions{
		Provider:           "cursor",
		Mode:               "dry-run",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
		Diagnostics:        &diagnostics,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "allow" {
		t.Fatalf("permission = %v, want allow in dry-run; output=%s", got, output.String())
	}
	var result bashpolicy.Result
	if err := json.Unmarshal(diagnostics.Bytes(), &result); err != nil {
		t.Fatalf("invalid diagnostic result: %v\n%s", err, diagnostics.String())
	}
	if result.Decision == bashpolicy.DecisionAllow {
		t.Fatalf("dry-run diagnostic decision = allow, want unsafe command signal; result=%+v", result)
	}
}

func TestBashPolicyEvaluateCommandCursorOffAllowsMalformedPayload(t *testing.T) {
	isolateClaudeHome(t)

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"not_command":`), &output, BashPolicyEvaluateOptions{
		Provider: "cursor",
		Mode:     "off",
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "allow" {
		t.Fatalf("permission = %v, want allow for off mode; output=%s", got, output.String())
	}
}

func TestBashPolicyEvaluateCommandCursorDryRunAllowsMissingPolicyRoot(t *testing.T) {
	isolateClaudeHome(t)
	t.Setenv("BASH_POLICY_ARTIFACT_ROOT", "")

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short"}`), &output, BashPolicyEvaluateOptions{
		Provider:    "cursor",
		Mode:        "dry-run",
		Diagnostics: &diagnostics,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "allow" {
		t.Fatalf("permission = %v, want allow for dry-run setup failure; output=%s", got, output.String())
	}
	if !strings.Contains(diagnostics.String(), "policy-artifact-root is required") {
		t.Fatalf("diagnostics missing setup failure:\n%s", diagnostics.String())
	}
}

func TestBashPolicyEvaluateCommandCursorDryRunAllowsMalformedPolicy(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, bashpolicy.PolicyFileName), []byte("rules: [\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short"}`), &output, BashPolicyEvaluateOptions{
		Provider:           "cursor",
		Mode:               "dry-run",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
		Diagnostics:        &diagnostics,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "allow" {
		t.Fatalf("permission = %v, want allow for dry-run setup failure; output=%s", got, output.String())
	}
	if !strings.Contains(diagnostics.String(), "parse bash policy") {
		t.Fatalf("diagnostics missing policy parse failure:\n%s", diagnostics.String())
	}
}

func TestBashPolicyEvaluateCommandCursorOnDeniesManualDecision(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	payload := `{"command":"rm -rf ` + root + `/tmp"}`

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(payload), &output, BashPolicyEvaluateOptions{
		Provider:           "cursor",
		Mode:               "on",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "deny" {
		t.Fatalf("permission = %v, want deny in on mode; output=%s", got, output.String())
	}
}

func TestBashPolicyEvaluateCommandCursorOnDeniesMalformedPolicy(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, bashpolicy.PolicyFileName), []byte("rules: [\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short"}`), &output, BashPolicyEvaluateOptions{
		Provider:           "cursor",
		Mode:               "on",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
		Diagnostics:        &diagnostics,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "deny" {
		t.Fatalf("permission = %v, want deny for on mode setup failure; output=%s", got, output.String())
	}
	if !strings.Contains(output.String(), "could not load policy artifacts") {
		t.Fatalf("output missing setup failure message:\n%s", output.String())
	}
	if !strings.Contains(diagnostics.String(), "parse bash policy") {
		t.Fatalf("diagnostics missing policy parse failure:\n%s", diagnostics.String())
	}
}

func TestBashPolicyEvaluateCommandCursorOnDeniesMissingPolicyRoot(t *testing.T) {
	isolateClaudeHome(t)
	t.Setenv("BASH_POLICY_ARTIFACT_ROOT", "")

	var output bytes.Buffer
	var diagnostics bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short"}`), &output, BashPolicyEvaluateOptions{
		Provider:    "cursor",
		Mode:        "on",
		Diagnostics: &diagnostics,
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["permission"]; got != "deny" {
		t.Fatalf("permission = %v, want deny for on mode setup failure; output=%s", got, output.String())
	}
	if !strings.Contains(output.String(), "could not load policy artifacts") {
		t.Fatalf("output missing setup failure message:\n%s", output.String())
	}
	if !strings.Contains(diagnostics.String(), "policy-artifact-root is required") {
		t.Fatalf("diagnostics missing setup failure:\n%s", diagnostics.String())
	}
}

func TestBashPolicyEvaluateCommandLoadsClaudeAllowPermissionsFromPolicyRootSettings(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	writeClaudeSettings(t, root, `{"permissions":{"allow":["Bash(gh pr view:*)"]}}`)

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short; gh pr view 123"}`), &output, BashPolicyEvaluateOptions{
		Provider:           "claude",
		Mode:               "on",
		PolicyArtifactRoot: root,
		SafeRoots:          []string{root},
	})
	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}

	var hookOutput map[string]map[string]any
	if err := json.Unmarshal(output.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Claude hook output: %v\n%s", err, output.String())
	}
	if got := hookOutput["hookSpecificOutput"]["permissionDecision"]; got != "allow" {
		t.Fatalf("permissionDecision = %v, want allow; output=%s", got, output.String())
	}
	if got := hookOutput["hookSpecificOutput"]["bashPolicyCommandShape"]; got != "git status --short ; gh pr view <number>" {
		t.Fatalf("bashPolicyCommandShape = %v, want compound shape; output=%s", got, output.String())
	}
}

func TestBashPolicyEvaluateCommandLoadsClaudeAllowPermissionsFromUserSettings(t *testing.T) {
	home := isolateClaudeHome(t)
	writeClaudeSettings(t, home, `{"permissions":{"allow":["Bash(gh pr view:*)"]}}`)
	root := t.TempDir()

	result := evaluateClaudeJSON(t, root, "gh pr view 123")

	if result.Decision != bashpolicy.DecisionAllow {
		t.Fatalf("decision = %s, want allow; result=%+v", result.Decision, result)
	}
	if result.CommandShape != "gh pr view <number>" {
		t.Fatalf("command shape = %q, want gh pr view <number>", result.CommandShape)
	}
}

func TestBashPolicyEvaluateCommandAppliesClaudeDenyPermissionsFromUserSettings(t *testing.T) {
	home := isolateClaudeHome(t)
	writeClaudeSettings(t, home, `{"permissions":{"deny":["Bash(gh pr view:*)"]}}`)
	root := t.TempDir()

	result := evaluateClaudeJSON(t, root, "gh pr view 123")

	if result.Decision != bashpolicy.DecisionDeny {
		t.Fatalf("decision = %s, want deny; result=%+v", result.Decision, result)
	}
}

func TestBashPolicyEvaluateCommandAppliesClaudeDenyPermissionsFromPolicyRootSettings(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()
	writeClaudeSettings(t, root, `{"permissions":{"deny":["Bash(gh pr view:*)"]}}`)

	result := evaluateClaudeJSON(t, root, "gh pr view 123")

	if result.Decision != bashpolicy.DecisionDeny {
		t.Fatalf("decision = %s, want deny; result=%+v", result.Decision, result)
	}
}

func TestBashPolicyEvaluateCommandPolicyRootSettingsPrevailOverUserSettingsConflicts(t *testing.T) {
	home := isolateClaudeHome(t)
	root := t.TempDir()

	writeClaudeSettings(t, home, `{"permissions":{"allow":["Bash(gh pr view:*)"],"deny":["Bash(grep -i:*)"]}}`)
	writeClaudeSettings(t, root, `{"permissions":{"allow":["Bash(grep -i:*)"],"deny":["Bash(gh pr view:*)"]}}`)

	deniedByRepo := evaluateClaudeJSON(t, root, "gh pr view 123")
	if deniedByRepo.Decision != bashpolicy.DecisionDeny {
		t.Fatalf("repo deny decision = %s, want deny; result=%+v", deniedByRepo.Decision, deniedByRepo)
	}

	allowedByRepo := evaluateClaudeJSON(t, root, "grep -i title")
	if allowedByRepo.Decision != bashpolicy.DecisionAllow {
		t.Fatalf("repo allow decision = %s, want allow; result=%+v", allowedByRepo.Decision, allowedByRepo)
	}
}

func TestBashPolicyEvaluateCommandDoesNotAllowUnsafeOrDryRunCommands(t *testing.T) {
	isolateClaudeHome(t)
	root := t.TempDir()

	tests := []struct {
		name            string
		mode            string
		command         string
		wantDiagnostics bool
		wantEvent       bool
	}{
		{name: "dry run safe command", mode: "dry-run", command: "git status --short", wantDiagnostics: true, wantEvent: true},
		{name: "on unsafe command", mode: "on", command: "git reset --hard", wantDiagnostics: true, wantEvent: true},
		{name: "off unsafe command", mode: "off", command: "git reset --hard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policyRoot := t.TempDir()
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"`+tt.command+`"}`), &output, BashPolicyEvaluateOptions{
				Provider:           "claude",
				Mode:               tt.mode,
				PolicyArtifactRoot: policyRoot,
				SafeRoots:          []string{root},
				Diagnostics:        &diagnostics,
			})
			if err != nil {
				t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
			}
			if output.Len() != 0 {
				t.Fatalf("output = %q, want empty no-op", output.String())
			}
			if tt.wantDiagnostics {
				var result bashpolicy.Result
				if err := json.Unmarshal(diagnostics.Bytes(), &result); err != nil {
					t.Fatalf("invalid diagnostics JSON: %v\n%s", err, diagnostics.String())
				}
				if result.Decision == "" {
					t.Fatalf("diagnostic result missing decision: %+v", result)
				}
			} else if diagnostics.Len() != 0 {
				t.Fatalf("diagnostics = %q, want empty", diagnostics.String())
			}
			events, err := bashpolicy.ReadEvents(filepath.Join(policyRoot, bashpolicy.DryRunLogFileName))
			if err != nil {
				t.Fatalf("read dry-run events: %v", err)
			}
			if tt.wantEvent && len(events) != 1 {
				t.Fatalf("events = %+v, want one dry-run event", events)
			}
			if !tt.wantEvent && len(events) != 0 {
				t.Fatalf("events = %+v, want none", events)
			}
		})
	}
}

func TestBashPolicyEvaluateCommandFailsClosedWithoutPolicyRootInDryRun(t *testing.T) {
	t.Setenv("BASH_POLICY_ARTIFACT_ROOT", "")
	root := t.TempDir()
	var output bytes.Buffer
	var diagnostics bytes.Buffer

	err := BashPolicyEvaluateCommand(strings.NewReader(`{"command":"git status --short"}`), &output, BashPolicyEvaluateOptions{
		Provider:    "claude",
		Mode:        "dry-run",
		SafeRoots:   []string{root},
		Diagnostics: &diagnostics,
	})

	if err != nil {
		t.Fatalf("BashPolicyEvaluateCommand failed: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, want empty no-op", output.String())
	}
	if !strings.Contains(diagnostics.String(), "bash policy disabled: policy-artifact-root is required") {
		t.Fatalf("diagnostics = %q, want disabled diagnostic", diagnostics.String())
	}
	if _, err := os.Stat(filepath.Join(root, bashpolicy.DryRunLogFileName)); !os.IsNotExist(err) {
		t.Fatalf("dry-run log should not be written without policy root, stat err: %v", err)
	}
}

func TestBashPolicyValidateCommandReportsValidPolicy(t *testing.T) {
	policyRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyRoot, bashpolicy.PolicyFileName), []byte(strings.Join([]string{
		"rules:",
		"- kind: command-shape",
		"  identity: gh issue view <number>",
		"  decision: manual",
		"- kind: permission-family",
		"  identity: Bash(gh:*)",
		"  status: resolved",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyValidateCommand(&output, BashPolicyValidateOptions{
		PolicyArtifactRoot: policyRoot,
	}); err != nil {
		t.Fatalf("BashPolicyValidateCommand failed: %v", err)
	}
	if !strings.Contains(output.String(), "Bash policy valid:") || !strings.Contains(output.String(), "(2 rules)") {
		t.Fatalf("output = %q, want valid summary", output.String())
	}
}

func TestBashPolicyValidateCommandRejectsInvalidPolicy(t *testing.T) {
	policyRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyRoot, bashpolicy.PolicyFileName), []byte(strings.Join([]string{
		"rules:",
		"- kind: command-shape",
		"  identity: gh issue view ...",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := BashPolicyValidateCommand(&output, BashPolicyValidateOptions{
		PolicyArtifactRoot: policyRoot,
	})
	if err == nil {
		t.Fatal("expected invalid policy to fail")
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, want empty on validation failure", output.String())
	}
	for _, want := range []string{"bash policy validation failed", "rules[0].decision is required", "not a usable command-shape identity"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q:\n%v", want, err)
		}
	}
}

func TestBashPolicyReportCommandIncludesMigrationAndRedactsSummaries(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "settings.json")
	settings := []byte(`{"permissions":{"allow":["Bash(git:*)","Bash(printenv:*)"]}}`)
	if err := os.WriteFile(settingsPath, settings, 0644); err != nil {
		t.Fatal(err)
	}

	input := strings.Join([]string{
		`{"decision":"allow","reason":"read-only git status","summary":"git status --short","command_family":"git"}`,
		`{"decision":"deny","reason":"secret","summary":"rg TOKEN ~/.ssh","command_family":"rg"}`,
	}, "\n")

	var output bytes.Buffer
	err := BashPolicyReportCommand(strings.NewReader(input), &output, BashPolicyReportOptions{
		ClaudeSettings: settingsPath,
	})
	if err != nil {
		t.Fatalf("BashPolicyReportCommand failed: %v", err)
	}
	if strings.Contains(output.String(), "TOKEN") || strings.Contains(output.String(), ".ssh") {
		t.Fatalf("report leaked sensitive summary:\n%s", output.String())
	}

	var report bashpolicy.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid report JSON: %v\n%s", err, output.String())
	}
	if len(report.Migration) != 2 {
		t.Fatalf("migration rows = %d, want 2: %+v", len(report.Migration), report.Migration)
	}
}

func TestBashPolicyReportCommandReadsDefaultArtifactLogWhenInputEmpty(t *testing.T) {
	policyRoot := t.TempDir()
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:      bashpolicy.DecisionManual,
		Reason:        "manual",
		Summary:       "gh pr view 123",
		CommandShape:  "gh pr view <number>",
		CommandFamily: "gh",
	}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err := BashPolicyReportCommand(strings.NewReader(""), &output, BashPolicyReportOptions{
		PolicyArtifactRoot: policyRoot,
	})
	if err != nil {
		t.Fatalf("BashPolicyReportCommand failed: %v", err)
	}

	var report bashpolicy.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid report JSON: %v\n%s", err, output.String())
	}
	if report.Total != 1 {
		t.Fatalf("report total = %d, want 1: %+v", report.Total, report)
	}
	if len(report.Aggregates) != 1 || report.Aggregates[0].Identity != "gh pr view <number>" {
		t.Fatalf("unexpected aggregates: %+v", report.Aggregates)
	}
}

func TestBashPolicyExportCommandWritesFilteredCandidatesAndIgnores(t *testing.T) {
	policyRoot := t.TempDir()
	initGitRepo(t, policyRoot)
	settingsPath := filepath.Join(policyRoot, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"permissions":{"allow":["Bash(rg:*)","Bash(sort:*)","Bash(gh:*)","Bash(printenv:*)"]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyRoot, bashpolicy.PolicyFileName), []byte(strings.Join([]string{
		"rules:",
		"- kind: permission-family",
		"  identity: Bash(gh:*)",
		"  status: resolved",
		"- kind: command-shape",
		"  identity: git status --short",
		"  decision: allow",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:     bashpolicy.DecisionManual,
		Reason:       "manual",
		Summary:      "git status --short",
		CommandShape: "git status --short",
	}); err != nil {
		t.Fatal(err)
	}
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:     bashpolicy.DecisionManual,
		Reason:       "manual",
		Summary:      "gh pr view 123",
		CommandShape: "gh pr view <number>",
	}); err != nil {
		t.Fatal(err)
	}
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:     bashpolicy.DecisionManual,
		Reason:       "manual",
		Summary:      "rg TODO -- src",
		CommandShape: "rg TODO -- <safe-path>",
	}); err != nil {
		t.Fatal(err)
	}
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:     bashpolicy.DecisionManual,
		Reason:       "manual",
		Summary:      "sort README.md",
		CommandShape: "sort README.md",
	}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyExportCommand(&output, BashPolicyExportOptions{
		Provider:           "claude",
		PolicyArtifactRoot: policyRoot,
		ClaudeSettings:     settingsPath,
	}); err != nil {
		t.Fatalf("BashPolicyExportCommand failed: %v", err)
	}

	candidatesContent, err := os.ReadFile(filepath.Join(policyRoot, bashpolicy.CandidatesFileName))
	if err != nil {
		t.Fatal(err)
	}
	candidates := string(candidatesContent)
	for _, want := range []string{"identity: Bash(printenv:*)", "identity: gh pr view <number>"} {
		if !strings.Contains(candidates, want) {
			t.Fatalf("candidates missing %q:\n%s", want, candidates)
		}
	}
	for _, unexpected := range []string{"Bash(rg:*)", "Bash(sort:*)", "Bash(gh:*)", "git status --short", "rg TODO", "sort README.md"} {
		if strings.Contains(candidates, unexpected) {
			t.Fatalf("candidates unexpectedly contain %q:\n%s", unexpected, candidates)
		}
	}
	exclude, err := os.ReadFile(filepath.Join(policyRoot, ".git", "info", "exclude"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		bashpolicy.DryRunLogFileName,
		bashpolicy.DryRunLogFileName + ".lock",
		bashpolicy.DryRunLogFileName + ".lock.owner.json",
		bashpolicy.CandidatesFileName,
	} {
		if !strings.Contains(string(exclude), want) {
			t.Fatalf("exclude missing %q:\n%s", want, string(exclude))
		}
	}
}

func TestBashPolicyInitCommandInstallsCursorProviderOnly(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)

	var output bytes.Buffer
	if err := BashPolicyInitCommand(&output, projectRoot, BashPolicyInitOptions{
		Provider:           "cursor",
		PolicyArtifactRoot: projectRoot,
		Command:            "/usr/local/bin/bash-policy",
	}); err != nil {
		t.Fatalf("BashPolicyInitCommand failed: %v", err)
	}

	cursorHooks, err := os.ReadFile(filepath.Join(projectRoot, ".cursor", "hooks.json"))
	if err != nil {
		t.Fatalf("Cursor hooks not installed: %v", err)
	}
	text := string(cursorHooks)
	for _, want := range []string{"--provider cursor", "--mode dry-run"} {
		if !strings.Contains(text, want) {
			t.Fatalf("Cursor hooks missing %q:\n%s", want, text)
		}
	}
	for _, unexpectedPath := range []string{
		filepath.Join(projectRoot, ".claude", "settings.json"),
		filepath.Join(projectRoot, ".codex", "hooks.json"),
	} {
		if _, err := os.Stat(unexpectedPath); !os.IsNotExist(err) {
			t.Fatalf("%s state = %v, want absent for Cursor-only init", unexpectedPath, err)
		}
	}
}

func TestBashPolicyActivationCommandUpdatesProviderHooks(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	claudeSettings := filepath.Join(projectRoot, ".claude", "settings.json")
	codexHooks := filepath.Join(projectRoot, ".codex", "hooks.json")
	cursorHooks := filepath.Join(projectRoot, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(claudeSettings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(codexHooks), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cursorHooks), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh\" claude dry-run"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexHooks, []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"command":".codex/hooks/bash-policy.sh codex dry-run"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorHooks, []byte(`{"version":1,"hooks":{"beforeShellExecution":[{"command":"/opt/wrapper evaluate --provider cursor --mode dry-run --policy-artifact-root /old --safe-root \"$PWD\"","failClosed":true}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "all",
		Activation: "off",
		Command:    "/usr/local/bin/bash-policy",
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}

	for _, path := range []string{claudeSettings, codexHooks, cursorHooks} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if strings.Contains(text, "dry-run") {
			t.Fatalf("%s still contains dry-run activation:\n%s", path, text)
		}
		if path == claudeSettings && (!strings.Contains(text, "bash-policy.sh") || !strings.Contains(text, "claude off")) {
			t.Fatalf("Claude settings did not preserve wrapper command with off activation:\n%s", text)
		}
		if path == codexHooks && (!strings.Contains(text, "bash-policy.sh") || !strings.Contains(text, "codex off")) {
			t.Fatalf("Codex hooks did not preserve wrapper command with off activation:\n%s", text)
		}
		if path == cursorHooks && (!strings.Contains(text, "/opt/wrapper evaluate") || !strings.Contains(text, "--provider cursor") || !strings.Contains(text, "--mode off")) {
			t.Fatalf("Cursor hooks did not preserve wrapper command with off activation:\n%s", text)
		}
	}
}

func TestBashPolicyActivationCommandPreservesRenamedEvaluateCommand(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	claudeSettings := filepath.Join(projectRoot, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(claudeSettings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /old --safe-root \"$CLAUDE_PROJECT_DIR\""}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "claude",
		Activation: "off",
		Command:    "/usr/local/bin/bash-policy",
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}
	content, err := os.ReadFile(claudeSettings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, want := range []string{"/opt/wrapper evaluate", "--provider claude", "--mode off", "--policy-artifact-root /old"} {
		if !strings.Contains(text, want) {
			t.Fatalf("settings missing preserved command fragment %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/usr/local/bin/bash-policy evaluate") {
		t.Fatalf("activation should preserve existing command unless command override is explicit:\n%s", text)
	}
}

func TestBashPolicyActivationCommandPrunesLegacyCursorHookWithoutNullEvent(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	cursorHooks := filepath.Join(projectRoot, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(cursorHooks), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursorHooks, []byte(`{"version":1,"hooks":{"afterShellExecution":[{"command":"bash .cursor/hooks/cursor-bash-policy.sh","failClosed":true}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "cursor",
		Activation: "dry-run",
		Command:    "/usr/local/bin/bash-policy",
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}

	content, err := os.ReadFile(cursorHooks)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Contains(text, "cursor-bash-policy.sh") {
		t.Fatalf("legacy Cursor wrapper should be pruned:\n%s", text)
	}
	if strings.Contains(text, `"afterShellExecution": null`) {
		t.Fatalf("legacy-only event should serialize as empty array, not null:\n%s", text)
	}
	if !strings.Contains(text, `"afterShellExecution": []`) {
		t.Fatalf("legacy-only event should remain a clean empty array:\n%s", text)
	}
}

func TestBashPolicyActivationCommandOverrideRewritesExistingCommand(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	claudeSettings := filepath.Join(projectRoot, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(claudeSettings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /old --safe-root \"$CLAUDE_PROJECT_DIR\""}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:        "claude",
		Activation:      "on",
		Command:         "/usr/local/bin/bash-policy",
		CommandOverride: true,
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}
	content, err := os.ReadFile(claudeSettings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, want := range []string{"/usr/local/bin/bash-policy evaluate", "--provider claude", "--mode on", "--policy-artifact-root", "--safe-root"} {
		if !strings.Contains(text, want) {
			t.Fatalf("settings missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/opt/wrapper") {
		t.Fatalf("override should replace existing wrapper command:\n%s", text)
	}
}

func TestBashPolicyActivationCommandPreservesUnrelatedEvaluateProviderHook(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	claudeSettings := filepath.Join(projectRoot, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(claudeSettings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"/opt/tool evaluate --provider claude --mode dry-run"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "claude",
		Activation: "off",
		Command:    "/usr/local/bin/bash-policy",
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}
	content, err := os.ReadFile(claudeSettings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if !strings.Contains(text, "/opt/tool evaluate --provider claude --mode dry-run") {
		t.Fatalf("unrelated provider hook should remain unchanged:\n%s", text)
	}
	for _, want := range []string{"/usr/local/bin/bash-policy evaluate", "--provider claude", "--mode off", "--policy-artifact-root", "--safe-root"} {
		if !strings.Contains(text, want) {
			t.Fatalf("settings missing managed hook fragment %q:\n%s", want, text)
		}
	}
}

func TestBashPolicyProviderCommandRejectsGenericEvaluateProviderHook(t *testing.T) {
	if isBashPolicyProviderCommand("/opt/wrapper evaluate --provider claude --mode dry-run", "claude") {
		t.Fatal("renamed evaluate command without artifact and safe roots should not be treated as a bash-policy hook")
	}
	if !isBashPolicyProviderCommand(`/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`, "claude") {
		t.Fatal("renamed evaluate command with full standalone shape should be treated as a bash-policy hook")
	}
}

func TestBashPolicyActivationCommandRejectsUnknownProvider(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)

	var output bytes.Buffer
	err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "unknown",
		Activation: "dry-run",
		Command:    "/usr/local/bin/bash-policy",
	})
	if err == nil {
		t.Fatal("expected unknown provider to fail")
	}
	if !strings.Contains(err.Error(), "claude, codex, cursor, or all") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBashPolicyCodexReadinessCommandJSON(t *testing.T) {
	projectRoot := t.TempDir()
	var output bytes.Buffer

	if err := BashPolicyCodexReadinessCommand(&output, projectRoot, true); err != nil {
		t.Fatalf("BashPolicyCodexReadinessCommand failed: %v", err)
	}

	var readiness bashpolicy.CodexReadiness
	if err := json.Unmarshal(output.Bytes(), &readiness); err != nil {
		t.Fatalf("invalid readiness JSON: %v\n%s", err, output.String())
	}
	if readiness.Status != bashpolicy.ReadinessNotConfigured {
		t.Fatalf("status = %s, want %s", readiness.Status, bashpolicy.ReadinessNotConfigured)
	}
}

func initGitRepo(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("git", "init")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init failed: %v\n%s", err, string(output))
	}
}
