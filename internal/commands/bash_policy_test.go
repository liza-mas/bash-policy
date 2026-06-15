package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liza-mas/liza/internal/bashpolicy"
)

func TestBashPolicyEvaluateCommandJSON(t *testing.T) {
	root := t.TempDir()
	payload := `{"tool_input":{"command":"git -C ` + root + ` status --short"}}`

	var output bytes.Buffer
	err := BashPolicyEvaluateCommand(strings.NewReader(payload), &output, BashPolicyEvaluateOptions{
		Provider:  "claude",
		Mode:      "dry-run",
		SafeRoots: []string{root},
		JSON:      true,
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

func TestBashPolicyEvaluateCommandDoesNotAllowUnsafeOrDryRunCommands(t *testing.T) {
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
		Provider:       "claude",
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
		Provider:           "claude",
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
	if err := BashPolicyExportCommand(strings.NewReader(""), &output, BashPolicyExportOptions{
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

func TestBashPolicyActivationCommandUpdatesProviderHooks(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)
	claudeSettings := filepath.Join(projectRoot, ".claude", "settings.json")
	codexHooks := filepath.Join(projectRoot, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(claudeSettings), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(codexHooks), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(claudeSettings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh\" claude dry-run"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexHooks, []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"command":".codex/hooks/bash-policy.sh codex dry-run"}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "all",
		Activation: "off",
	}); err != nil {
		t.Fatalf("BashPolicyActivationCommand failed: %v", err)
	}
	for _, path := range []string{claudeSettings, codexHooks} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		if strings.Contains(text, "dry-run") {
			t.Fatalf("%s still contains dry-run activation:\n%s", path, text)
		}
		if path == claudeSettings && !strings.Contains(text, " claude off") {
			t.Fatalf("Claude settings missing off activation:\n%s", text)
		}
		if path == codexHooks && !strings.Contains(text, " codex off") {
			t.Fatalf("Codex hooks missing off activation:\n%s", text)
		}
	}
}

func TestBashPolicyActivationCommandRejectsUnknownProvider(t *testing.T) {
	projectRoot := t.TempDir()
	initGitRepo(t, projectRoot)

	var output bytes.Buffer
	err := BashPolicyActivationCommand(&output, projectRoot, BashPolicyActivationOptions{
		Provider:   "unknown",
		Activation: "dry-run",
	})
	if err == nil {
		t.Fatal("expected unknown provider to fail")
	}
	if !strings.Contains(err.Error(), "claude, codex, or all") {
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
