package bashpolicy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssessCodexReadinessReportsNotConfigured(t *testing.T) {
	readiness := AssessCodexReadiness(t.TempDir())
	if readiness.Status != ReadinessNotConfigured {
		t.Fatalf("status = %s, want %s", readiness.Status, ReadinessNotConfigured)
	}
}

func TestAssessCodexReadinessReportsLogOnlyForCompleteInstall(t *testing.T) {
	projectRoot := t.TempDir()
	writeCodexReadinessFixture(t, projectRoot, true)

	readiness := AssessCodexReadiness(projectRoot)
	if readiness.Status != ReadinessLogOnly {
		t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessLogOnly, readiness.Checks)
	}
	if readiness.BlockingVerified {
		t.Fatal("blocking contract should not be marked verified by installation checks alone")
	}
	if !hasReadinessCheck(readiness, "blocking_contract_verified", false) {
		t.Fatalf("missing unverified blocking-contract check: %+v", readiness.Checks)
	}
}

func TestAssessCodexReadinessReportsOffForExplicitActivation(t *testing.T) {
	projectRoot := t.TempDir()
	writeCodexReadinessFixture(t, projectRoot, true)
	hooksPath := filepath.Join(projectRoot, ".codex", "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"/usr/local/bin/bash-policy evaluate --provider codex --mode off --policy-artifact-root /project --safe-root \"$PWD\""}]}]}}`), 0644); err != nil {
		t.Fatal(err)
	}

	readiness := AssessCodexReadiness(projectRoot)
	if readiness.Status != ReadinessOff {
		t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessOff, readiness.Checks)
	}
	if !hasReadinessCheck(readiness, "bash_policy_activation", true) {
		t.Fatalf("missing bash_policy_activation off check: %+v", readiness.Checks)
	}
}

func TestAssessCodexReadinessReportsDegradedForMissingInstallPreconditions(t *testing.T) {
	t.Run("hooks disabled", func(t *testing.T) {
		projectRoot := t.TempDir()
		writeCodexReadinessFixture(t, projectRoot, true)
		if err := os.WriteFile(filepath.Join(projectRoot, ".codex", "config.toml"), []byte("[features]\nhooks = false\n"), 0644); err != nil {
			t.Fatal(err)
		}

		readiness := AssessCodexReadiness(projectRoot)
		if readiness.Status != ReadinessDegraded {
			t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessDegraded, readiness.Checks)
		}
	})

	t.Run("missing bash policy safe root wiring", func(t *testing.T) {
		projectRoot := t.TempDir()
		writeCodexReadinessFixture(t, projectRoot, false)

		readiness := AssessCodexReadiness(projectRoot)
		if readiness.Status != ReadinessDegraded {
			t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessDegraded, readiness.Checks)
		}
		if !hasReadinessCheck(readiness, "bash_policy_hook_wired", false) {
			t.Fatalf("expected hooks wiring check to fail: %+v", readiness.Checks)
		}
	})
}

func TestCodexHooksJSONRequiresSingleBashPolicyCommandShape(t *testing.T) {
	hooksJSON := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"command":"/opt/one evaluate --provider codex"},{"command":"/opt/two --mode dry-run --policy-artifact-root /project --safe-root \"$PWD\""}]}]}}`)

	if codexHooksJSONHasExpectedCommands(hooksJSON) {
		t.Fatal("expected split hook commands not to satisfy Codex bash policy readiness")
	}
}

func TestCodexHooksJSONAcceptsRenamedEvaluateCommand(t *testing.T) {
	hooksJSON := []byte(`{"hooks":{"PreToolUse":[{"matcher":"^Bash$","hooks":[{"command":"/opt/wrapper evaluate --provider codex --mode dry-run --policy-artifact-root /project --safe-root \"$PWD\""}]}]}}`)

	if !codexHooksJSONHasExpectedCommands(hooksJSON) {
		t.Fatal("expected renamed evaluate command to satisfy Codex bash policy readiness")
	}
}

func TestCodexHooksJSONMatcherRegexMustMatchBash(t *testing.T) {
	tests := []struct {
		name    string
		matcher string
		want    bool
	}{
		{name: "match all", matcher: ".*", want: true},
		{name: "codex match all", matcher: "*", want: true},
		{name: "alternation", matcher: "Bash|Edit", want: true},
		{name: "non matching", matcher: "Edit", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hooksJSON := []byte(`{"hooks":{"PreToolUse":[{"matcher":"` + tt.matcher + `","hooks":[{"command":"/opt/wrapper evaluate --provider codex --mode dry-run --policy-artifact-root /project --safe-root \"$PWD\""}]}]}}`)

			got := codexHooksJSONHasExpectedCommands(hooksJSON)
			if got != tt.want {
				t.Fatalf("codexHooksJSONHasExpectedCommands = %t, want %t for matcher %q", got, tt.want, tt.matcher)
			}
		})
	}
}

func writeCodexReadinessFixture(t *testing.T, projectRoot string, includeSafeRoot bool) {
	t.Helper()

	codexDir := filepath.Join(projectRoot, ".codex")
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("[features]\nhooks = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	command := `/usr/local/bin/bash-policy evaluate --provider codex --mode dry-run --policy-artifact-root /project`
	if includeSafeRoot {
		command += ` --safe-root $PWD`
	}
	hooksJSON := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"` + command + `"}]}]}}`
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(hooksJSON), 0644); err != nil {
		t.Fatal(err)
	}
}

func hasReadinessCheck(readiness CodexReadiness, name string, ok bool) bool {
	for _, check := range readiness.Checks {
		if check.Name == name && check.OK == ok {
			return true
		}
	}
	return false
}
