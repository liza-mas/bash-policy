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
	if err := os.WriteFile(hooksPath, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":".codex/hooks/bash-policy.sh codex off"}]}]}}`), 0644); err != nil {
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

	t.Run("missing rtk hook wiring", func(t *testing.T) {
		projectRoot := t.TempDir()
		writeCodexReadinessFixture(t, projectRoot, false)

		readiness := AssessCodexReadiness(projectRoot)
		if readiness.Status != ReadinessDegraded {
			t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessDegraded, readiness.Checks)
		}
		if !hasReadinessCheck(readiness, "expected_hooks_wired", false) {
			t.Fatalf("expected hooks wiring check to fail: %+v", readiness.Checks)
		}
	})

	t.Run("unexecutable hook file", func(t *testing.T) {
		projectRoot := t.TempDir()
		writeCodexReadinessFixture(t, projectRoot, true)
		hookPath := filepath.Join(projectRoot, ".codex", "hooks", "bash-policy.sh")
		if err := os.Chmod(hookPath, 0644); err != nil {
			t.Fatal(err)
		}

		readiness := AssessCodexReadiness(projectRoot)
		if readiness.Status != ReadinessDegraded {
			t.Fatalf("status = %s, want %s; checks=%+v", readiness.Status, ReadinessDegraded, readiness.Checks)
		}
		if !hasReadinessCheck(readiness, "hook_file_bash-policy.sh", false) {
			t.Fatalf("expected bash-policy hook-file check to fail: %+v", readiness.Checks)
		}
	})
}

func writeCodexReadinessFixture(t *testing.T, projectRoot string, includeRTKHookWiring bool) {
	t.Helper()

	codexDir := filepath.Join(projectRoot, ".codex")
	hooksDir := filepath.Join(codexDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte("[features]\nhooks = true\n"), 0644); err != nil {
		t.Fatal(err)
	}

	hooksJSON := `{"hooks":{"SessionStart":[{"hooks":[{"command":".codex/hooks/session-context.sh"}]}],"PreToolUse":[{"hooks":[{"command":".codex/hooks/enforce-init.sh"},{"command":".codex/hooks/git-guard.sh"},{"command":".codex/hooks/bash-policy.sh"},{"command":".codex/hooks/worktree-path-guard.sh"}]}]}}`
	if includeRTKHookWiring {
		hooksJSON = `{"hooks":{"SessionStart":[{"hooks":[{"command":".codex/hooks/session-context.sh"}]}],"PreToolUse":[{"hooks":[{"command":".codex/hooks/enforce-init.sh"},{"command":".codex/hooks/git-guard.sh"},{"command":".codex/hooks/rtk-guard.sh"},{"command":".codex/hooks/bash-policy.sh"},{"command":".codex/hooks/worktree-path-guard.sh"}]}]}}`
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(hooksJSON), 0644); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"enforce-init.sh", "session-context.sh", "git-guard.sh", "rtk-guard.sh", "bash-policy.sh", "worktree-path-guard.sh"} {
		if err := os.WriteFile(filepath.Join(hooksDir, name), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
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
