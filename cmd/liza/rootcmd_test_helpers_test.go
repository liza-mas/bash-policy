package main

import (
	"io"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestResetRootCmdForTestClearsBashPolicyFlagState(t *testing.T) {
	if err := bashPolicyEvaluateCmd.Flags().Set("provider", "codex"); err != nil {
		t.Fatalf("set --provider failed: %v", err)
	}
	if err := bashPolicyEvaluateCmd.Flags().Set("mode", "on"); err != nil {
		t.Fatalf("set --mode failed: %v", err)
	}
	if err := bashPolicyEvaluateCmd.Flags().Set("policy-artifact-root", "/tmp/policy"); err != nil {
		t.Fatalf("set --policy-artifact-root failed: %v", err)
	}
	if err := bashPolicyEvaluateCmd.Flags().Set("safe-root", "/tmp/project"); err != nil {
		t.Fatalf("set --safe-root failed: %v", err)
	}
	if err := bashPolicyReportCmd.Flags().Set("claude-settings", "/tmp/settings.json"); err != nil {
		t.Fatalf("set --claude-settings failed: %v", err)
	}

	resetRootCmdForTest(t)

	provider, err := bashPolicyEvaluateCmd.Flags().GetString("provider")
	if err != nil {
		t.Fatalf("get --provider failed: %v", err)
	}
	if provider != "claude" {
		t.Fatalf("--provider = %q, want default claude", provider)
	}
	mode, err := bashPolicyEvaluateCmd.Flags().GetString("mode")
	if err != nil {
		t.Fatalf("get --mode failed: %v", err)
	}
	if mode != "dry-run" {
		t.Fatalf("--mode = %q, want default dry-run", mode)
	}
	policyRoot, err := bashPolicyEvaluateCmd.Flags().GetString("policy-artifact-root")
	if err != nil {
		t.Fatalf("get --policy-artifact-root failed: %v", err)
	}
	if policyRoot != "" {
		t.Fatalf("--policy-artifact-root = %q, want empty", policyRoot)
	}
	safeRoots, err := bashPolicyEvaluateCmd.Flags().GetStringArray("safe-root")
	if err != nil {
		t.Fatalf("get --safe-root failed: %v", err)
	}
	if len(safeRoots) != 0 {
		t.Fatalf("--safe-root = %v, want empty", safeRoots)
	}
	claudeSettings, err := bashPolicyReportCmd.Flags().GetString("claude-settings")
	if err != nil {
		t.Fatalf("get --claude-settings failed: %v", err)
	}
	if claudeSettings != "" {
		t.Fatalf("--claude-settings = %q, want empty", claudeSettings)
	}
}

func resetRootCmdForTest(t *testing.T) {
	t.Helper()

	resetHelpFlag(t, rootCmd)
	resetCommandFlagsForTest(t, rootCmd)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs(nil)
}

func resetCommandFlagsForTest(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	resetHelpFlag(t, cmd)
	for _, name := range []string{
		"provider",
		"mode",
		"policy-artifact-root",
		"safe-root",
		"claude-settings",
		"json",
	} {
		resetFlagIfPresent(cmd, name)
	}
	for _, child := range cmd.Commands() {
		resetCommandFlagsForTest(t, child)
	}
}

func resetFlagIfPresent(cmd *cobra.Command, name string) {
	f := cmd.Flags().Lookup(name)
	if f == nil {
		f = cmd.PersistentFlags().Lookup(name)
	}
	if f == nil {
		return
	}
	if sliceValue, ok := f.Value.(pflag.SliceValue); ok {
		_ = sliceValue.Replace(nil)
		f.Changed = false
		return
	}
	_ = f.Value.Set(f.DefValue)
	f.Changed = false
}

type testingHelper interface {
	Helper()
	Fatalf(string, ...any)
}

func resetHelpFlag(t testingHelper, cmd *cobra.Command) {
	t.Helper()

	helpFlag := cmd.Flags().Lookup("help")
	if helpFlag == nil {
		return
	}
	if err := cmd.Flags().Set("help", "false"); err != nil {
		t.Fatalf("failed to reset help flag for %s: %v", cmd.CommandPath(), err)
	}
	helpFlag.Changed = false
}
