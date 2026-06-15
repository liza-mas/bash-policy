package main

import (
	"io"
	"os"
	"strings"

	"github.com/liza-mas/liza/internal/commands"
	"github.com/spf13/cobra"
)

var bashPolicyCmd = &cobra.Command{
	Use:   "bash-policy",
	Short: "Evaluate provider Bash command policy decisions",
}

var bashPolicyEvaluateCmd = &cobra.Command{
	Use:   "evaluate",
	Short: "Evaluate one provider hook payload from stdin",
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, _ := cmd.Flags().GetString("provider")
		mode, _ := cmd.Flags().GetString("mode")
		policyArtifactRoot, _ := cmd.Flags().GetString("policy-artifact-root")
		safeRoots, _ := cmd.Flags().GetStringArray("safe-root")
		jsonOutput, _ := cmd.Flags().GetBool("json")
		return commands.BashPolicyEvaluateCommand(os.Stdin, os.Stdout, commands.BashPolicyEvaluateOptions{
			Provider:           provider,
			Mode:               mode,
			PolicyArtifactRoot: policyArtifactRoot,
			SafeRoots:          safeRoots,
			JSON:               jsonOutput,
			Diagnostics:        os.Stderr,
		})
	},
}

var bashPolicyReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Build a redacted dry-run report from policy result JSONL",
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, _ := cmd.Flags().GetString("provider")
		policyArtifactRoot, _ := cmd.Flags().GetString("policy-artifact-root")
		if policyArtifactRoot == "" {
			projectRoot, err := requireProjectRoot()
			if err != nil {
				return err
			}
			policyArtifactRoot = projectRoot
		}
		claudeSettings, _ := cmd.Flags().GetString("claude-settings")
		return commands.BashPolicyReportCommand(optionalStdinReader(os.Stdin), os.Stdout, commands.BashPolicyReportOptions{
			Provider:           provider,
			PolicyArtifactRoot: policyArtifactRoot,
			ClaudeSettings:     claudeSettings,
		})
	},
}

var bashPolicyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export unresolved Bash policy candidates",
	RunE: func(cmd *cobra.Command, args []string) error {
		provider, _ := cmd.Flags().GetString("provider")
		policyArtifactRoot, _ := cmd.Flags().GetString("policy-artifact-root")
		if policyArtifactRoot == "" {
			projectRoot, err := requireProjectRoot()
			if err != nil {
				return err
			}
			policyArtifactRoot = projectRoot
		}
		claudeSettings, _ := cmd.Flags().GetString("claude-settings")
		return commands.BashPolicyExportCommand(os.Stdin, os.Stdout, commands.BashPolicyExportOptions{
			Provider:           provider,
			PolicyArtifactRoot: policyArtifactRoot,
			ClaudeSettings:     claudeSettings,
		})
	},
}

var bashPolicyActivationCmd = &cobra.Command{
	Use:   "activation on|dry-run|off",
	Short: "Set provider Bash policy hook activation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		projectRoot, err := requireProjectRoot()
		if err != nil {
			return err
		}
		provider, _ := cmd.Flags().GetString("provider")
		policyArtifactRoot, _ := cmd.Flags().GetString("policy-artifact-root")
		return commands.BashPolicyActivationCommand(os.Stdout, projectRoot, commands.BashPolicyActivationOptions{
			Provider:           provider,
			Activation:         args[0],
			PolicyArtifactRoot: policyArtifactRoot,
		})
	},
}

var bashPolicyCodexReadinessCmd = &cobra.Command{
	Use:   "codex-readiness",
	Short: "Report Codex project hook readiness for Bash policy enforcement",
	RunE: func(cmd *cobra.Command, args []string) error {
		projectRoot, err := requireProjectRoot()
		if err != nil {
			return err
		}
		jsonOutput, _ := cmd.Flags().GetBool("json")
		return commands.BashPolicyCodexReadinessCommand(os.Stdout, projectRoot, jsonOutput)
	},
}

func init() {
	rootCmd.AddCommand(bashPolicyCmd)
	bashPolicyCmd.AddCommand(bashPolicyEvaluateCmd)
	bashPolicyCmd.AddCommand(bashPolicyReportCmd)
	bashPolicyCmd.AddCommand(bashPolicyExportCmd)
	bashPolicyCmd.AddCommand(bashPolicyActivationCmd)
	bashPolicyCmd.AddCommand(bashPolicyCodexReadinessCmd)

	bashPolicyEvaluateCmd.Flags().String("provider", "claude", "provider adapter: claude or codex")
	bashPolicyEvaluateCmd.Flags().String("mode", "dry-run", "activation: on, dry-run, or off")
	bashPolicyEvaluateCmd.Flags().String("policy-artifact-root", "", "durable root for bash policy artifacts")
	bashPolicyEvaluateCmd.Flags().StringArray("safe-root", nil, "canonical project/worktree root eligible for safe path checks")
	addJSONFlag(bashPolicyEvaluateCmd)

	bashPolicyReportCmd.Flags().String("provider", "claude", "provider report target")
	bashPolicyReportCmd.Flags().String("policy-artifact-root", "", "durable root for bash policy artifacts")
	bashPolicyReportCmd.Flags().String("claude-settings", "", "Claude settings JSON to seed Bash permission migration rows")

	bashPolicyExportCmd.Flags().String("provider", "claude", "provider export target")
	bashPolicyExportCmd.Flags().String("policy-artifact-root", "", "durable root for bash policy artifacts")
	bashPolicyExportCmd.Flags().String("claude-settings", "", "Claude settings JSON to seed Bash permission-family candidates")

	bashPolicyActivationCmd.Flags().String("provider", "all", "provider hook to update: claude, codex, or all")
	bashPolicyActivationCmd.Flags().String("policy-artifact-root", "", "durable root for bash policy artifacts")

	addJSONFlag(bashPolicyCodexReadinessCmd)
}

func optionalStdinReader(stdin *os.File) io.Reader {
	info, err := stdin.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return strings.NewReader("")
	}
	return stdin
}
