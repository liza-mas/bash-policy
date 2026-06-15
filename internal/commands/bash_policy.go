package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/liza-mas/bash-policy/internal/bashpolicy"
	"github.com/liza-mas/bash-policy/internal/embedded"
)

type BashPolicyEvaluateOptions struct {
	Provider           string
	Mode               string
	PolicyArtifactRoot string
	SafeRoots          []string
	JSON               bool
	Diagnostics        io.Writer
}

type BashPolicyReportOptions struct {
	Provider           string
	PolicyArtifactRoot string
	ClaudeSettings     string
}

type BashPolicyExportOptions struct {
	Provider           string
	PolicyArtifactRoot string
	ClaudeSettings     string
}

type BashPolicyActivationOptions struct {
	Provider           string
	Activation         string
	PolicyArtifactRoot string
	Command            string
	CommandOverride    bool
	Reader             *bufio.Reader
}

type BashPolicyInitOptions struct {
	Provider           string
	PolicyArtifactRoot string
	Command            string
	Reader             *bufio.Reader
}

func BashPolicyInitCommand(output io.Writer, projectRoot string, opts BashPolicyInitOptions) error {
	policyRoot, err := bashpolicy.ResolveRequiredPolicyArtifactRoot(firstNonEmpty(opts.PolicyArtifactRoot, projectRoot))
	if err != nil {
		return err
	}
	if strings.TrimSpace(opts.Command) == "" {
		return fmt.Errorf("bash-policy hook command is required")
	}
	if err := bashpolicy.EnsurePolicyArtifactIgnores(policyRoot); err != nil {
		return err
	}
	provider, err := normalizeProvider(opts.Provider, true)
	if err != nil {
		return err
	}
	if provider == "claude" || provider == "all" {
		if err := embedded.WriteClaudeSettings(projectRoot, policyRoot, opts.Command, opts.Reader); err != nil {
			return err
		}
	}
	if provider == "codex" || provider == "all" {
		if err := embedded.WriteCodexProjectHooks(projectRoot, policyRoot, opts.Command, opts.Reader); err != nil {
			return err
		}
	}
	fmt.Fprintf(output, "Bash policy initialized for %s\n", provider)
	return nil
}

func BashPolicyEvaluateCommand(input io.Reader, output io.Writer, opts BashPolicyEvaluateOptions) error {
	data, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("read hook input: %w", err)
	}
	command, err := bashpolicy.CommandFromHookPayload(data)
	if err != nil {
		return err
	}
	activation, err := bashpolicy.NormalizeActivation(opts.Mode)
	if err != nil {
		return err
	}
	if activation == bashpolicy.ActivationOff {
		return nil
	}
	policyRoot, rootErr := bashpolicy.ResolveRequiredPolicyArtifactRoot(opts.PolicyArtifactRoot)
	if rootErr != nil {
		if opts.Diagnostics != nil {
			fmt.Fprintf(opts.Diagnostics, "bash policy disabled: %v\n", rootErr)
		}
		return nil
	}
	policy, err := bashpolicy.LoadPolicy(policyRoot)
	if err != nil {
		return err
	}
	result := bashpolicy.Evaluate(bashpolicy.Request{
		Command:            command,
		ProjectRoot:        firstSafeRoot(opts.SafeRoots),
		SafeRoots:          opts.SafeRoots,
		PolicyArtifactRoot: policyRoot,
		Policy:             policy,
	})
	if opts.JSON {
		return json.NewEncoder(output).Encode(result)
	}
	if shouldWriteDiagnostics(activation) && policyRoot != "" {
		if err := bashpolicy.AppendDryRunEvent(policyRoot, opts.Provider, activation, result); err != nil {
			return err
		}
	}
	if shouldWriteDiagnostics(activation) && opts.Diagnostics != nil {
		if err := json.NewEncoder(opts.Diagnostics).Encode(result); err != nil {
			return fmt.Errorf("write bash policy diagnostics: %w", err)
		}
	}
	return writeProviderHookOutput(output, opts.Provider, activation, result)
}

func BashPolicyReportCommand(input io.Reader, output io.Writer, opts BashPolicyReportOptions) error {
	results, err := readPolicyResults(input)
	if err != nil {
		return err
	}
	var policy *bashpolicy.Policy
	policyRoot := ""
	if len(results) == 0 || opts.PolicyArtifactRoot != "" {
		policyRoot, err = bashpolicy.ResolveInteractivePolicyArtifactRoot(opts.PolicyArtifactRoot)
		if err != nil {
			if len(results) == 0 {
				return err
			}
		}
	}
	if len(results) == 0 && policyRoot != "" {
		events, err := bashpolicy.ReadEvents(filepath.Join(policyRoot, bashpolicy.DryRunLogFileName))
		if err != nil {
			return err
		}
		results = bashpolicy.ResultsFromEvents(events)
	}
	if policyRoot != "" {
		policy, err = bashpolicy.LoadPolicy(policyRoot)
		if err != nil {
			return err
		}
	}
	var permissions []string
	if opts.ClaudeSettings != "" {
		content, err := os.ReadFile(opts.ClaudeSettings)
		if err != nil {
			return fmt.Errorf("read Claude settings: %w", err)
		}
		permissions = bashpolicy.ExtractBashPermissions(content)
	}
	report := bashpolicy.BuildReport(results, bashpolicy.ReportOptions{CandidatePermissions: permissions, Policy: policy})
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func BashPolicyExportCommand(output io.Writer, opts BashPolicyExportOptions) error {
	policyRoot, err := bashpolicy.ResolveInteractivePolicyArtifactRoot(opts.PolicyArtifactRoot)
	if err != nil {
		return err
	}
	if err := bashpolicy.EnsurePolicyArtifactIgnores(policyRoot); err != nil {
		return err
	}
	policy, err := bashpolicy.LoadPolicy(policyRoot)
	if err != nil {
		return err
	}
	var permissions []string
	if opts.ClaudeSettings != "" {
		content, err := os.ReadFile(opts.ClaudeSettings)
		if err != nil {
			return fmt.Errorf("read Claude settings: %w", err)
		}
		permissions = bashpolicy.ExtractBashPermissions(content)
	}
	events, err := bashpolicy.ReadEvents(filepath.Join(policyRoot, bashpolicy.DryRunLogFileName))
	if err != nil {
		return err
	}
	candidates := bashpolicy.BuildCandidates(opts.Provider, permissions, policy, events, policyRoot)
	candidatesPath := filepath.Join(policyRoot, bashpolicy.CandidatesFileName)
	if err := bashpolicy.WriteCandidates(candidatesPath, candidates); err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{
		"path":       candidatesPath,
		"candidates": len(candidates.Candidates),
	})
}

func BashPolicyActivationCommand(output io.Writer, projectRoot string, opts BashPolicyActivationOptions) error {
	activation, err := bashpolicy.NormalizeActivation(opts.Activation)
	if err != nil {
		return err
	}
	policyRoot, err := bashpolicy.ResolveRequiredPolicyArtifactRoot(firstNonEmpty(opts.PolicyArtifactRoot, projectRoot))
	if err != nil {
		return err
	}
	if err := bashpolicy.EnsurePolicyArtifactIgnores(policyRoot); err != nil {
		return err
	}
	if strings.TrimSpace(opts.Command) == "" {
		return fmt.Errorf("bash-policy hook command is required")
	}
	provider, err := normalizeProvider(opts.Provider, true)
	if err != nil {
		return err
	}
	if provider == "claude" || provider == "all" {
		if err := updateClaudeBashPolicyActivation(projectRoot, policyRoot, opts.Command, activation, opts.CommandOverride); err != nil {
			return err
		}
	}
	if provider == "codex" || provider == "all" {
		if err := updateCodexBashPolicyActivation(projectRoot, policyRoot, opts.Command, activation, opts.CommandOverride); err != nil {
			return err
		}
	}
	fmt.Fprintf(output, "Bash policy activation set to %s for %s\n", activation, provider)
	return nil
}

func BashPolicyCodexReadinessCommand(output io.Writer, projectRoot string, jsonOutput bool) error {
	readiness := bashpolicy.AssessCodexReadiness(projectRoot)
	if jsonOutput {
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(readiness)
	}
	fmt.Fprintf(output, "Codex bash policy readiness: %s\n", readiness.Status)
	for _, check := range readiness.Checks {
		marker := "FAIL"
		if check.OK {
			marker = "OK"
		}
		fmt.Fprintf(output, "- %s: %s - %s\n", marker, check.Name, check.Message)
	}
	return nil
}

func writeProviderHookOutput(output io.Writer, provider string, mode string, result bashpolicy.Result) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	mode = strings.ToLower(strings.TrimSpace(mode))
	// Deny is logged but not provider-enforced yet; this hook only emits verified Claude allow decisions.
	if provider == "claude" && mode == bashpolicy.ActivationOn && result.Decision == bashpolicy.DecisionAllow {
		shape := result.CommandShape
		if shape == "" {
			shape = result.Summary
		}
		payload := map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "allow",
				"permissionDecisionReason": result.Reason,
				"bashPolicyCommandShape":   shape,
			},
		}
		return json.NewEncoder(output).Encode(payload)
	}
	return nil
}

func shouldWriteDiagnostics(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case bashpolicy.ActivationDryRun, bashpolicy.ActivationOn:
		return true
	default:
		return false
	}
}

func readPolicyResults(input io.Reader) ([]bashpolicy.Result, error) {
	var results []bashpolicy.Result
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var result bashpolicy.Result
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, fmt.Errorf("parse result JSONL: %w", err)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read result JSONL: %w", err)
	}
	return results, nil
}

func firstSafeRoot(roots []string) string {
	if len(roots) == 0 {
		return ""
	}
	return roots[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func normalizeProvider(provider string, allowAll bool) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(provider))
	if normalized == "" {
		if allowAll {
			return "all", nil
		}
		return "claude", nil
	}
	if normalized == "claude" || normalized == "codex" || allowAll && normalized == "all" {
		return normalized, nil
	}
	if allowAll {
		return "", fmt.Errorf("unsupported bash policy provider %q (want claude, codex, or all)", provider)
	}
	return "", fmt.Errorf("unsupported bash policy provider %q (want claude or codex)", provider)
}
