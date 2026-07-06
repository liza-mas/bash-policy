package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liza-mas/bash-policy/internal/bashpolicy"
	"github.com/liza-mas/bash-policy/internal/version"
)

func TestRunHelpDoesNotRequirePolicyInput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity([]string{"--help"}, strings.NewReader(""), &stdout, &stderr, version.BuildIdentity{})

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusOK)
	}
	if !strings.Contains(stdout.String(), "bash-policy --version") {
		t.Fatalf("stdout = %q, want usage", stdout.String())
	}
	if !strings.Contains(stdout.String(), "bash-policy report [--policy-artifact-root DIR] [--claude-settings PATH]") {
		t.Fatalf("stdout = %q, want provider-agnostic report usage", stdout.String())
	}
	if strings.Contains(stdout.String(), "bash-policy report [--provider") {
		t.Fatalf("stdout = %q, want report usage without provider filter", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunVersionUsesBuildIdentity(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"--version"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		version.BuildIdentity{SourceRef: "test", SourceRevision: "abc123"},
	)

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusOK)
	}
	if !strings.Contains(stdout.String(), "bash-policy source ref=test revision=abc123") {
		t.Fatalf("stdout = %q, want supplied build identity", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunRejectsUnsupportedShape(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity([]string{"check"}, strings.NewReader(""), &stdout, &stderr, version.BuildIdentity{})

	if got != statusUsage {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusUsage)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "check"`) {
		t.Fatalf("stderr = %q, want unknown command diagnostic", stderr.String())
	}
}

func TestRunEvaluateCLIJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	payload := `{"command":"git -C ` + root + ` status --short"}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"evaluate", "--policy-artifact-root", root, "--safe-root", root, "--json"},
		strings.NewReader(payload),
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d; stderr=%s", got, statusOK, stderr.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty for --json diagnostics", stderr.String())
	}
	var result bashpolicy.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid result JSON: %v\n%s", err, stdout.String())
	}
	if result.Decision != bashpolicy.DecisionAllow {
		t.Fatalf("decision = %s, want allow; result=%+v", result.Decision, result)
	}
}

func TestRunEvaluateCursorDryRunAllowsMalformedPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, bashpolicy.PolicyFileName), []byte("rules: [\n"), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"evaluate", "--provider", "cursor", "--mode", "dry-run", "--policy-artifact-root", root, "--safe-root", root},
		strings.NewReader(`{"command":"git status --short"}`),
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d; stderr=%s", got, statusOK, stderr.String())
	}
	var hookOutput map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &hookOutput); err != nil {
		t.Fatalf("invalid Cursor hook output: %v\n%s", err, stdout.String())
	}
	if got := hookOutput["permission"]; got != "allow" {
		t.Fatalf("permission = %v, want allow for dry-run setup failure; output=%s", got, stdout.String())
	}
	if !strings.Contains(stderr.String(), "parse bash policy") {
		t.Fatalf("stderr missing policy parse failure:\n%s", stderr.String())
	}
}

func TestRunValidateCLI(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, bashpolicy.PolicyFileName), []byte(strings.Join([]string{
		"rules:",
		"- kind: command-shape",
		"  identity: gh pr view <number>",
		"  decision: allow",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"validate", "--policy-artifact-root", root},
		strings.NewReader(""),
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d; stderr=%s", got, statusOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Bash policy valid:") {
		t.Fatalf("stdout = %q, want validation summary", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunValidateCLIRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, bashpolicy.PolicyFileName), []byte(strings.Join([]string{
		"rules:",
		"- kind: command-shape",
		"  identity: gh pr view ...",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"validate", "--policy-artifact-root", root},
		strings.NewReader(""),
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusUsage {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusUsage)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{"bash policy validation failed", "rules[0].decision is required"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestRunReportUsesArtifactLogForTerminalStdin(t *testing.T) {
	policyRoot := t.TempDir()
	if err := bashpolicy.AppendDryRunEvent(policyRoot, "claude", bashpolicy.ActivationDryRun, bashpolicy.Result{
		Decision:     bashpolicy.DecisionManual,
		Reason:       "manual",
		Summary:      "gh issue view 123",
		CommandShape: "gh issue view <number>",
	}); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"report", "--policy-artifact-root", policyRoot},
		stdin,
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d; stderr=%s", got, statusOK, stderr.String())
	}
	var report bashpolicy.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid report JSON: %v\n%s", err, stdout.String())
	}
	if report.Total != 1 {
		t.Fatalf("report total = %d, want 1: %+v", report.Total, report)
	}
}

func TestRunReportRejectsProviderFlag(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity(
		[]string{"report", "--provider", "cursor"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		version.BuildIdentity{},
	)

	if got != statusUsage {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusUsage)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr missing undefined flag diagnostic:\n%s", stderr.String())
	}
}
