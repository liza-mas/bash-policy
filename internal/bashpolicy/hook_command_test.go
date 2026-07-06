package bashpolicy

import "testing"

func TestParseHookCommandAcceptsStandaloneShape(t *testing.T) {
	info, ok := ParseHookCommand(`/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`)

	if !ok {
		t.Fatal("expected standalone hook command to parse")
	}
	if info.Provider != "claude" || info.Activation != ActivationDryRun || info.PolicyArtifactRoot != "/project" || info.SafeRoot != "$CLAUDE_PROJECT_DIR" || info.Legacy {
		t.Fatalf("unexpected hook command info: %+v", info)
	}
}

func TestParseHookCommandAcceptsStandaloneCodexShape(t *testing.T) {
	info, ok := ParseHookCommand(`/opt/wrapper evaluate --provider codex --mode on --policy-artifact-root /project --safe-root "$PWD"`)

	if !ok {
		t.Fatal("expected Codex standalone hook command to parse")
	}
	if info.Provider != "codex" || info.Activation != ActivationOn || info.PolicyArtifactRoot != "/project" || info.SafeRoot != "$PWD" || info.Legacy {
		t.Fatalf("unexpected Codex hook command info: %+v", info)
	}
}

func TestParseHookCommandAcceptsStandaloneCursorShape(t *testing.T) {
	info, ok := ParseHookCommand(`/opt/wrapper evaluate --provider cursor --mode dry-run --policy-artifact-root /project --safe-root "$PWD"`)

	if !ok {
		t.Fatal("expected Cursor standalone hook command to parse")
	}
	if info.Provider != "cursor" || info.Activation != ActivationDryRun || info.PolicyArtifactRoot != "/project" || info.SafeRoot != "$PWD" || info.Legacy {
		t.Fatalf("unexpected Cursor hook command info: %+v", info)
	}
}

func TestParseHookCommandRejectsGenericEvaluateProviderCommand(t *testing.T) {
	if _, ok := ParseHookCommand(`/opt/tool evaluate --provider claude --mode dry-run`); ok {
		t.Fatal("generic evaluate provider command should not parse as a bash-policy hook")
	}
}

func TestParseHookCommandRequiresArtifactAndSafeRoots(t *testing.T) {
	tests := []string{
		`/opt/wrapper evaluate --provider codex --mode dry-run --safe-root "$PWD"`,
		`/opt/wrapper evaluate --provider codex --mode dry-run --policy-artifact-root /project`,
		`/opt/wrapper evaluate --provider codex --mode dry-run --policy-artifact-root --safe-root "$PWD"`,
		`/opt/wrapper evaluate --provider codex --mode dry-run --policy-artifact-root /project --safe-root --json`,
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			if _, ok := ParseHookCommand(command); ok {
				t.Fatal("expected malformed standalone hook command not to parse")
			}
		})
	}
}

func TestParseHookCommandAcceptsLegacyWrapperShape(t *testing.T) {
	info, ok := ParseHookCommand(`bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude off`)

	if !ok {
		t.Fatal("expected legacy wrapper hook command to parse")
	}
	if info.Provider != "claude" || info.Activation != ActivationOff || !info.Legacy {
		t.Fatalf("unexpected legacy hook command info: %+v", info)
	}
}

func TestParseHookCommandRejectsLegacyAuditAlias(t *testing.T) {
	if _, ok := ParseHookCommand(`bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude audit`); ok {
		t.Fatal("legacy audit alias should not parse as a supported activation")
	}
}

func TestRewriteHookCommandActivationRejectsNonHookOrInvalidActivation(t *testing.T) {
	if got, ok := RewriteHookCommandActivation(`/opt/tool evaluate --provider claude --mode dry-run`, ActivationOff); ok || got != "" {
		t.Fatalf("non-hook rewrite = (%q, %t), want empty false", got, ok)
	}
	if got, ok := RewriteHookCommandActivation(`/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`, "audit"); ok || got != "" {
		t.Fatalf("invalid activation rewrite = (%q, %t), want empty false", got, ok)
	}
}

func TestRewriteHookCommandActivation(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "standalone space flag",
			command: `/opt/wrapper evaluate --provider claude --mode dry-run --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`,
			want:    `/opt/wrapper evaluate --provider claude --mode off --policy-artifact-root /project --safe-root "$CLAUDE_PROJECT_DIR"`,
		},
		{
			name:    "standalone equals flag",
			command: `/opt/wrapper evaluate --provider=codex --mode=dry-run --policy-artifact-root=/project --safe-root="$PWD"`,
			want:    `/opt/wrapper evaluate --provider=codex --mode=off --policy-artifact-root=/project --safe-root="$PWD"`,
		},
		{
			name:    "legacy wrapper",
			command: `bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude dry-run`,
			want:    `bash "$CLAUDE_PROJECT_DIR/.claude/hooks/bash-policy.sh" claude off`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := RewriteHookCommandActivation(tt.command, ActivationOff)
			if !ok {
				t.Fatal("expected rewrite to succeed")
			}
			if got != tt.want {
				t.Fatalf("rewritten command = %q, want %q", got, tt.want)
			}
		})
	}
}
