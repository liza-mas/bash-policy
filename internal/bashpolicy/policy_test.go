package bashpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestEvaluateAllowsSafeReadOnlyGitForms(t *testing.T) {
	root := t.TempDir()

	tests := []string{
		"cd " + root + " && git status --short",
		"git -C " + root + " diff --stat",
		"git -C " + root + " diff -- README.md",
		"git show :README.md",
		"git worktree list --porcelain",
		"rg --line-number TODO -- " + root,
		"rg --files " + root,
		"rtk rg TODO -- " + root,
		"rtk git diff --stat",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			result := Evaluate(Request{Command: command, ProjectRoot: root})
			if result.Decision != DecisionAllow {
				t.Fatalf("decision = %s, want allow; reason=%s summary=%s", result.Decision, result.Reason, result.Summary)
			}
		})
	}
}

func TestEvaluateAllowsSafeReadOnlyUnixForms(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("alpha:one\nbeta:two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "OTHER.md"), []byte("alpha:one\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []string{
		"basename README.md",
		"cat -n README.md",
		"cd " + root,
		"cut -d: -f1 README.md",
		"date +%Y",
		"diff -u README.md OTHER.md",
		"dirname README.md",
		"echo ok",
		"file README.md",
		"head -n 20 README.md",
		"ls -la .",
		"pwd",
		"realpath README.md",
		"sha256sum README.md",
		"sort -u README.md",
		"tail -n 20 README.md",
		"tr -d a",
		"tree -L 2 .",
		"uniq README.md",
		"wc -l README.md",
		"which git",
		"rtk sort README.md",
	}

	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			result := Evaluate(Request{Command: command, ProjectRoot: root})
			if result.Decision != DecisionAllow {
				t.Fatalf("decision = %s, want allow; reason=%s summary=%s", result.Decision, result.Reason, result.Summary)
			}
		})
	}
}

func TestBuiltInShapeCoverageMatchesEvaluator(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("alpha:one\nbeta:two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "OTHER.md"), []byte("alpha:one\n"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		command   string
		wantAllow bool
	}{
		{command: "cat README.md", wantAllow: true},
		{command: "cat -- README.md", wantAllow: true},
		{command: "date +%Y", wantAllow: true},
		{command: "date -d tomorrow", wantAllow: true},
		{command: "sort README.md", wantAllow: true},
		{command: "rtk sort README.md", wantAllow: true},
		{command: "diff -u README.md OTHER.md", wantAllow: true},
		{command: "git status --short", wantAllow: true},
		{command: "git show README.md", wantAllow: true},
		{command: "git show :README.md", wantAllow: true},
		{command: "git show 18d1fd84 -- README.md", wantAllow: true},
		{command: "cat .env", wantAllow: false},
		{command: "git show .env", wantAllow: false},
		{command: "date -date", wantAllow: false},
		{command: "sort --output out.txt README.md", wantAllow: false},
		{command: "head /tmp/outside", wantAllow: false},
		{command: "find . -type f", wantAllow: false},
		{command: "rg --pre TODO", wantAllow: false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			result := Evaluate(Request{Command: tt.command, ProjectRoot: root})
			gotAllow := result.Decision == DecisionAllow
			if gotAllow != tt.wantAllow {
				t.Fatalf("decision = %s, want allow=%t; reason=%s summary=%s shape=%s", result.Decision, tt.wantAllow, result.Reason, result.Summary, result.CommandShape)
			}
			gotCovered := BuiltInCoversCommandShape(result.CommandShape)
			if gotCovered != gotAllow {
				t.Fatalf("BuiltInCoversCommandShape(%q) = %t, want %t to match evaluator allow decision; result=%+v", result.CommandShape, gotCovered, gotAllow, result)
			}
		})
	}
}

func TestResolveInteractivePolicyArtifactRootDiscoversPolicyFileUpward(t *testing.T) {
	t.Setenv("BASH_POLICY_ARTIFACT_ROOT", "")
	root := t.TempDir()
	nested := filepath.Join(root, "worktree", "child")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, PolicyFileName), []byte("rules: []\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()
	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveInteractivePolicyArtifactRoot("")
	if err != nil {
		t.Fatalf("ResolveInteractivePolicyArtifactRoot failed: %v", err)
	}
	want, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("artifact root = %q, want %q", got, filepath.Clean(want))
	}
}

func TestValidatePolicyFileAcceptsSupportedRuleKinds(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, PolicyFileName)
	if err := os.WriteFile(path, []byte(strings.Join([]string{
		"rules:",
		"  - kind: command-shape",
		"    identity: gh pr view <number> --json <fields>",
		"    decision: allow",
		"  - kind: permission-family",
		"    identity: Bash(gh:*)",
		"    status: resolved",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := ValidatePolicyFile(path)
	if err != nil {
		t.Fatalf("ValidatePolicyFile failed: %v", err)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("issues = %+v, want none", result.Issues)
	}
	if result.RuleCount != 2 {
		t.Fatalf("rule count = %d, want 2", result.RuleCount)
	}
}

func TestValidatePolicyFileReportsSchemaIssues(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, PolicyFileName)
	if err := os.WriteFile(path, []byte(strings.Join([]string{
		"rules:",
		"  - kind: command-shape",
		"    identity: gh pr view ...",
		"  - kind: permission-family",
		"    identity: gh",
		"    decision: allow",
		"  - kind: other",
		"    identity: noop",
		"    decision: allow",
		"",
	}, "\n")), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := ValidatePolicyFile(path)
	if err != nil {
		t.Fatalf("ValidatePolicyFile failed: %v", err)
	}
	messages := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		messages = append(messages, issue.String())
	}
	joined := strings.Join(messages, "\n")
	for _, want := range []string{
		"line 2:5: rules[0].decision is required",
		"line 3:15: rules[0].identity is not a usable command-shape identity",
		"line 6:15: rules[1].decision is not supported for permission-family rules",
		"line 5:15: rules[1].identity must be a canonical Bash(<family>:*) permission family",
		"line 7:11: rules[2].kind must be \"command-shape\" or \"permission-family\"",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("issues missing %q:\n%s", want, joined)
		}
	}
}

func TestBuiltInCoversFreeFormEchoShapesOnlyForEchoProfile(t *testing.T) {
	if !BuiltInCoversCommandShape(`echo "=== <redacted> @ activation ==="`) {
		t.Fatal("redacted echo shape should be covered by the built-in echo profile")
	}
	if !BuiltInCoversCommandShape("echo <safe-path>") {
		t.Fatal("safe-path echo shape should be covered by the built-in echo profile")
	}
	if BuiltInCoversCommandShape("echo /tmp/outside") {
		t.Fatal("absolute echo path should not bypass path safety")
	}
	if BuiltInCoversCommandShape("echo ../outside") {
		t.Fatal("parent-relative echo path should not bypass path safety")
	}
	if BuiltInCoversCommandShape("echo <number>") {
		t.Fatal("unsupported echo placeholder should not be covered")
	}
	if BuiltInCoversCommandShape("head --lines=<redacted> <safe-path>") {
		t.Fatal("redacted inline flag values should not be covered")
	}
	if BuiltInCoversCommandShape("head -n <redacted> <safe-path>") {
		t.Fatal("redacted space-form flag values should not be covered")
	}
	if BuiltInCoversCommandShape("tr <redacted> x") {
		t.Fatal("redacted operands should not be covered for profiles that do not opt in")
	}
}

func TestEvaluateRejectsUnsafeCommandShapes(t *testing.T) {
	root := t.TempDir()

	tests := []struct {
		name    string
		command string
		want    Decision
	}{
		{name: "branch delete", command: "git branch -D topic", want: DecisionDeny},
		{name: "remote add", command: "git remote add origin https://example.invalid/repo.git", want: DecisionDeny},
		{name: "reset hard", command: "git reset --hard", want: DecisionDeny},
		{name: "printenv", command: "printenv", want: DecisionDeny},
		{name: "credential path", command: "cat .env", want: DecisionDeny},
		{name: "git show ssh key object path", command: "git show HEAD:id_rsa", want: DecisionDeny},
		{name: "git show nested ssh key object path", command: "git show HEAD:config/id_rsa", want: DecisionDeny},
		{name: "git show env object path", command: "git show HEAD:.env", want: DecisionDeny},
		{name: "secret search", command: "rg TOKEN ~/.ssh", want: DecisionDeny},
		{name: "rg execution pre-hook", command: "rg --pre 'go test' TODO", want: DecisionManual},
		{name: "rg pattern file", command: "rg --file patterns.txt", want: DecisionManual},
		{name: "rg combined zip and pattern-file flags", command: "rg -zf patterns.txt", want: DecisionManual},
		{name: "rg hidden search", command: "rg --hidden TODO", want: DecisionManual},
		{name: "rg hidden files", command: "rg --files --hidden", want: DecisionManual},
		{name: "sort output flag", command: "sort --output out.txt README.md", want: DecisionManual},
		{name: "uniq output operand", command: "uniq README.md out.txt", want: DecisionManual},
		{name: "wc files from flag", command: "wc --files0-from list.txt", want: DecisionManual},
		{name: "sha256sum check", command: "sha256sum --check checksums.txt", want: DecisionManual},
		{name: "date set", command: "date -s tomorrow", want: DecisionManual},
		{name: "tail follow", command: "tail -f README.md", want: DecisionManual},
		{name: "head outside safe root", command: "head /tmp/outside", want: DecisionManual},
		{name: "find remains manual", command: "find . -type f", want: DecisionManual},
		{name: "rtk proxy", command: "rtk proxy git status", want: DecisionDeny},
		{name: "subshell", command: "echo $(git status)", want: DecisionManual},
		{name: "pipeline", command: "git status | cat", want: DecisionManual},
		{name: "redirection", command: "git status > status.txt", want: DecisionManual},
		{name: "shell wrapper", command: "bash -c 'git status'", want: DecisionManual},
		{name: "worktree missing list", command: "git worktree --porcelain", want: DecisionManual},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Evaluate(Request{Command: tt.command, ProjectRoot: root})
			if result.Decision != tt.want {
				t.Fatalf("decision = %s, want %s; reason=%s summary=%s", result.Decision, tt.want, result.Reason, result.Summary)
			}
		})
	}
}

func TestEvaluateProjectPolicyRulesAfterSafetyFloor(t *testing.T) {
	root := t.TempDir()
	policy := &Policy{Rules: []PolicyRule{
		{Kind: "command-shape", Identity: "gh pr view <number>", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "git diff --cached <safe-path>...", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "git reset --hard", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "rg --pre TODO", Decision: DecisionAllow},
	}}

	allowed := Evaluate(Request{Command: "gh pr view 123", ProjectRoot: root, Policy: policy})
	if allowed.Decision != DecisionAllow {
		t.Fatalf("configured gh decision = %s, want allow; result=%+v", allowed.Decision, allowed)
	}
	if allowed.CommandShape != "gh pr view <number>" {
		t.Fatalf("configured command shape = %q, want normalized shape", allowed.CommandShape)
	}

	rtkAllowed := Evaluate(Request{Command: "rtk gh pr view 123", ProjectRoot: root, Policy: policy})
	if rtkAllowed.Decision != DecisionAllow {
		t.Fatalf("configured rtk command decision = %s, want allow; result=%+v", rtkAllowed.Decision, rtkAllowed)
	}
	if rtkAllowed.Summary != "rtk gh pr view 123" {
		t.Fatalf("configured rtk command summary = %q, want literal wrapped command", rtkAllowed.Summary)
	}
	if rtkAllowed.CommandShape != "gh pr view <number>" {
		t.Fatalf("configured rtk command shape = %q, want unwrapped normalized shape", rtkAllowed.CommandShape)
	}

	singlePath := Evaluate(Request{Command: "git diff --cached internal/policy.go", ProjectRoot: root, Policy: policy})
	if singlePath.Decision != DecisionAllow {
		t.Fatalf("configured variadic git decision = %s, want allow; result=%+v", singlePath.Decision, singlePath)
	}
	if singlePath.CommandShape != "git diff --cached <safe-path>" {
		t.Fatalf("configured variadic command shape = %q, want normalized concrete shape", singlePath.CommandShape)
	}

	multiPath := Evaluate(Request{Command: "git diff --cached internal/policy.go internal/policy_test.go", ProjectRoot: root, Policy: policy})
	if multiPath.Decision != DecisionAllow {
		t.Fatalf("configured variadic multi-path git decision = %s, want allow; result=%+v", multiPath.Decision, multiPath)
	}
	if multiPath.CommandShape != "git diff --cached <safe-path> <safe-path>" {
		t.Fatalf("configured variadic multi-path command shape = %q, want normalized concrete shape", multiPath.CommandShape)
	}

	destructive := Evaluate(Request{Command: "git reset --hard", ProjectRoot: root, Policy: policy})
	if destructive.Decision != DecisionDeny {
		t.Fatalf("destructive git policy decision = %s, want deny; result=%+v", destructive.Decision, destructive)
	}

	rgExec := Evaluate(Request{Command: "rg --pre TODO", ProjectRoot: root, Policy: policy})
	if rgExec.Decision != DecisionManual {
		t.Fatalf("rg execution flag policy decision = %s, want manual; result=%+v", rgExec.Decision, rgExec)
	}
}

func TestPolicyCommandRuleSupportsTerminalVariadicPlaceholder(t *testing.T) {
	policy := &Policy{Rules: []PolicyRule{
		{Kind: "command-shape", Identity: "git diff --cached <safe-path>...", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "gh pr view <number>", Decision: DecisionManual},
		{Kind: "command-shape", Identity: `echo "=== staged separator (line 579) ==="`, Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "sed -n <number>,<number>p", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "tool <fields>.json", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "bad <safe-path>.bak", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "bad <safe-path>... suffix", Decision: DecisionAllow},
		{Kind: "permission-family", Identity: "git diff --cached <safe-path>...", Decision: DecisionDeny},
	}}

	matches := []string{
		"git diff --cached <safe-path>",
		"git diff --cached <safe-path> <safe-path>",
		"git diff --cached <safe-path> <safe-path> <safe-path>",
		"gh pr view <number>",
		`echo "=== staged separator (line 579) ==="`,
		"sed -n 1,140p",
		"tool title,body.json",
	}
	for _, identity := range matches {
		if _, ok := policy.CommandRule(identity); !ok {
			t.Fatalf("CommandRule(%q) did not match", identity)
		}
	}

	nonMatches := []string{
		"git diff --cached",
		"git diff --cached <number>",
		"git diff --cached <safe-path> --stat",
		"git diff <safe-path>",
		"sed -n a,140p",
		"sed -n 1,140q",
		"bad README.md.bak",
		"bad <safe-path> suffix",
	}
	for _, identity := range nonMatches {
		if rule, ok := policy.CommandRule(identity); ok {
			t.Fatalf("CommandRule(%q) matched %+v, want no match", identity, rule)
		}
	}
}

func FuzzCommandShapeFieldsRoundTrip(f *testing.F) {
	seeds := [][3]string{
		{"plain", "two words", ""},
		{"|", `quote"inside`, "line\nbreak"},
		{"<safe-path>", "<number>,<number>p", `back\slash`},
	}
	for _, seed := range seeds {
		f.Add(seed[0], seed[1], seed[2])
	}

	f.Fuzz(func(t *testing.T, first string, second string, third string) {
		fields := []string{first, second, third}
		identity := joinCommandShapeFields(fields)
		got, ok := commandShapeFields(identity)
		if !ok {
			t.Fatalf("commandShapeFields(%q) failed", identity)
		}
		if !slices.Equal(got, fields) {
			t.Fatalf("round trip = %#v, want %#v for identity %q", got, fields, identity)
		}
	})
}

func TestEvaluateBuildsCanonicalCompoundCommandShapes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "internal", "bashpolicy", "policy.go")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package bashpolicy\n"), 0644); err != nil {
		t.Fatal(err)
	}

	command := `git status --porcelain=v1 | grep -i bashpolicy; echo "---commands---"; git diff --cached internal/bashpolicy/policy.go`
	wantShape := "git status --porcelain=v1 | grep -i bashpolicy ; echo ---commands--- ; git diff --cached <safe-path>"

	result := Evaluate(Request{Command: command, ProjectRoot: root})
	if result.Decision != DecisionManual {
		t.Fatalf("compound decision = %s, want manual; result=%+v", result.Decision, result)
	}
	if result.CommandShape != wantShape {
		t.Fatalf("compound command shape = %q, want %q", result.CommandShape, wantShape)
	}
	if strings.Contains(result.CommandShape, "...") {
		t.Fatalf("compound command shape is truncated: %q", result.CommandShape)
	}

	policy := &Policy{Rules: []PolicyRule{
		{
			Kind:     "command-shape",
			Identity: "grep -i bashpolicy",
			Decision: DecisionAllow,
		},
		{
			Kind:     "command-shape",
			Identity: "git diff --cached <safe-path>",
			Decision: DecisionAllow,
		},
	}}
	allowed := Evaluate(Request{Command: command, ProjectRoot: root, Policy: policy})
	if allowed.Decision != DecisionAllow {
		t.Fatalf("configured leaf decision = %s, want allow for compound command; result=%+v", allowed.Decision, allowed)
	}
	if allowed.CommandShape != wantShape {
		t.Fatalf("configured compound command shape = %q, want %q", allowed.CommandShape, wantShape)
	}

	redirection := Evaluate(Request{Command: "git status > status.txt", ProjectRoot: root})
	if redirection.Decision != DecisionManual {
		t.Fatalf("redirection decision = %s, want manual; result=%+v", redirection.Decision, redirection)
	}
	if redirection.CommandShape != "" {
		t.Fatalf("redirection command shape = %q, want empty unsafe shell shape", redirection.CommandShape)
	}
}

func TestEvaluateDoesNotAllowPathsOutsideSafeRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "safe")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "link-to-outside")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	tests := []string{
		"cd " + link + " && git status",
		"git -C " + filepath.Join(root, "..", "outside") + " status",
		"git -C /tmp status",
	}
	for _, command := range tests {
		t.Run(command, func(t *testing.T) {
			result := Evaluate(Request{Command: command, ProjectRoot: root})
			if result.Decision == DecisionAllow {
				t.Fatalf("decision = allow, want non-allow; reason=%s summary=%s", result.Reason, result.Summary)
			}
		})
	}
}

func TestCommandFromHookPayloadFindsProviderCommandShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "claude tool input",
			payload: []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status --short"}}`),
			want:    "git status --short",
		},
		{
			name:    "codex tool input",
			payload: []byte(`{"type":"pre_tool_use","tool":{"name":"Bash","input":{"command":"git diff --stat"}}}`),
			want:    "git diff --stat",
		},
		{
			name:    "deeply nested command",
			payload: []byte(`{"outer":[{"inner":{"command":"rtk git diff --stat"}}]}`),
			want:    "rtk git diff --stat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, err := CommandFromHookPayload(tt.payload)
			if err != nil {
				t.Fatalf("CommandFromHookPayload failed: %v", err)
			}
			if command != tt.want {
				t.Fatalf("command = %q, want %q", command, tt.want)
			}
		})
	}
}

func TestBuildReportRedactsSummariesAndAddsMigrationEvidence(t *testing.T) {
	results := []Result{
		{Decision: DecisionDeny, Reason: "secret", Summary: "rg TOKEN ~/.ssh API_KEY=abc A7vC4zF9mQ2pL6sT8xY1nB3dE5gH7jK9", CommandFamily: "rg"},
		{Decision: DecisionAllow, Reason: "read-only git status", Summary: "git status --short", CommandFamily: "git"},
		{Decision: DecisionDeny, Reason: "environment dump commands are not safe", Summary: "printenv", CommandFamily: "printenv"},
	}

	report := BuildReport(results, ReportOptions{
		CandidatePermissions: []string{"Bash(git:*)", "Bash(printenv:*)", "Bash(rg:*)", "Bash(sort:*)"},
	})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, leaked := range []string{"TOKEN", ".ssh", "API_KEY=abc", "A7vC4zF9mQ2pL6sT8xY1nB3dE5gH7jK9"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("report leaked %q:\n%s", leaked, text)
		}
	}

	var gitRow *PermissionMigrationRow
	var printenvRow *PermissionMigrationRow
	for i := range report.Migration {
		switch report.Migration[i].Permission {
		case "Bash(git:*)":
			gitRow = &report.Migration[i]
		case "Bash(printenv:*)":
			printenvRow = &report.Migration[i]
		}
	}
	if gitRow == nil || gitRow.ProposedStatus != "specialize" || len(gitRow.Examples) != 1 || gitRow.Examples[0] != "git status --short" {
		t.Fatalf("unexpected git migration row: %+v", gitRow)
	}
	if printenvRow == nil || printenvRow.ProposedStatus != "deny/manual" || len(printenvRow.Examples) != 1 || printenvRow.Examples[0] != "printenv" {
		t.Fatalf("unexpected printenv migration row: %+v", printenvRow)
	}
	for _, row := range report.Migration {
		if row.Permission == "Bash(rg:*)" {
			t.Fatalf("built-in rg family should not be reported as unresolved: %+v", row)
		}
		if row.Permission == "Bash(sort:*)" {
			t.Fatalf("built-in read-only unix family should not be reported as unresolved: %+v", row)
		}
	}
}

func TestBuildCandidatesOmitsBuiltInsResolvedFamiliesAndCuratedShapes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "internal", "bashpolicy", "policy.go")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package bashpolicy\n"), 0644); err != nil {
		t.Fatal(err)
	}

	policy := &Policy{Rules: []PolicyRule{
		{Kind: "permission-family", Identity: "Bash(gh:*)", Status: "resolved"},
		{Kind: "command-shape", Identity: "git status --short", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "git diff --cached <safe-path>...", Decision: DecisionAllow},
		{Kind: "command-shape", Identity: "gh pr checkout <number> <safe-path>...", Decision: DecisionAllow},
	}}
	events := []Event{
		{Provider: "claude", Decision: DecisionManual, CommandShape: "git status --short"},
		{Provider: "claude", Decision: DecisionManual, Summary: "git diff --cached internal/bashpolicy/policy.go", CommandShape: "git diff --cached internal/bashpolicy/policy.go"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "gh pr view <number>"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "gh pr checkout <number> <safe-path> <safe-path>"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "rg TODO -- <safe-path>"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "rtk rg TODO -- <safe-path>"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "rg --pre TODO"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "sort README.md"},
		{Provider: "claude", Decision: DecisionManual, CommandShape: "rtk sort README.md"},
		{
			Provider:     "claude",
			Decision:     DecisionManual,
			Summary:      `echo "=== staged separator (line 579) ==="; git show internal/bashpolicy/policy.go`,
			CommandShape: `echo "=== staged separator (line 579) ===" ; git show <safe-path>`,
		},
		{Provider: "claude", Decision: DecisionManual, Summary: "go test ./internal/bashpolicy/ -run TestZZProbe...", CommandShape: "go test ./internal/bashpolicy/ -run TestZZProbe..."},
		{Provider: "claude", Decision: DecisionAllow, CommandShape: "rg TODO -- <safe-path>"},
		{Provider: "codex", Decision: DecisionManual, CommandShape: "gh issue list"},
	}

	candidates := BuildCandidates("claude", []string{
		"Bash(rg:*)",
		"Bash(sort:*)",
		"Bash(gh:*)",
		"Bash(rtk:*)",
		"Bash(rtk grep:*)",
		"Bash(rtk proxy:*)",
		"Bash(printenv:*)",
	}, policy, events, root)

	got := map[string]Candidate{}
	for _, candidate := range candidates.Candidates {
		got[candidate.Kind+":"+candidate.Identity] = candidate
	}
	if _, ok := got["permission-family:Bash(printenv:*)"]; !ok {
		t.Fatalf("missing unresolved printenv permission-family candidate: %+v", candidates.Candidates)
	}
	if _, ok := got["permission-family:Bash(grep:*)"]; !ok {
		t.Fatalf("missing unwrapped grep permission-family candidate: %+v", candidates.Candidates)
	}
	if _, ok := got["command-shape:gh pr view <number>"]; !ok {
		t.Fatalf("missing unresolved gh command-shape candidate: %+v", candidates.Candidates)
	}
	if _, ok := got["command-shape:rg --pre TODO"]; !ok {
		t.Fatalf("missing unresolved unsupported rg command-shape candidate: %+v", candidates.Candidates)
	}
	for _, unexpected := range []string{
		"permission-family:Bash(rg:*)",
		"permission-family:Bash(sort:*)",
		"permission-family:Bash(gh:*)",
		"permission-family:Bash(rtk:*)",
		"permission-family:Bash(rtk grep:*)",
		"permission-family:Bash(rtk proxy:*)",
		"command-shape:git status --short",
		"command-shape:git diff --cached internal/bashpolicy/policy.go",
		"command-shape:git diff --cached <safe-path>",
		"command-shape:gh pr checkout <number> <safe-path> <safe-path>",
		"command-shape:rg TODO -- <safe-path>",
		"command-shape:rtk rg TODO -- <safe-path>",
		"command-shape:sort README.md",
		"command-shape:rtk sort README.md",
		`command-shape:echo "=== staged separator (line 579) ===" ; git show <safe-path>`,
		`command-shape:echo "=== staged separator (line 579) ==="`,
		"command-shape:git show <safe-path>",
		"command-shape:go test ./internal/bashpolicy/ -run TestZZProbe...",
		"command-shape:gh issue list",
	} {
		if _, ok := got[unexpected]; ok {
			t.Fatalf("unexpected candidate %s in %+v", unexpected, candidates.Candidates)
		}
	}
	for _, candidate := range candidates.Candidates {
		if strings.Contains(candidate.Identity, "TestZZProbe...") {
			t.Fatalf("candidate identity is truncated: %+v", candidate)
		}
	}
}

func TestDryRunCandidatesUseCanonicalCommandShapeIdentities(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "internal", "bashpolicy", "policy.go")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package bashpolicy\n"), 0644); err != nil {
		t.Fatal(err)
	}

	command := "git diff --cached internal/bashpolicy/policy.go"
	result := Evaluate(Request{Command: command, ProjectRoot: root})
	if result.Decision != DecisionManual {
		t.Fatalf("decision = %s, want manual; result=%+v", result.Decision, result)
	}
	if result.Summary != command {
		t.Fatalf("summary = %q, want display command %q", result.Summary, command)
	}
	if result.CommandShape != "git diff --cached <safe-path>" {
		t.Fatalf("command shape = %q, want canonical safe-path shape", result.CommandShape)
	}
	if err := AppendDryRunEvent(root, "claude", ActivationDryRun, result); err != nil {
		t.Fatal(err)
	}

	rtkCommand := "rtk " + command
	rtkResult := Evaluate(Request{Command: rtkCommand, ProjectRoot: root})
	if rtkResult.Decision != DecisionManual {
		t.Fatalf("rtk decision = %s, want manual; result=%+v", rtkResult.Decision, rtkResult)
	}
	if rtkResult.Summary != rtkCommand {
		t.Fatalf("rtk summary = %q, want display command %q", rtkResult.Summary, rtkCommand)
	}
	if rtkResult.CommandShape != "git diff --cached <safe-path>" {
		t.Fatalf("rtk command shape = %q, want unwrapped canonical safe-path shape", rtkResult.CommandShape)
	}
	if err := AppendDryRunEvent(root, "claude", ActivationDryRun, rtkResult); err != nil {
		t.Fatal(err)
	}

	compound := Evaluate(Request{Command: "git status; echo ok", ProjectRoot: root})
	if compound.Decision != DecisionAllow {
		t.Fatalf("covered compound decision = %s, want allow; result=%+v", compound.Decision, compound)
	}
	if compound.CommandShape != "git status ; echo ok" {
		t.Fatalf("compound command shape = %q, want canonical shell shape", compound.CommandShape)
	}
	if err := AppendDryRunEvent(root, "claude", ActivationDryRun, compound); err != nil {
		t.Fatal(err)
	}
	unresolvedCompound := Evaluate(Request{Command: "git status | grep bashpolicy; echo ok", ProjectRoot: root})
	if unresolvedCompound.Decision != DecisionManual {
		t.Fatalf("unresolved compound decision = %s, want manual; result=%+v", unresolvedCompound.Decision, unresolvedCompound)
	}
	if unresolvedCompound.CommandShape != "git status | grep bashpolicy ; echo ok" {
		t.Fatalf("unresolved compound command shape = %q, want canonical shell shape", unresolvedCompound.CommandShape)
	}
	if err := AppendDryRunEvent(root, "claude", ActivationDryRun, unresolvedCompound); err != nil {
		t.Fatal(err)
	}
	if err := AppendDryRunEvent(root, "claude", ActivationDryRun, Result{
		Decision:     DecisionManual,
		Summary:      `echo "=== sensitive marker @ activation ==="; grep bashpolicy`,
		CommandShape: `echo "=== <redacted> @ activation ===" ; grep bashpolicy`,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := ReadEvents(filepath.Join(root, DryRunLogFileName))
	if err != nil {
		t.Fatal(err)
	}
	candidates := BuildCandidates("claude", nil, nil, events)
	got := map[string]Candidate{}
	for _, candidate := range candidates.Candidates {
		got[candidate.Kind+":"+candidate.Identity] = candidate
	}
	canonical, ok := got["command-shape:git diff --cached <safe-path>"]
	if !ok {
		t.Fatalf("missing canonical command-shape candidate: %+v", candidates.Candidates)
	}
	if canonical.Observations != 2 {
		t.Fatalf("canonical candidate observations = %d, want wrapped and unwrapped observations", canonical.Observations)
	}
	if _, ok := got["command-shape:grep bashpolicy"]; !ok {
		t.Fatalf("missing unresolved compound leaf command-shape candidate: %+v", candidates.Candidates)
	}
	for _, unexpected := range []string{
		"command-shape:git diff --cached internal/bashpolicy/policy.go",
		"command-shape:rtk git diff --cached <safe-path>",
		"command-shape:rtk git diff --cached internal/bashpolicy/policy.go",
		"command-shape:git status",
		"command-shape:echo ok",
		`command-shape:echo "=== <redacted> @ activation ==="`,
		"command-shape:git status; echo ok",
		"command-shape:git status ; echo ok",
		"command-shape:git status | grep bashpolicy ; echo ok",
	} {
		if _, ok := got[unexpected]; ok {
			t.Fatalf("unexpected candidate %s in %+v", unexpected, candidates.Candidates)
		}
	}

	policy := &Policy{Rules: []PolicyRule{{
		Kind:     "command-shape",
		Identity: "git diff --cached <safe-path>",
		Decision: DecisionAllow,
	}}}
	allowed := Evaluate(Request{Command: command, ProjectRoot: root, Policy: policy})
	if allowed.Decision != DecisionAllow {
		t.Fatalf("curated canonical candidate decision = %s, want allow; result=%+v", allowed.Decision, allowed)
	}
	rtkAllowed := Evaluate(Request{Command: rtkCommand, ProjectRoot: root, Policy: policy})
	if rtkAllowed.Decision != DecisionAllow {
		t.Fatalf("curated canonical candidate for rtk decision = %s, want allow; result=%+v", rtkAllowed.Decision, rtkAllowed)
	}
}

func TestAppendDryRunEventConcurrentWritersProduceCompleteJSONL(t *testing.T) {
	root := t.TempDir()
	const writers = 32

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- AppendDryRunEvent(root, "claude", ActivationDryRun, Result{
				Decision:     DecisionManual,
				Reason:       "manual",
				Summary:      fmt.Sprintf("gh pr view %d", i),
				CommandShape: "gh pr view <number>",
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AppendDryRunEvent failed: %v", err)
		}
	}

	events, err := ReadEvents(filepath.Join(root, DryRunLogFileName))
	if err != nil {
		t.Fatalf("ReadEvents failed: %v", err)
	}
	if len(events) != writers {
		t.Fatalf("events = %d, want %d: %+v", len(events), writers, events)
	}
	for _, event := range events {
		if event.Timestamp == "" || event.Provider != "claude" || event.CommandShape != "gh pr view <number>" {
			t.Fatalf("unexpected event: %+v", event)
		}
	}
}

func TestLooksSensitiveRedactsHighEntropyTokensWithoutMaskingCommitSHA(t *testing.T) {
	if !LooksSensitive("A7vC4zF9mQ2pL6sT8xY1nB3dE5gH7jK9") {
		t.Fatal("mixed-class high-entropy token was not classified sensitive")
	}
	if !LooksSensitive("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456") {
		t.Fatal("known secret-looking token prefix was not classified sensitive")
	}
	if !LooksSensitive("id_rsa") || !LooksSensitive("config/id_ed25519") {
		t.Fatal("SSH private key path was not classified sensitive")
	}
	if LooksSensitive("0123456789abcdef0123456789abcdef01234567") {
		t.Fatal("plain hexadecimal commit-like value should not be classified sensitive")
	}
}

func TestExtractBashPermissionsSortsNestedPermissions(t *testing.T) {
	settings := []byte(`{
		"permissions": {
			"allow": ["Skill(test)", "Bash(printenv:*)"],
			"deny": [{"nested": "Bash(git reset:*)"}]
		}
	}`)

	got := ExtractBashPermissions(settings)
	want := []string{"Bash(git reset:*)", "Bash(printenv:*)"}
	if len(got) != len(want) {
		t.Fatalf("permissions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("permissions = %v, want %v", got, want)
		}
	}
}
