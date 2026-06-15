# Configuration Reference

## Two-Layer Architecture

Claude Code unions permissions from global and project settings:

| Layer | File | Managed by | Contains |
|-------|------|-----------|----------|
| **Project** | `<project>/.claude/settings.json` | `liza init` (automatic) | Liza CLI permissions, skills, git/build commands |
| **Global** | `~/.claude/settings.json` | Manual (one-time) | Personal MCP tools (IDE, search, etc.), machine-specific permissions |

The project layer is portable (team-shared). The global layer is machine-specific (personal tools and paths). Neither alone is sufficient — both are needed.

For global setup and project activation, use `liza setup` and `liza init`.

Liza also installs `.claude/hooks/bash-policy.sh` after the existing init, git,
and RTK guards. The hook calls `liza bash-policy evaluate --provider claude` and
starts in dry-run mode from the embedded settings, so it records redacted policy
decisions under the durable policy artifact root without changing Claude
permission behavior. `on` activation is reserved for rollout phases where hook
precedence and hard-deny preservation have been verified; `off` keeps the
managed hook entry explicit but inactive.

For Bash policy commands, `.claude/settings.json` is Claude's project settings
file, not the Bash policy file:

| Command | How `.claude/settings.json` is used |
|---------|-------------------------------------|
| `liza init --claude` | Writes or merges the embedded Claude settings template and installs the hooks referenced by it. |
| `liza bash-policy activation ... --provider claude` | Updates the managed Bash policy hook entry in Claude settings. |
| `liza bash-policy evaluate` | Does not read Claude settings; runtime decisions come from built-ins, `.bash-policy.yaml`, safe roots, and the requested activation mode. |
| `liza bash-policy report --claude-settings .claude/settings.json` | Reads current `Bash(...)` permissions so the dry-run report can list broad Claude permission families to migrate. It does not write policy. |
| `liza bash-policy export --claude-settings .claude/settings.json` | Reads current `Bash(...)` permissions so `.bash-policy-candidates.yaml` can include unresolved `permission-family` candidates. |

Dry-run and `on` evaluation writes redacted JSONL diagnostics to stderr so
provider transcripts can capture rollout evidence while stdout remains reserved
for provider hook decisions. Dry-run evidence comes from
`.bash-policy-dry-run.jsonl`; curated runtime command decisions live in
`.bash-policy.yaml`.

Bash policy artifacts live under the `policy-artifact-root`, normally the main
project root even when hooks execute inside a task or reviewer worktree:

| Artifact | Lifecycle |
|----------|-----------|
| `.bash-policy.yaml` | Curated project policy; may be tracked. |
| `.bash-policy-dry-run.jsonl` | Generated redacted rollout evidence; ignored/excluded by Liza. |
| `.bash-policy-candidates.yaml` | Generated unresolved candidate export; ignored/excluded by Liza. |

Use this workflow to turn dry-run evidence into `.bash-policy.yaml`:

1. Keep the hook in `dry-run` long enough to collect representative Bash
   commands in `.bash-policy-dry-run.jsonl`.
2. Run `liza bash-policy report --provider claude --claude-settings
   .claude/settings.json` to inspect what was allowed, denied, or left
   manual. The report is for triage; it does not write policy.
3. Run `liza bash-policy export --claude-settings
   .claude/settings.json` to write `.bash-policy-candidates.yaml`.
   The export combines dry-run command shapes with unresolved broad
   `Bash(...)` permission families from Claude settings.
4. Copy only the specific runtime `command-shape` candidates you accept into
   `.bash-policy.yaml`, and give each one a `decision: allow`, `decision: deny`,
   or `decision: manual`:

   ```yaml
   rules:
     - kind: command-shape
       identity: gh pr view <number>
       decision: allow
   ```

   Prefer normalized placeholders over literal local values when the shape is
   reusable:

   | Placeholder | Meaning |
   |-------------|---------|
   | `<safe-path>` | A path accepted by the configured safe roots. Prefer this over repository-specific paths such as `internal/foo_test.go` when the command should be allowed for any safe project file. |
   | `<number>` | A numeric argument such as a PR number, issue number, port, or count. |
   | `<fields>` | A comma-separated field list. |
   | `<redacted>` | A value hidden from artifacts because it looked sensitive. Do not allow this shape unless you can replace it with a safer, intentional shape. |

   Append `...` to a final placeholder token to match one or more repeated
   normalized operands of the same kind. For example, prefer:

   ```yaml
   rules:
     - kind: command-shape
       identity: git diff --cached <safe-path>...
       decision: allow
   ```

   over literal one-off project paths or several separate one-, two-, and
   three-path rules. `rtk` wrappers are normalized away for policy identity, so
   curate `git diff --cached <safe-path>...` rather than
   `rtk git diff --cached <safe-path>...`.

   Non-sensitive placeholders may also appear inside a single token when the
   command's syntax naturally combines values. For example:

   ```yaml
   rules:
     - kind: command-shape
       identity: sed -n <number>,<number>p
       decision: allow
   ```

   matches `sed -n 1,140p`. Embedded placeholders are powerful because one rule
   covers a whole family of concrete arguments. Keep the surrounding literal
   syntax as narrow as the command requires: `sed -n <number>,<number>p` does
   not match write variants such as `sed -i ...`, but a broader rule can allow
   more than intended. Path and redaction placeholders are stricter:
   `<safe-path>`, `<safe-pathspec>`, and `<redacted>` must be whole tokens and
   are not allowed inside larger tokens.

   `command-shape` identities are policy keys generated from the parsed Bash
   AST, not display summaries. Tokens containing whitespace are quoted so one
   argv token remains one policy token, for example
   `echo "=== staged separator (line 579) ==="`.

   Multi-operation dry-run evidence is split into individual leaf command shapes
   before export applies built-in and `.bash-policy.yaml` coverage. For example,
   `echo "=== staged separator (line 579) ==="; git show <safe-path>` contributes
   the leaf shapes `echo "=== staged separator (line 579) ==="` and
   `git show <safe-path>`; if both are built-in-covered, no candidate is emitted.
   Do not copy display summaries, transcript snippets, or whole multi-operation
   command lines into policy. Export ignores legacy shortened identities
   containing display `...`; delete or rotate old dry-run evidence when you
   intentionally want a fresh export from current normalization logic.

   An agent can assist with curation.
5. Use `permission-family` entries only to silence reviewed broad Claude
   permission families in future exports. They are bookkeeping, not runtime
   authorization:

   ```yaml
   rules:
     - kind: permission-family
       identity: Bash(gh:*)
       status: resolved
   ```

   A `permission-family` rule with `status: resolved` does not auto-allow
   `gh:*`; only built-in profiles and `command-shape` rules affect runtime
   command decisions.
6. Re-run `liza bash-policy export --claude-settings
   .claude/settings.json`. The candidate file should shrink as
   accepted command shapes and resolved permission families are omitted. Repeat
   until the remaining candidates are intentionally unresolved.

Use `liza bash-policy activation on|dry-run|off --provider claude|codex|all` to
change the managed provider hook entries. `liza init` repairs missing managed
hook files and wiring, but it preserves an existing Bash policy activation
instead of silently changing `on`, `dry-run`, or `off`.

## Codex Project Permissions

`liza init --codex` manages the active project entries and preserves unrelated
settings when merging an existing config.

Project-local Codex hooks live under `.codex/hooks/` and are wired by
`.codex/hooks.json`. Liza installs the same init, git, RTK, Bash policy, and
worktree-path guards there, but the Bash policy hook runs Codex in `dry-run`
until blocking semantics are verified for the provider. Dry-run activation does
not add approval friction for safe read-only commands and must not be described
as hard denial.

Run `liza bash-policy codex-readiness --json` from a project to inspect the
Codex Bash policy posture:

| Status | Meaning |
|--------|---------|
| `not-configured` | No project `.codex/` layer is installed. |
| `off` | The managed Codex Bash policy hook is explicitly inactive. |
| `degraded` | Hooks are present but a required config, wiring, executable hook file, or trust/blocking precondition is missing. |
| `log-only` | Install checks pass, but Liza has not verified a Codex hook blocking contract. |
| `blocking-ready` | Reserved for a future verified Codex blocking contract. |

Validation surfaces may warn on `degraded` or `log-only` readiness, but Liza
must not claim Codex hard-deny protection unless the status is `blocking-ready`.
