# Configuration Reference

## Provider Hooks

`bash-policy` installs project-local provider hooks for Claude Code and Codex.
The hook command calls the standalone binary directly:

```bash
bash-policy evaluate --provider claude --mode dry-run --policy-artifact-root /abs/project --safe-root "$CLAUDE_PROJECT_DIR"
bash-policy evaluate --provider codex --mode dry-run --policy-artifact-root /abs/project --safe-root "$PWD"
```

Use `bash-policy init` from a project checkout to install or repair hook
configuration:

```bash
bash-policy init --provider claude
bash-policy init --provider codex
bash-policy init --provider all
```

By default, `init` resolves the current git root as `policy-artifact-root` and
writes the current executable path into provider hook configuration. Use
`--policy-artifact-root` when installing from an auxiliary worktree and
`--command` when the provider hook should call a wrapper or PATH-resolved binary.
Later `activation` updates preserve the existing hook command and change only the
activation mode unless `--command` is supplied explicitly.

## Claude Settings

`.claude/settings.json` remains Claude Code's project settings file, not the
Bash policy file.

| Command | How `.claude/settings.json` is used |
|---------|-------------------------------------|
| `bash-policy init --provider claude` | Writes or merges the Claude PreToolUse Bash hook. |
| `bash-policy activation ... --provider claude` | Updates the installed hook activation. |
| `bash-policy evaluate` | Does not read Claude settings; runtime decisions come from built-ins, `.bash-policy.yaml`, safe roots, and the requested activation mode. |
| `bash-policy validate` | Reads `.bash-policy.yaml` and reports schema errors before activation or export workflows rely on it. |
| `bash-policy report --claude-settings .claude/settings.json` | Reads current `Bash(...)` permissions so reports can list broad Claude permission families to migrate. |
| `bash-policy export --claude-settings .claude/settings.json` | Reads current `Bash(...)` permissions so `.bash-policy-candidates.yaml` can include unresolved `permission-family` candidates. |

## Policy Artifacts

Bash policy artifacts live under `policy-artifact-root`, normally the durable
project root even when hooks execute inside an auxiliary worktree.

| Artifact | Lifecycle |
|----------|-----------|
| `.bash-policy.yaml` | Curated project policy; may be tracked. |
| `.bash-policy-dry-run.jsonl` | Generated redacted rollout evidence; ignored or excluded by standalone setup. |
| `.bash-policy-dry-run.jsonl.lock` | Generated log coordination file; ignored or excluded by standalone setup. |
| `.bash-policy-dry-run.jsonl.lock.owner.json` | Generated lock owner diagnostics; ignored or excluded by standalone setup. |
| `.bash-policy-candidates.yaml` | Generated unresolved candidate export; ignored or excluded by standalone setup. |

Provider hook evaluation must receive `--policy-artifact-root` or
`BASH_POLICY_ARTIFACT_ROOT`. Interactive `report` and `export` may also discover
the root by walking upward until `.bash-policy.yaml` is found. Before that file
exists, pass `--policy-artifact-root` explicitly.

## Rollout Workflow

1. Install hooks in dry-run mode:

   ```bash
   bash-policy init --provider all
   ```

2. Keep the hook in `dry-run` long enough to collect representative Bash
   commands in `.bash-policy-dry-run.jsonl`.

3. Review observed decisions:

   ```bash
   bash-policy report --provider claude --policy-artifact-root /abs/project --claude-settings .claude/settings.json
   ```

   The report is for triage; it does not write policy.

4. Export unresolved candidates:

   ```bash
   bash-policy export --provider claude --policy-artifact-root /abs/project --claude-settings .claude/settings.json
   ```

   Export writes `.bash-policy-candidates.yaml`, combining dry-run command
   shapes with unresolved broad `Bash(...)` permission families from Claude
   settings.

5. Curate `.bash-policy.yaml` from `.bash-policy-candidates.yaml`. Asking an
   agent to review the candidates and draft the curated policy is a good fit;
   keep only accepted runtime `command-shape` candidates and give each one a
   `decision: allow`, `decision: deny`, or `decision: manual`:

   ```yaml
   rules:
     - kind: command-shape
       identity: gh pr view <number>
       decision: allow
   ```

   Validate the curated policy before relying on it:

   ```bash
   bash-policy validate --policy-artifact-root /abs/project
   ```

6. Prefer normalized placeholders over literal local values when the shape is
   reusable:

   | Placeholder | Meaning |
   |-------------|---------|
   | `<safe-path>` | A path accepted by the configured safe roots. Prefer this over repository-specific paths when the command should be allowed for any safe project file. |
   | `<number>` | A numeric argument such as a PR number, issue number, port, or count. |
   | `<fields>` | A comma-separated field list. |
   | `<pattern>` | A single non-sensitive search-pattern token, intended for grep-style pattern positions. It can match normalized scalar placeholders such as `<fields>`, `<number>`, or `<safe-path>` when those appear as the pattern operand. |
   | `<redacted>` | A value hidden from artifacts because it looked sensitive. Do not allow this shape unless you can replace it with a safer, intentional shape. |

   Append `...` to a final placeholder token to match one or more repeated
   normalized operands of the same kind:

   ```yaml
   rules:
     - kind: command-shape
       identity: git diff --cached <safe-path>...
       decision: allow
   ```

   `rtk` wrappers are normalized away for policy identity, so curate
   `git diff --cached <safe-path>...` rather than
   `rtk git diff --cached <safe-path>...`.

7. Use `permission-family` entries only to silence reviewed broad Claude
   permission families in future exports. They are bookkeeping, not runtime
   authorization:

   ```yaml
   rules:
     - kind: permission-family
       identity: Bash(gh:*)
       status: resolved
   ```

8. Re-run export. The candidate file should shrink as accepted command shapes
   and resolved permission families are omitted.

9. Change activation when ready:

   ```bash
   bash-policy activation dry-run --provider all
   bash-policy activation on --provider claude
   bash-policy activation off --provider codex
   ```

`dry-run` records diagnostics and does not change provider behavior. `on` lets a
verified provider adapter emit behavior-changing decisions. `off` keeps the hook
entry explicit but inactive. Activation changes keep wrapper or PATH-resolved
commands installed by `init --command`; pass `activation ... --command COMMAND`
only when replacing the hook command is intentional.

## Codex Readiness

Project-local Codex hooks are configured with `.codex/config.toml` and
`.codex/hooks.json`. Run this from a project checkout:

```bash
bash-policy codex-readiness --json
```

| Status | Meaning |
|--------|---------|
| `not-configured` | No project `.codex/` layer is installed. |
| `off` | The Codex Bash policy hook is explicitly inactive. |
| `degraded` | Hooks are present but required config or direct hook wiring is missing. |
| `log-only` | Install checks pass, but Codex hook blocking is not verified. |
| `blocking-ready` | Reserved for a future verified Codex blocking contract. |

Until readiness is `blocking-ready`, Codex hard-deny protection must be treated
as log-only or degraded rather than a verified execution block.
