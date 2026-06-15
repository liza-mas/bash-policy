# PRD: Standalone Provider-Aware Bash Command Policy CLI

Status: draft

## Goal

Create a standalone provider-aware `bash-policy` CLI that reduces Claude
headless permission stalls for provably safe commands and hardens vanilla Claude
Code and Codex projects against unsafe shell, git, RTK, and secret-exposure
command shapes.

## Context

Claude Code and Codex users commonly compensate for provider-specific Bash
permission behavior with prompt guidance, broad Claude Bash permissions, and
ad hoc deny guards. This works operationally, but it makes prompts carry policy
that belongs in runtime enforcement and still leaves unattended agents
vulnerable to repeated permission blocks or unsafe command forms.

Claude and Codex need different outcomes from the same policy engine. Claude
benefits from emitting `allow` for safe commands so headless agents do not stall
on permission prompts. Codex does not have the same approval-loop failure mode;
its benefit is deny/log hardening inside the workspace sandbox.

The CLI must install and operate in ordinary project checkouts without depending
on a host agent framework. Provider hook trust, hook merge behavior, and
provider output contracts are part of the safety boundary. A provider adapter
must not claim hard denial or deny-authority preservation until those mechanics
are verified.

## General Information

Applies to provider PreToolUse Bash hooks, standalone provider hook
configuration, Bash command prompt guidance, and staged tightening of Claude
permissions.

### References

- User requirement: pairing discussion on 2026-06-14 - create a plan for a
  Bash command parsing hook inspired by `cc-bash-allow.go`.
- User requirement: pairing discussion on 2026-06-14 - `bash-policy export`
  should accept `.claude/settings.json` as a startup candidate source so users
  can curate a reference policy without first running a dry-run phase.
- User requirement: pairing discussion on 2026-06-14 - the Bash policy user
  journey belongs in project documentation, but that documentation update should
  be delivered with the feature rather than before implementation.
- User requirement: pairing review on 2026-06-14 - distinguish the durable policy
  artifact root from active worktree safe roots, define curated policy rule
  kinds, and assign generated-artifact ignore/exclude setup to an implementation
  step.
- User requirement: pairing review on 2026-06-14 - specify how policy artifact
  root is supplied or resolved from inside worktrees, finish the
  policy-artifact-root terminology migration, connect safe-root to safe-dir, and
  enumerate permission-family resolution statuses.
- User requirement: pairing discussion on 2026-06-15 - read-only Bash command
  families commonly granted in Claude settings should seed built-in default
  allow profiles, with the non-overridable safety floor guarding credential,
  write, environment-dump, bypass, and safe-root escape cases first.
- User requirement: pairing discussion on 2026-06-15 - common read-only Unix
  inspection commands should be hardcoded as built-in allow profiles instead of
  repeatedly listed in `.claude/settings.json`, with package-level
  documentation listing the profile families.
- User requirement: pairing discussion on 2026-06-15 - policy and candidate
  identities should use canonical placeholders such as `<safe-path>` rather
  than concrete project file paths, and should support terminal variadic
  placeholders such as `<safe-path>...` for repeated operands.
- User requirement: pairing discussion on 2026-06-15 - `rtk` is a command
  wrapper, so candidate and policy identities should strip the wrapper and key
  decisions on the wrapped command where the wrapped command is recoverable.
- User requirement: pairing discussion on 2026-06-15 - dry-run logs may contain
  redacted summaries, but downstream candidates and `.bash-policy.yaml` entries
  must not inherit display-truncated or transcript-fragment identities.
- User requirement: pairing discussion on 2026-06-15 - multi-operation Bash
  commands are common enough that command-shape identities must be derived from
  the parsed Bash AST and support compound command shapes.
- User requirement: pairing discussion on 2026-06-15 - the configuration guide
  must make the role of `.claude/settings.json`, generated candidate files, and
  curated `.bash-policy.yaml` explicit in each command workflow.
- Design note DN-001 below - durable summary of the `cc-bash-allow.go` AST
  strategy so the spec does not depend on `~/Downloads`.
- Design note DN-002 below - committed summary of the 2026-06-11
  command-failure corpus categories used for regression coverage.
- Prototype source: bash policy implementation commit `f05e5c21` - evaluator,
  provider adapters, activation updates, candidate export, reports, and
  generated hook configuration.
- Source: `.claude/settings.json` - Claude PreToolUse hook order and broad
  `Bash(...)` permission entries when present in a target project.
- Source: `.codex/hooks.json` - Codex project-local hook installation model
  when present in a target project.
- Source: Codex manual, Hooks - project `.codex/` hooks load only for trusted
  project layers; changed non-managed hooks require review/trust.
- Source: Codex manual, Rules - `prefix_rule(... decision="forbidden")` is a
  documented hard-blocking policy surface for commands that reach Codex command
  rule evaluation, primarily commands outside the sandbox; ordinary
  sandbox-allowed Bash blocking still requires verification or another
  provider-supported mechanism.
- Observation: Codex projects often use `approval_policy = "never"` and
  `sandbox_mode = "workspace-write"`, so Codex needs deny/log hardening rather
  than Claude-style auto-approval.

### Terminology

- `policy-artifact-root`: the durable project root whose configuration persists
  across provider sessions, hook regeneration, and disposable worktree
  creation/deletion. Bash policy artifacts live here even when a hook executes
  inside a separate auxiliary worktree. It must be supplied or resolved
  independently from the active worktree safe root.
- `safe-root`: the active repository or worktree root used to validate command
  paths for one hook evaluation. A safe root may be any project or worktree root
  explicitly supplied to the hook and is separate from `policy-artifact-root`. A
  `safe-dir` or `safe-path` is valid only when canonicalization keeps it inside
  one configured `safe-root`.
- `command-shape identity`: the canonical policy key derived from parsed Bash
  syntax, wrapper normalization, argument classification, and safe-root-aware
  placeholders. It is distinct from human-facing summaries and must be stable
  enough to curate in `.bash-policy.yaml`.

### Standalone CLI Surface

- `bash-policy init --provider claude|codex|all`: install or repair project-local
  provider hook configuration for vanilla Claude Code and Codex without changing
  an existing activation choice. Options include `--policy-artifact-root` and
  `--command` for overriding the generated hook executable path.
- `bash-policy evaluate --provider claude|codex --mode on|dry-run|off`: evaluate
  one provider Bash hook payload from stdin, append redacted telemetry when
  enabled, and emit provider-specific hook output only when verified. Provider
  hooks must pass `--policy-artifact-root` and at least one `--safe-root`.
- `bash-policy activation on|dry-run|off --provider claude|codex|all`: update
  installed hook activation while preserving unrelated provider settings. Options
  include `--policy-artifact-root` and `--command` for explicitly replacing the
  installed hook command; otherwise activation changes preserve the existing
  command and update only its mode.
- `bash-policy validate`: validate the curated `.bash-policy.yaml` schema,
  defaulting to interactive `policy-artifact-root` discovery and accepting
  `--policy-artifact-root` for explicit roots.
- `bash-policy report`: build a redacted aggregate report from dry-run JSONL
  evidence, defaulting to `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl`
  when stdin is empty. Options include `--provider`, `--policy-artifact-root`,
  and `--claude-settings`.
- `bash-policy export`: regenerate unresolved candidate policy entries from
  dry-run evidence and optional Claude settings input. Options include
  `--provider`, `--policy-artifact-root`, and `--claude-settings`.
- `bash-policy codex-readiness`: report whether a vanilla Codex project is
  blocking-ready, log-only, degraded, off, or not configured.

### Policy Root Resolution

Provider hooks must not discover `policy-artifact-root` from cwd. Generated hook
entries must pass a canonical absolute `--policy-artifact-root` value, or set
`BASH_POLICY_ARTIFACT_ROOT` to the same value, and must pass one or more
`--safe-root` values for command path validation. `bash-policy init` resolves the
hook executable to an absolute path by default and writes that path into provider
hook configuration; users may override it with `--command` when they intentionally
want PATH-based lookup or a wrapper.

Root resolution order is:

1. Explicit `--policy-artifact-root`, canonicalized after symlink evaluation.
2. `BASH_POLICY_ARTIFACT_ROOT`, canonicalized after symlink evaluation.
3. For non-hook interactive commands only, walk upward from the command cwd until
   `.bash-policy.yaml` is found and use the directory containing it.

Before `.bash-policy.yaml` exists, interactive `report` and `export` commands
must receive `--policy-artifact-root` or `BASH_POLICY_ARTIFACT_ROOT`; they must
not silently fall back to cwd or the active worktree git root. `bash-policy init`
is the only command that may default `policy-artifact-root` to the current git
root, because it writes that resolved root into generated provider hooks.

`bash-policy evaluate` in `on` or `dry-run` mode must not use upward
`.bash-policy.yaml` discovery to decide where to write telemetry or emit
behavior-changing provider output. If neither an explicit root nor
`BASH_POLICY_ARTIFACT_ROOT` is available, provider evaluation must fail closed:
append no artifact, emit no `allow` or hard-deny claim, and return only a
redacted diagnostic. In a single normal project checkout, `bash-policy init` may
default `policy-artifact-root` to the current git root; when installing from an
auxiliary or disposable worktree, the user must provide the durable root
explicitly.

### Non-Functional Requirements

- NFR-000-1: The policy engine must fail closed. Unparseable, dynamic, or
  unsupported Bash must not be classified safe.
- NFR-000-2: The policy must not log secrets, credential values, full
  environment dumps, or sensitive file contents.
- NFR-000-3: Any configured provider deny guards and the CLI's built-in
  hard-deny predicates must remain authoritative.
- NFR-000-4: Provider-specific adapters must not require mutating user-global
  Claude or Codex configuration during normal operation.
- NFR-000-5: Policy decisions must be observable enough to debug repeated
  denials without exposing sensitive command payloads.
- NFR-000-6: Provider adapters must not rely on hook ordering alone to preserve
  deny authority. Any adapter that emits `allow` must independently re-run
  hard-deny predicates; when any predicate matches, it must emit no `allow` and
  then follow the provider's verified hard-deny or degraded no-claim behavior.
- NFR-000-7: Codex hard-deny claims require verified hook activation, hook
  trust, and a verified deny output contract. Otherwise Codex hard blocking must
  be routed through documented Codex rules/execpolicy, or the feature must remain
  log-only for Codex.
- NFR-000-8: Dry-run telemetry must survive provider session and disposable
  worktree cleanup. Rollout evidence must be written under
  `policy-artifact-root`, outside provider cache directories and outside
  disposable auxiliary worktrees.
- NFR-000-9: `bash-policy init` must not silently change an already configured
  Bash policy activation state. It may install or repair missing hook artifacts,
  but existing `on`, `dry-run`, or `off` activation choices are user intent.
- NFR-000-10: Dry-run event logging must be safe when multiple agents append
  concurrently. Log writes must not interleave, truncate, or corrupt JSONL
  records under concurrent Claude and Codex hook executions.
- NFR-000-11: Bash policy artifacts under `policy-artifact-root` must have
  explicit lifecycle disposition. `.bash-policy.yaml` is the curated project
  policy and may be tracked. `.bash-policy-dry-run.jsonl` and
  `.bash-policy-candidates.yaml` are generated evidence artifacts. Dry-run lock
  files, including `.bash-policy-dry-run.jsonl.lock` and
  `.bash-policy-dry-run.jsonl.lock.owner.json`, are generated coordination
  artifacts. Generated evidence and coordination artifacts must be ignored or
  worktree-excluded by standalone setup so they do not pollute normal git status
  or get committed accidentally.
- NFR-000-12: Policy identities written to `.bash-policy-candidates.yaml` or
  `.bash-policy.yaml` must be canonical machine identities, not display summaries
  or shortened transcript fragments. Export may repair legacy full summaries
  using the current parser and safe roots; when a legacy identity contains only a
  display truncation marker and cannot be reconstructed, export must omit it
  rather than generating a misleading rule.
- NFR-000-13: User-facing documentation must distinguish `.claude/settings.json`
  as a Claude permission-family source for export and hook installation from
  `.bash-policy.yaml` as the runtime policy source for command-shape decisions.

### Related External Components

- Component C-001 - Claude Code PreToolUse hook protocol.
- Component C-002 - Codex PreToolUse hook protocol.
- Component C-003 - `mvdan.cc/sh/v3/syntax` shell parser.
- Component C-004 - RTK command wrapper.

### Out of Scope

- Replacing every pre-existing project-specific deny hook.
- Built-in/default auto-approval of potentially harmful, hard-to-reverse,
  credential-exposing, or safe-root-escaping command shapes.
- Rotating or editing user-local credentials.
- Rewriting all prompt command guidance in the first implementation step.
- Creating a general-purpose shell sandbox.

### Assumptions

- ASM-000-1: The first implementation should be additive and dry-run capable
  before it emits Claude `allow` decisions. Confidence: HIGH.
- ASM-000-2: A shared policy engine with provider adapters is preferable to
  separate Claude-only and Codex-only policy scripts. Confidence: HIGH.
- ASM-000-3: Literal `cd <safe-dir> && git <read-only>` and
  `git -C <safe-dir> <read-only>` forms should be eligible for approval once
  parsed and path-validated. Confidence: HIGH.
- ASM-000-4: The implementation should provide a standalone `bash-policy` binary
  because vanilla Claude Code and Codex hooks need an installable command that
  does not depend on a host agent framework. Confidence: HIGH.
- ASM-000-5: Claude and Codex should share one provider-tagged rollout event
  log rather than maintain separate provider-specific files. Confidence: HIGH.

### Open Questions

- None. Provider denial semantics and hook activation/trust are implementation
  prerequisites, not deferred open questions.

### Prototype Implementation Notes - 2026-06-15

- The source prototype documents a built-in Bash policy catalog and implements
  constrained read-only profiles for common Unix inspection commands, modeled
  read-only git subcommands, `rg`, `rtk` wrapper unwrapping, and hard denial of
  environment dumps.
- Command-shape identities use canonical placeholder forms derived from parsed
  Bash syntax instead of literal paths or display summaries. They preserve argv
  boundaries with quote-aware tokens, split compound dry-run evidence into leaf
  command shapes for curation, and support terminal variadic placeholders such
  as `<safe-path>...`.
- Candidate export compares dry-run evidence and Claude settings against
  built-in coverage plus `.bash-policy.yaml`, normalizes recoverable `rtk`
  wrappers, canonicalizes legacy full summaries where possible, and drops
  unreconstructable display-truncated identities.
- A curated `.bash-policy.yaml` contains runtime command-shape rules plus
  permission-family `resolved` entries used only to suppress export noise.
- Standalone documentation must describe the step-by-step workflow from dry-run
  report to candidate export, curation, and activation, including the distinct
  roles of `.claude/settings.json`, `.bash-policy-candidates.yaml`, and
  `.bash-policy.yaml`.
- Standalone generated-artifact exclusion covers the dry-run log, candidate file,
  and dry-run lock files. Regression tests cover evaluator/export coverage
  parity, compound command shapes, placeholder and variadic matching, `rtk`
  normalization, legacy candidate cleanup, and artifact exclusions.

### Durable Design Notes

- DN-001: The inspiration hook parses Bash with `mvdan.cc/sh`, walks all command
  nodes including nested shells, rejects dynamic command names and write
  redirections, and emits Claude `allow` only when every command is classified
  safe. The standalone CLI must keep the AST-walk idea but add argument policy,
  path policy, provider adapters, and hard-deny predicate checks.
- DN-002: Regression corpus categories must include: multi-operation commands,
  `cd` before git, `cd` plus redirection, shell expansion, command
  substitution, shell operators, heredocs/inline payloads, sleep/polling loops,
  RTK bypasses, unsupported `env -C` shapes, unquoted globs, runtime-determined
  `sed` targets, credential-path reads, and filesystem allowlist failures.
- DN-003: Existing Claude `Bash(...)` permissions informed the packaged built-in
  default catalog, but they are not read as a runtime allow catalog. Read-only
  families may appear in packaged default allow profiles only when guarded by
  the non-overridable safety floor and profile-specific argument constraints.
  Broad non-read-only, environment-dump, shell-wrapper, and bypass-oriented
  entries remain candidate inventory and must be split, narrowed, or left manual
  before any concrete command profile can emit auto-allow.
- DN-004: Bash policy activation is an explicit provider hook state:
  `on`, `dry-run`, or `off`. `dry-run` means classify and persist redacted
  telemetry without changing provider behavior. `on` means the provider adapter
  may emit verified behavior-changing decisions. `off` means the hook is
  intentionally inactive. Every activation state is persisted as an explicit
  standalone hook entry, not inferred from absence; a project with no hook entry
  is "never configured" and must not be conflated with any user-selected
  activation state.
- DN-005: Dry-run telemetry is rollout evidence, not session or ephemeral state.
  The durable default log path is
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl`.
  Each line must identify the provider and activation state so a shared log can
  be filtered by Claude, Codex, or combined rollout behavior. Appends must use a
  cross-process lock or equivalent atomic append mechanism so concurrent agents
  produce complete, independently parseable JSONL records.
- DN-006: Provider hook wrapper arguments must use the same activation
  vocabulary as `bash-policy activation on|dry-run|off`. Generated Claude and
  Codex hook configuration must not introduce separate non-activation wrapper
  modes. The target state has no `audit` wrapper mode; implementation references
  to `audit` must be renamed or removed rather than normalized into a second
  public spelling.
- DN-007: Hard-coded command profiles are bootstrap defaults, not the source of
  truth once a project policy configuration exists. Rule precedence is:
  non-overridable safety floor, configured project rules, and built-in defaults.
  The built-in default catalog should include read-only command families commonly
  granted in Claude settings when the safety floor and
  profile-specific argument constraints can reject hazardous targets, flags,
  payloads, and escapes. Unmatched commands fall back to `manual`.
- DN-008: Dry-run telemetry becomes useful through a promotion workflow:
  export aggregated unresolved command shapes from
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl`, and optionally unresolved
  Claude `Bash(...)` permission entries from
  `[POLICY_ARTIFACT_ROOT]/.claude/settings.json`, to
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-candidates.yaml`. The user curates
  accepted rules into `[POLICY_ARTIFACT_ROOT]/.bash-policy.yaml`, then activates
  evaluation against
  `.bash-policy.yaml`. The candidates file is generated evidence, not the policy
  source of truth. It should contain only deduplicated unresolved items absent
  from `.bash-policy.yaml` and not already covered by built-in default profiles.
- DN-009: A command-shape identity is the canonical, redacted policy key derived
  from parsed Bash syntax after wrapper peeling, cwd validation, argument
  classification, safe-root-aware placeholder normalization, and quote-aware token
  rendering. It includes executable family, subcommand, allowed flags, normalized
  option-value classes, cwd class, and validated placeholders such as
  `<safe-path>` or `<safe-pathspec>`. Tokens containing whitespace are rendered
  quoted so one argv token remains one policy token. It is not a human display
  summary. Two dry-run observations are duplicate candidates when their
  command-shape identities are equal. A curated rule covers an observed command
  when the rule matches that command-shape identity under the same normalization.
  Worked example for tests:
  `git diff -- path/to/a.go` and `git diff -- path/to/b.go` can normalize to
  the same `git diff -- <safe-path>` identity when both paths are inside the
  safe-root, while `git diff -- .env` must not be covered by that identity
  because credential paths fail before placeholder normalization. A quoted argument such
  as `echo "=== staged separator (line 579) ==="` must remain one rendered policy
  token.
- DN-010: Claude `Bash(...)` permissions imported from `.claude/settings.json`
  are permission-family candidates, not observed command-shape candidates. Their
  candidate identity is the normalized permission expression, for example
  `Bash(<family>:*)`. Read-only families already represented by built-in default
  profiles are omitted before permission-family candidates are emitted. Remaining
  permission-family candidates are considered covered only by an explicit curated
  policy entry that records the same permission-family identity as resolved;
  narrower command-shape rules do not implicitly resolve a broad
  permission-family candidate. Worked example for tests: `Bash(gh:*)` imported
  from Claude settings remains an unresolved permission-family candidate until
  `.bash-policy.yaml` records an explicit permission-family resolution for
  `Bash(gh:*)`; curated command-shape rules for narrower `gh` invocations do not
  resolve the broad family candidate. By contrast, a read-only family such as
  `Bash(rg:*)` should be omitted from unresolved permission-family candidates
  when it is already covered by the built-in read-only default catalog after
  safety-floor checks. Wrapper-shaped Claude permissions must not introduce
  runtime policy keyed on `rtk` itself; when an inner family can be recovered, the
  exporter normalizes to the wrapped family before built-in coverage and
  unresolved-candidate checks.
- DN-011: `.bash-policy.yaml` must support two rule kinds. A command-shape rule
  maps one normalized command-shape identity to a decision: `allow`, `deny`, or
  `manual`. A permission-family resolution maps one normalized Claude
  `Bash(...)` permission-family identity to status `resolved` so export can stop
  reporting it as unresolved. `resolved` is export-only and has no runtime policy
  effect. Permission-family resolutions do not by themselves auto-allow concrete
  commands; concrete command decisions require command-shape rules or built-in
  defaults after the safety floor.
- DN-012: Command-shape rule matching is token-based, quote-aware, and
  placeholder-aware. A validated placeholder token such as `<safe-path>` matches
  one normalized operand in that class. A terminal variadic placeholder such as
  `<safe-path>...` matches one or more consecutive normalized operands in that
  class and must appear only as the last token of the rule. Non-sensitive
  placeholders such as `<number>` and `<fields>` may appear inside a token when
  the command syntax naturally combines values, for example
  `sed -n <number>,<number>p`; path and redaction placeholders such as
  `<safe-path>`, `<safe-pathspec>`, and `<redacted>` must remain whole tokens. A
  curated embedded-placeholder rule must keep the non-placeholder syntax narrow
  enough that write variants or unrelated argument forms do not match
  accidentally. A standalone `...` or an unquoted mid-token display ellipsis is
  a truncation marker, not policy syntax, and must not be emitted as a candidate
  identity.
  Compound command summaries may contain unquoted shell operator tokens such as
  `;`, `&&`, `||`, and `|`, but export decomposes compound evidence into leaf
  command-shape candidates before coverage filtering.

### Activation State Mapping

| Activation | Claude behavior | Codex behavior |
|---|---|---|
| `off` | Do not evaluate or emit provider decisions. Preserve this state across `bash-policy init`. | Do not evaluate or emit provider decisions. Preserve this state across `bash-policy init`. |
| `dry-run` | Evaluate and append redacted events to `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl`; emit no Claude permission decision. | Evaluate and append redacted events to `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl`; emit no Codex blocking claim. |
| `on` | Emit verified hard-deny output for built-in hard-deny predicates, emit `allow` only where the policy and verified Claude adapter contract permit it, and still append redacted events. If hard-deny output is not verified, report degraded hardening and emit no block claim. | Remain log-only unless Codex hook blocking or another Codex-supported blocking surface is verified. |

Codex's log-only ceiling is a provider capability limit, not an activation state;
it can still apply while activation is `on` until a blocking contract is
verified.

### Codex Readiness Status Mapping

| Status | Meaning |
|---|---|
| `blocking-ready` | Project-local Codex hooks or another Codex-supported blocking surface are trusted, active, and verified to block the command classes the standalone CLI claims it can deny. |
| `log-only` | Bash policy evaluation and redacted event logging are active, but Codex blocking is not verified. This is the target replacement name for current WIP `audit-only` wording. |
| `degraded` | Codex policy integration is configured but missing required trust, hook, rule, or path prerequisites, so the standalone CLI must not claim hard denial. |
| `off` | Bash policy activation is explicitly `off`; readiness checks must report no evaluation or blocking behavior for this hook. |
| `not-configured` | No standalone Codex Bash policy hook entry exists; this is distinct from explicit `off`. |

### Provider Decision Mapping

| Decision | Claude adapter | Codex adapter |
|---|---|---|
| `allow` | Emit `allow` only after deny predicates pass and hook semantics are verified. | No-op; Codex does not need approval unblocking. |
| `deny` | Emit a verified Claude hard-deny response, or invoke a generated companion hard-deny hook, for built-in hard-deny predicates; if no deny contract is verified, emit no `allow` and report degraded hardening instead of claiming block behavior. | Deny only after hook trust/output contract is verified, otherwise use rules/execpolicy or log-only behavior. |
| `manual` | No-op; native permission flow decides. | Log-only unless mapped to a verified Codex policy surface. |
| `no-op` | No-op. | No-op. |

---

## Feature FT-001 - Shared Bash Policy Engine

### Functional Requirements

- FR-001-1: The policy engine must parse Bash commands with a real shell AST
  parser rather than command-name regexes.
- FR-001-2: The policy engine must inspect every command node, including nested
  command substitutions, subshells, pipelines, loops, and process substitutions.
- FR-001-3: The policy engine must reject write redirections, append
  redirections, bidirectional redirections, here-doc payload execution, and
  command names that are not plain literals.
- FR-001-4: The policy engine must classify commands by command plus arguments,
  not by executable name alone.
- FR-001-5: The policy engine must recursively evaluate `rtk <command>` wrappers
  against the wrapped command and apply RTK hard-deny predicates even when no
  separate RTK deny hook is configured.
- FR-001-6: The policy engine must classify read-only git forms with explicit
  subcommand and flag policy.
- FR-001-7: The policy engine must allow literal safe-directory cwd forms for
  read-only commands, including `cd <safe-dir> && git status --short` and
  `git -C <safe-dir> diff -- <safe-path>`.
- FR-001-8: The policy engine must block credential-path reads and likely
  secret-exposure commands, including `.env`, key files, credential files,
  git object path operands such as `HEAD:id_rsa` or `HEAD:config/id_rsa`,
  unrestricted `printenv`, and searches targeting secret stores.
- FR-001-9: The policy engine must return a structured decision:
  `allow`, `deny`, `manual`, or `no-op`, with a short redacted reason.
- FR-001-10: `safe-dir` means a literal path that canonicalizes, after symlink
  evaluation and `..` cleaning, inside the active project root or another
  auxiliary worktree root explicitly supplied to the hook.
- FR-001-11: `safe-dir` must not default to `$HOME`, `/tmp`, provider writable
  roots, or arbitrary additional directories.
- FR-001-12: `safe-path` means a literal file path or git pathspec that remains
  inside the canonical `safe-dir` root and does not match credential-file
  patterns.
- FR-001-13: Paths using shell expansion, globbing, command substitution,
  unresolved symlink escape, parent traversal outside the root, or credential
  globs must not be classified safe.
- FR-001-14: A unit command may be classified safe only when it matches a
  command allow profile: a command-specific contract covering accepted argv
  forms, flags and flag values, path arguments, write surfaces,
  secret-exposure surfaces, and execution-escape flags. Safety must be evaluated
  by potential harm, reversibility/recoverability, credential exposure, and root
  containment, not by state-changing status alone.
- FR-001-15: Unknown commands, unknown flags, unknown argument shapes, or
  unmodeled path behavior must not be classified safe.
- FR-001-16: The first built-in default profile catalog must include read-only
  Bash command families commonly present in Claude `Bash(...)` settings as
  packaged default allow profiles when the global safety floor and the
  command-family profile can reject unsafe flags, paths, payloads, and escapes. Broad
  non-read-only, environment-dump, shell-wrapper, and bypass-oriented permissions
  must remain candidate inventory and must not be promoted wholesale. The initial
  common Unix inspection catalog must include `basename`, `cat`, `cd`, `cut`,
  `date`, `diff`, `dirname`, `echo`, `file`, `head`, `ls`, `pwd`, `realpath`,
  `sha256sum`, `sort`, `tail`, `tr`, `tree`, `uniq`, `wc`, and `which`, each with
  command-specific operand and flag constraints. The package-level documentation
  must list these built-in top-level families and modeled git subcommands.
- FR-001-17: The policy engine must load a project policy configuration. When
  present, configured rules must override built-in default command profiles.
- FR-001-18: Built-in defaults must remain useful when no project policy
  configuration exists, but they must not permanently deny operations that can
  be made safe by command-shape, argument, and path constraints.
- FR-001-19: Configured rules may allow constrained repo-state operations needed
  by useful agents when they are not potentially harmful, are reversible or
  recoverable, and still satisfy credential and safe-root constraints.
- FR-001-20: Configured rules must not override the non-overridable safety floor:
  secret exposure, credential paths, safe-root escape, verified bypasses, and
  destructive irreversible operations must never become auto-allowed.
- FR-001-21: The project policy configuration must support at minimum the
  `.bash-policy.yaml` rule kinds in DN-011: command-shape rules with
  `allow|deny|manual` decisions and permission-family resolution entries.
- FR-001-22: Hook wrappers and `bash-policy` commands that read or write Bash
  policy artifacts must receive or resolve `policy-artifact-root` independently
  from `safe-root`. Provider hook evaluation may use only an explicit
  `--policy-artifact-root` option or `BASH_POLICY_ARTIFACT_ROOT`; it must not
  infer `policy-artifact-root` from hook cwd, `CLAUDE_PROJECT_DIR`, active
  worktree `git rev-parse --show-toplevel`, or upward `.bash-policy.yaml`
  discovery.
- FR-001-23: Non-hook interactive commands may discover `policy-artifact-root` by
  walking upward from the command cwd until `.bash-policy.yaml` is found. This
  discovery is a convenience for reports, export, and local maintenance only; it
  must not be used by provider hook evaluation to choose an artifact write
  location or to emit behavior-changing output.
- FR-001-24: If a hook executes from an auxiliary worktree and cannot resolve
  `policy-artifact-root`, it must not write `.bash-policy-dry-run.jsonl` or
  `.bash-policy-candidates.yaml` under the active worktree. It must emit no
  provider behavior-changing decision and return a redacted diagnostic.
- FR-001-25: The policy engine must derive command-shape identities from the
  parsed Bash AST rather than from display summaries. The identity generator must
  support single commands and top-level compound diagnostic shapes composed with
  standalone `;`, `&&`, `||`, and `|` operator tokens, while preserving quoted
  argv boundaries inside leaf command-shape identities.
- FR-001-26: A compound command must not become auto-allowed merely because each
  component can be parsed. Compound command auto-allow requires every leaf command
  to pass the non-overridable safety floor and resolve to `allow` through a
  built-in profile or configured leaf command-shape rule. Whole compound
  command-shape rules are not the curation unit.
- FR-001-27: The command-shape identity for `rtk <command>` must be based on the
  wrapped command when the wrapper can be safely peeled. Human-facing summaries may
  retain enough context to explain that `rtk` was used, but candidates and
  `.bash-policy.yaml` command-shape rules must key on the wrapped command shape.
- FR-001-28: Command-shape rule matching must support validated placeholder
  tokens, including terminal variadic placeholders such as `<safe-path>...` for
  one or more repeated safe operands. Variadic placeholders must not match
  credential paths, paths outside the safe root, or arguments in another
  placeholder class. Embedded placeholders must be limited to non-sensitive
  placeholder classes such as `<number>` and `<fields>`.
- FR-001-29: Unsupported redirections, command substitutions, process
  substitutions, heredocs, shell expansions, and dynamic command names must remain
  fail-closed. Such forms may be summarized for logs, but must not be exported as
  allowable command-shape identities unless a future profile can validate their
  effects directly.
- FR-001-30: Current default git status and git diff handling must remain
  read-only profile logic with explicit allowed flag sets and safe path validation;
  it must not be replaced by a broad `git status:*` or `git diff:*` family allow.

### Acceptance Criteria

- AC-001-1: Given `cd <safe-worktree> && git status --short`, when the policy
  evaluates the command, then it classifies it as safe for Claude auto-approval.
- AC-001-2: Given `git branch -D topic`, `git remote add origin ...`, or
  `git reset --hard`, when the policy evaluates the command, then it does not
  classify the command as safe.
- AC-001-3: Given `cat .env`, `printenv`, or `rg TOKEN ~/.ssh`, when the policy
  evaluates the command, then it returns a deny or manual decision.
- AC-001-4: Given `rtk git diff --stat`, when the policy evaluates the command,
  then it classifies the wrapped `git diff --stat` command rather than trusting
  the `rtk` executable name.
- AC-001-5: Given `cd safe/link-to-home && git status`, when the symlink resolves
  outside the safe root, then the policy does not classify the command safe.
- AC-001-6: Given `git -C safe/../outside status`, when canonicalization escapes
  the safe root, then the policy does not classify the command safe.
- AC-001-7: Given `git -C /tmp status` without `/tmp` explicitly supplied as a
  safe-root, then the policy does not classify the command safe.
- AC-001-8: Given the packaged built-in default catalog includes a read-only
  family such as `rg`, when a matching concrete command satisfies the
  non-overridable safety floor and profile-specific argument constraints, then
  the policy may classify it as allow without reading `.claude/settings.json`.
- AC-001-9: Given `git branch -D topic`, `printenv`, `bash -c 'git status'`, or
  `rtk proxy git status` appears under a broad seeded setting or built-in default
  family, when the policy evaluates the command, then it does not classify the
  command safe.
- AC-001-10: Given the built-in default profile would return `manual` for a
  concrete command shape, and the project policy configuration allows the
  matching command-shape identity, when the policy evaluates the command inside a
  safe-root and the safety floor does not match, then it returns `allow`.
- AC-001-11: Given the project policy configuration allows a command-shape
  identity with safe path placeholders, when the policy evaluates a matching
  concrete command targeting a credential file or path outside the safe-root,
  then the command is not classified safe.
- AC-001-12: Given
  `echo "---commands---"; git diff --cached path/to/policy.go`, when
  the policy evaluates the command without a matching project rule, then the
  result remains manual and exposes the canonical compound command-shape identity
  `echo --- ; git diff --cached <safe-path>`.
- AC-001-13: Given `.bash-policy.yaml` allows the unresolved leaf identity
  `git diff --cached <safe-path>`, when the same concrete compound command is
  evaluated inside a safe root and every other leaf is built-in-covered, then the
  compound command can return `allow`.
- AC-001-14: Given `.bash-policy.yaml` allows
  `git diff --cached <safe-path>...`, when the policy evaluates
  `git diff --cached path/to/policy_test.go docs/CONFIGURATION.md`,
  then the variadic placeholder matches both safe paths; when any operand is a
  credential path or outside the safe root, the command is not classified safe.
- AC-001-15: Given
  `rtk cat /safe/project/README.md`, when the policy derives a command-shape
  identity, then the identity is `cat <safe-path>` and not an `rtk`-prefixed
  rule.
- AC-001-16: Given `git diff --cached internal/a.go > out.patch`, when the policy
  evaluates the command, then the write redirection fails closed and no
  command-shape rule can convert it to auto-allow.

---

## Feature FT-002 - Claude Allow Adapter

### Functional Requirements

- FR-002-1: Claude integration must install or update the standalone Bash policy
  PreToolUse hook without removing unrelated project hooks. The installed
  integration must provide a hard-deny path for the CLI's built-in hard-deny
  predicates, either through the same policy hook or a generated companion
  hard-deny hook, before claiming vanilla Claude hardening.
- FR-002-2: In dry-run mode, the Claude adapter must log redacted policy
  decisions to `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl` without
  changing permission behavior.
- FR-002-3: When activation is `on`, the Claude adapter must emit
  `permissionDecision: "allow"` only when the shared policy returns `allow`, all
  hard-deny predicates return false, and Claude hook precedence/merge behavior
  has been verified.
- FR-002-4: For `deny` decisions, the Claude adapter must emit a verified
  provider hard-deny response with a redacted reason, or report degraded
  hardening and emit no block claim if no deny output contract is verified. For
  `manual` and `no-op` decisions, the adapter must avoid masking earlier
  deny-guard behavior.
- FR-002-5: Claude broad Bash permissions must be tightened only after the hook
  has dry-run evidence and tests covering common command shapes for the target
  project.
- FR-002-6: If Claude hook precedence cannot be proven to preserve earlier
  denies, the allow adapter must remain dry-run/no-op until deny predicates are
  unified into the same decision point.
- FR-002-7: `bash-policy activation on|dry-run|off` must update the Claude Bash
  policy hook activation without creating duplicate hook entries.
- FR-002-8: `bash-policy init --provider claude` must preserve an existing
  Claude Bash policy activation if the hook is already configured.
- FR-002-9: Claude hook configuration must call the wrapper with the explicit
  activation argument, for example
  `/abs/bin/bash-policy evaluate --provider claude --mode dry-run --policy-artifact-root /abs/project --safe-root "$CLAUDE_PROJECT_DIR"`,
  so provider settings align with the `bash-policy activation` vocabulary,
  provider evaluation receives explicit roots, and generated hooks do not depend
  on PATH unless the user supplied `--command`.

### Acceptance Criteria

- AC-002-1: Given a safe read-only compound command that previously triggered a
  Claude permission prompt, when Claude activation is `on`, then the command
  receives an allow decision.
- AC-002-2: Given a destructive git command that matches a hard-deny predicate,
  when the full Claude hook chain runs, then the combined provider outcome is
  denial or no allow decision is emitted; a later allow must never unblock it.
- AC-002-3: Given `.claude/settings.json` already contains a standalone Bash
  policy hook configured as `on`, `dry-run`, or `off`, when
  `bash-policy init --provider claude` updates Claude settings, then the existing
  activation is preserved and no duplicate Bash policy hook entry is added.
- AC-002-4: Given Claude activation is `dry-run`, when Bash commands are
  evaluated, then redacted provider-tagged events are appended to
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl` and no Claude permission
  decision is emitted.
- AC-002-5: Given a vanilla Claude project has broad `Bash(...)` permissions and
  no pre-existing deny hook, when `bash-policy init --provider claude` has
  installed the hook and `bash-policy activation on --provider claude` enables it
  with a verified Claude hard-deny contract, then
  secret-exposure and destructive git commands matching built-in hard-deny
  predicates are blocked rather than merely not auto-allowed.

---

## Feature FT-003 - Codex Deny And Log-Only Adapter

### Functional Requirements

- FR-003-1: Codex integration must use the same policy engine but must not rely
  on Claude-style auto-approval semantics.
- FR-003-2: Codex integration must install through a project-local
  `.codex/hooks.json` hook model compatible with vanilla Codex.
- FR-003-3: Codex integration must first verify that project-local hooks are
  loaded, enabled, trusted, and capable of blocking execution before claiming
  hook-based denial.
- FR-003-4: Codex integration must support redacted dry-run logging for manual
  and unsafe command classifications using the shared provider-tagged dry-run
  event log.
- FR-003-5: Codex integration must not mutate `~/.codex/config.toml` as part of
  normal init or hook execution.
- FR-003-6: Standalone init or readiness validation must detect when Codex hooks
  are not active because the project `.codex/` layer is untrusted, hooks are
  disabled, hook hashes are untrusted, or launch args omit a chosen trust-bypass
  strategy.
- FR-003-7: Codex integration must replicate the RTK hard-deny predicates inside
  the shared policy for Codex, or install an equivalent standalone hard-deny hook
  before claiming RTK hard denial.
- FR-003-8: If Codex hook output cannot block execution, unsafe-command blocking
  must use Codex rules/execpolicy only where verified to apply to the command
  class being blocked. Ordinary sandbox-allowed Bash commands must remain
  log-only unless hook denial or another Codex-supported blocking surface is
  verified.
- FR-003-9: `bash-policy activation on|dry-run|off` must update Codex Bash policy
  hook activation without creating duplicate hook entries when Codex project
  hooks are configured.
- FR-003-10: `bash-policy init --provider codex` must preserve an existing Codex
  Bash policy activation if the hook is already configured.
- FR-003-11: Codex hook configuration must call the wrapper with the explicit
  activation argument, for example
  `/abs/bin/bash-policy evaluate --provider codex --mode dry-run --policy-artifact-root /abs/project --safe-root "$PWD"`;
  generated `.codex/hooks.json` must use only `on|dry-run|off` activation
  vocabulary, pass explicit roots, and avoid PATH-dependent binary lookup unless
  the user supplied `--command`.

### Acceptance Criteria

- AC-003-1: Given Codex runs with `approval_policy = "never"`, when a safe
  read-only command is evaluated, then the hook does not add friction.
- AC-003-2: Given a trusted project-local `.codex` layer, hooks enabled, the
  policy hook trusted, and a verified Codex blocking contract, when Codex runs a
  secret-exposure or destructive git command inside a writable root, then the
  command is blocked before execution.
- AC-003-3: Given those Codex hook preconditions are not satisfied, when
  `bash-policy codex-readiness` validates Codex readiness, then the feature
  reports degraded or log-only status instead of claiming hard denial.
- AC-003-4: Given Codex activation is `dry-run`, when Bash commands are
  evaluated, then redacted events are appended to the shared dry-run log with
  `provider: "codex"` and no hard-deny claim is made.
- AC-003-5: Given `bash-policy init --provider codex` writes or repairs
  `.codex/hooks.json`, when the Bash policy hook entry is inspected, then it uses
  an absolute `bash-policy evaluate --provider codex --mode dry-run` command with
  explicit `--policy-artifact-root` and `--safe-root` arguments by default.

---

## Feature FT-004 - Prompt And Permission Simplification Rollout

### Functional Requirements

- FR-004-1: The first rollout phase must keep existing prompt restrictions and
  provider permissions unchanged while collecting dry-run evidence.
- FR-004-2: The second rollout phase may simplify prompt guidance from
  provider-specific permission workarounds to policy-approved command shapes.
- FR-004-3: The third rollout phase is a behavior-narrowing migration, not only
  cleanup. It may tighten Claude `Bash(...)` permissions only after impact is
  quantified.
- FR-004-4: Prompt simplification must not remove hard safety guidance for
  destructive operations, credential files, or unbounded shell execution.
- FR-004-5: Before tightening, the dry-run report must quantify historical
  commands that would newly become manual or denied, including `env`, `printenv`,
  `sed`, `awk`, `find`, heredocs, interpreter invocations, package managers, and
  broad shell wrappers.
- FR-004-6: Before tightening, the dry-run report must include a migration table
  for each current Claude `Bash(...)` permission entry: candidate family,
  proposed status (`auto-allow`, `specialize`, `manual`, or `deny/manual`),
  rationale, and representative historical command examples when available.
- FR-004-7: The dry-run report must read
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-dry-run.jsonl` by default when no stdin is
  supplied.
- FR-004-8: The dry-run report must aggregate repeated command-shape events with
  counts rather than dropping frequency evidence as duplicates. Reports may
  filter by provider, but the underlying event log remains shared.
- FR-004-9: `bash-policy export` must build
  `[POLICY_ARTIFACT_ROOT]/.bash-policy-candidates.yaml` from candidate sources.
  Supported sources must include aggregated dry-run events and an explicit Claude
  settings JSON path, for example `--claude-settings .claude/settings.json`.
- FR-004-10: When export reads Claude settings JSON, it must extract `Bash(...)`
  permissions not already covered by built-in default profiles or
  `.bash-policy.yaml` as candidate permission families. Broad non-read-only
  permissions must remain candidate inventory and must not imply auto-allow.
- FR-004-11: Export must compare every candidate identity against
  `[POLICY_ARTIFACT_ROOT]/.bash-policy.yaml` when the curated policy file exists,
  using the command-shape identity and permission-family identity rules in DN-009
  and DN-010. Export must also omit candidate identities already covered by
  built-in default read-only profiles.
- FR-004-12: `.bash-policy-candidates.yaml` must contain only deduplicated
  unresolved candidates that are absent from `.bash-policy.yaml` and not covered
  by built-in default profiles; candidates already represented by a curated
  command-shape rule, explicit permission-family resolution, or built-in default
  profile must be omitted from candidates.
- FR-004-13: Export must treat `.bash-policy-candidates.yaml` as a regenerated
  candidate snapshot, not policy state. Re-running export must compute output
  from current candidate sources plus `.bash-policy.yaml`, avoid duplicates, and
  omit candidates covered by `.bash-policy.yaml` or built-in default profiles
  regardless of previous candidate-file contents.
- FR-004-14: Activation must evaluate against `.bash-policy.yaml`, not directly
  against raw dry-run logs, reports, `.claude/settings.json`, or
  `.bash-policy-candidates.yaml`.
- FR-004-15: The implementation must update standalone configuration
  documentation at `docs/CONFIGURATION.md`.
  The documentation must explain the user journey across activation states,
  `.bash-policy-dry-run.jsonl`, `.claude/settings.json`,
  `.bash-policy-candidates.yaml`, `.bash-policy.yaml`, export, curation, and
  activation. It must explain that `.claude/settings.json` is used by Claude
  Code and by `bash-policy export --claude-settings` as a permission-family
  candidate source, but is not the runtime command-shape policy file.
- FR-004-16: When `bash-policy init` installs or repairs Bash policy hooks, it must
  ensure generated policy artifact paths are ignored or worktree-excluded under
  `policy-artifact-root`. `bash-policy activation` must perform the same
  setup when enabling or repairing policy activation in a project that predates
  the hook setup.
- FR-004-17: Export must write canonical command-shape identities, not display
  summaries. When reading legacy dry-run events that contain full redacted
  summaries, export should reparse and normalize them with the current evaluator
  and safe roots. When a legacy event identity is only a shortened display string
  containing truncation `...`, export must drop it instead of emitting a literal
  or partial policy rule.
- FR-004-18: Export must treat compound dry-run commands as evidence containers.
  It must decompose parseable compound commands into quote-preserving leaf
  command-shape identities, apply built-in and `.bash-policy.yaml` coverage to
  each leaf, and emit candidates only for unresolved leaves.
- FR-004-19: Export must normalize `rtk`-wrapped command evidence before candidate
  comparison. Dry-run command-shape candidates for safely peelable `rtk`
  invocations must use the wrapped command identity; Claude permission-family
  candidates that encode an `rtk` wrapper must be normalized to the recoverable
  inner family before built-in coverage and unresolved-candidate checks.
- FR-004-20: The generated candidate file and the recommended curated policy must
  prefer placeholder command-shape identities such as `<safe-path>`, `<number>`,
  `<fields>`, and terminal variadic placeholders such as `<safe-path>...` over
  literal repository paths whenever the broader shape is safe.
- FR-004-21: Standalone ignore/exclude setup must cover all generated Bash
  policy artifacts: `.bash-policy-dry-run.jsonl`,
  `.bash-policy-dry-run.jsonl.lock`,
  `.bash-policy-dry-run.jsonl.lock.owner.json`, and
  `.bash-policy-candidates.yaml`.
- FR-004-22: The initial project curation should produce `.bash-policy.yaml` with
  canonical command-shape rules for accepted runtime shapes and
  permission-family entries marked `resolved` for export-only bookkeeping. It
  must avoid overlapping literal command-shape rules when a safe placeholder or
  terminal variadic placeholder rule covers the intended cases.

### Acceptance Criteria

- AC-004-1: Given dry-run evidence shows safe `cd && git` and `git -C` forms are
  approved, when prompts are simplified, then the prompts stop forbidding those
  forms solely because of historical permission stalls.
- AC-004-2: Given Claude permissions are tightened, when Claude Code runs common
  read-only inspection commands, then the hook still prevents headless stalls.
- AC-004-3: Given multiple identical command shapes are observed during dry-run,
  when the report is generated, then the report shows one aggregate row with a
  count instead of duplicate rows or discarded observations.
- AC-004-4: Given dry-run evidence contains an observed command-shape identity
  absent from `.bash-policy.yaml` and not covered by built-in default profiles,
  for example `gh issue view <number> --json <fields>`, when
  `bash-policy export --provider claude` runs, then
  `.bash-policy-candidates.yaml` contains one candidate for that command shape
  with aggregated observation metadata.
- AC-004-5: Given `.bash-policy.yaml` already contains a command-shape rule that
  covers an observed command-shape identity, for example
  `gh issue view <number> --json <fields>`, when export runs, then
  `.bash-policy-candidates.yaml` does not contain a candidate for that identity.
- AC-004-6: Given `.bash-policy.yaml` contains a command-shape rule or
  permission-family resolution that covers a current candidate source item, when
  export runs, then `.bash-policy-candidates.yaml` does not contain that
  candidate regardless of any previous candidates file content.
- AC-004-7: Given activation is set to `on`, when evaluation runs, then it uses
  `.bash-policy.yaml` plus the non-overridable safety floor and ignores
  `.bash-policy-candidates.yaml`.
- AC-004-8: Given no dry-run log exists and `.claude/settings.json` contains a
  `Bash(...)` permission absent from `.bash-policy.yaml`, for example the DN-010
  `Bash(gh:*)` family, when
  `bash-policy export --claude-settings .claude/settings.json` runs, then
  `.bash-policy-candidates.yaml` contains one unresolved candidate for that
  permission-family identity.
- AC-004-9: Given `.bash-policy.yaml` already contains an explicit curated
  permission-family resolution for a `Bash(...)` permission, for example the
  DN-010 `Bash(gh:*)` family, when export reads `.claude/settings.json`, then
  `.bash-policy-candidates.yaml` does not contain a duplicate candidate for that
  permission-family identity.
- AC-004-10: Given `.claude/settings.json` contains a read-only `Bash(...)`
  permission covered by the built-in default catalog, for example `Bash(rg:*)`,
  when export reads `.claude/settings.json`, then
  `.bash-policy-candidates.yaml` does not contain an unresolved
  permission-family candidate for that built-in-covered family.
- AC-004-11: Given the Bash policy feature is implemented, when
  `docs/CONFIGURATION.md` is reviewed, then it documents the full
  export-to-curation-to-activation workflow and does not describe unavailable
  commands as current user-facing behavior.
- AC-004-12: Given `bash-policy init` installs Bash policy hooks or
  `bash-policy activation dry-run` repairs activation, when the project is
  inspected, then `.bash-policy-dry-run.jsonl` and
  `.bash-policy-candidates.yaml` are ignored or worktree-excluded under
  `policy-artifact-root`.
- AC-004-13: Given dry-run evidence contains the full command
  `git diff --cached path/to/policy_test.go docs/CONFIGURATION.md`,
  when export runs with the project safe root, then the candidate identity uses
  the canonical placeholder form `git diff --cached <safe-path>...` rather than
  either concrete file path.
- AC-004-14: Given legacy dry-run evidence contains a display-truncated identity
  such as `bashpolicy ; echo ...`, when export runs, then the generated candidate
  file omits that shortened identity unless it can be reconstructed into a
  canonical command-shape identity.
- AC-004-15: Given `.claude/settings.json` contains an `rtk`-wrapped
  permission-family candidate whose inner family is recoverable, when export
  reads the Claude settings file, then the unresolved candidate comparison uses
  the inner family and does not emit a wrapper-only `Bash(rtk:*)` policy item.
- AC-004-16: Given the Bash policy feature is implemented, when
  `docs/CONFIGURATION.md` is reviewed, then it documents `<safe-path>` as the
  preferred path placeholder, terminal `<placeholder>...` syntax,
  embedded non-sensitive placeholder syntax such as
  `sed -n <number>,<number>p`, quote-preserving command-shape tokens, compound
  evidence splitting into leaf candidates, `rtk` normalization, and the
  operator caution that embedded-placeholder rules should keep literal syntax
  narrow, and the export-only nature of permission-family `resolved` entries.
- AC-004-17: Given standalone ignore/exclude setup has run, when the project is
  inspected after dry-run event writes, then `.bash-policy-dry-run.jsonl.lock`
  and `.bash-policy-dry-run.jsonl.lock.owner.json` are also absent from normal
  git status.
- AC-004-18: Given `.bash-policy.yaml` contains
  `git diff --cached <safe-path>...`, when export considers a concrete observed
  `git diff --cached` shape with one or more safe paths, then it omits narrower
  literal candidates already covered by that variadic rule.

---

## Feature FT-005 - Regression Corpus And Observability

### Functional Requirements

- FR-005-1: The implementation must include unit tests for AST parsing,
  redirection handling, nested commands, git policy, RTK wrapping, cwd policy,
  and secret-path blocking.
- FR-005-2: The implementation must include representative command cases from
  DN-002.
- FR-005-3: The implementation must expose a dry-run report that summarizes
  policy outcomes without leaking command secrets.
- FR-005-4: Tests must verify provider-specific hook behavior: Claude allow
  output cannot override hard-deny predicates, and Codex hard-deny behavior is
  only claimed when hook trust/output or rules/execpolicy blocking is verified.
- FR-005-5: Tests must verify durable dry-run event persistence, including
  provider and activation fields, redaction, and append behavior.
- FR-005-6: Tests must verify Bash policy activation upsert behavior for Claude
  and Codex settings, including preserving existing activation across
  `bash-policy init` merge flows.
- FR-005-7: Tests must verify generated Claude and Codex hook commands use
  `on|dry-run|off` activation vocabulary and do not emit non-activation wrapper
  modes.
- FR-005-8: Tests must verify concurrent dry-run event writes from multiple
  goroutines or processes produce the expected number of parseable JSONL records
  without partial lines or lost events.
- FR-005-9: Tests must verify policy export reconciliation, including candidate
  creation for unresolved command shapes, omission of shapes already covered by
  `.bash-policy.yaml` or built-in default profiles, removal after curation,
  Claude settings candidate extraction, and no duplicate candidates.
- FR-005-10: Tests must verify command-shape and permission-family identity
  behavior, including concrete safe-path arguments matching placeholder-based
  command-shape rules and broad permission-family candidates requiring explicit
  permission-family resolution, while built-in read-only families from common
  Claude settings are omitted from unresolved candidate output. Tests must use
  the worked examples in DN-009 and DN-010 as canonical fixtures.
- FR-005-11: Tests must verify lifecycle disposition for `policy-artifact-root`
  Bash policy artifacts: `.bash-policy.yaml` remains available as curated policy,
  and generated `.bash-policy-dry-run.jsonl` plus
  `.bash-policy-candidates.yaml` are ignored or worktree-excluded by standalone
  setup.
- FR-005-12: Tests must verify `policy-artifact-root` resolution from an
  auxiliary worktree: dry-run events and candidates are written
  under the durable main project root, while command path validation still uses
  the active worktree as a safe root.
- FR-005-13: Tests must pin evaluator/export parity for built-in read-only Unix
  profiles. For representative command shapes, `Evaluate(...) == allow` must
  agree with the export-side built-in coverage predicate so future profile edits
  do not make export over-claim or under-claim built-in coverage silently.
- FR-005-14: Tests must verify AST-derived compound diagnostic shape generation,
  quote-preserving leaf extraction and matching, standalone operator tokens for
  `;`, `&&`, `||`, and `|`, and unsupported redirections failing closed before
  project policy can allow a command.
- FR-005-15: Tests must verify command-shape placeholder matching, including
  terminal variadic placeholders such as `<safe-path>...`, and must prove that
  variadic rules do not match credential paths, outside-root paths, or non-final
  placeholder positions. Tests must also pin the quote-aware command-shape token
  round trip so rendered tokens parse back to their original argv fields.
- FR-005-16: Tests must verify export canonicalization from legacy full summaries,
  rejection of display-truncated identities, and `rtk` wrapper normalization for
  both dry-run command-shape candidates and Claude settings permission-family
  candidates.
- FR-005-17: Tests must verify generated-artifact lifecycle setup covers dry-run
  logs, candidate files, and dry-run lock files.

### Acceptance Criteria

- AC-005-1: Given a corpus of previously blocked but safe inspection commands,
  when tests run, then the policy classifies them as allowable for Claude.
- AC-005-2: Given a corpus of unsafe shell, git, RTK, and secret-read commands,
  when tests run, then none are classified as allowable.
- AC-005-3: Given hook output logs are inspected, when commands include
  sensitive paths or environment-like tokens, then logs contain only redacted
  reasons and safe command summaries.
- AC-005-4: Given a dry-run event log exists under `policy-artifact-root`, when a
  provider session directory or disposable worktree is deleted and recreated,
  then the dry-run event log remains available for rollout reporting.
- AC-005-5: Given multiple agents invoke the Bash policy hook at the same time,
  when they append dry-run events to the shared `policy-artifact-root` log, then
  every event is present as one complete JSONL record and the report can read the
  file without parse errors.
- AC-005-6: Given a Bash policy hook runs from an auxiliary worktree whose
  `git rev-parse --show-toplevel` is the worktree, when dry-run logging occurs,
  then the event is written under `policy-artifact-root` and no
  `.bash-policy-dry-run.jsonl` is created in the auxiliary worktree root.
- AC-005-7: Given representative read-only Unix commands such as `cat`, `date`,
  `sort`, `uniq`, and `rtk sort`, when the evaluator and export built-in coverage
  predicates are tested together, then each command has the same allow/covered
  result in both paths.
- AC-005-8: Given an observed compound command with multiple operations, when the
  regression corpus runs, then tests assert the diagnostic compound shape,
  quote-preserving leaf extraction, omission of built-in-covered leaves, and
  successful runtime allow when all leaves are covered by built-ins or configured
  leaf command-shape rules.
- AC-005-9: Given legacy candidate evidence includes both a reconstructable full
  summary and an unreconstructable display-truncated summary, when export tests
  run, then the full summary is canonicalized into placeholders and the truncated
  identity is omitted.
- AC-005-10: Given `.claude/settings.json` contains broad read-only families and
  `rtk`-wrapped families, when export tests run, then built-in-covered families
  are omitted, recoverable wrapper families are normalized to the inner family,
  and unresolved non-built-in permission families remain export-only candidates.
- AC-005-11: Given standalone ignore/exclude setup is tested, when the generated
  artifact paths are inspected, then dry-run log files, dry-run lock files, and
  candidate files are all ignored or worktree-excluded.
