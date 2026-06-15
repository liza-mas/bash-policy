#!/bin/bash
# PreToolUse hook: provider-aware Bash policy evaluation.
# Defaults to no behavior change unless the provider adapter emits an explicit
# decision. Policy logic lives in the bash-policy CLI, not in this shell wrapper.

provider="${1:-claude}"
mode="${2:-dry-run}"
bash_policy_bin="${BASH_POLICY_BIN:-bash-policy}"

input=$(cat)

root="${CLAUDE_PROJECT_DIR:-}"
if [[ -z "$root" ]]; then
  root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
fi

if ! command -v "$bash_policy_bin" >/dev/null 2>&1; then
  exit 0
fi

args=(evaluate --provider "$provider" --mode "$mode" --safe-root "$root")
if [[ -n "${BASH_POLICY_ARTIFACT_ROOT:-}" ]]; then
  args+=(--policy-artifact-root "$BASH_POLICY_ARTIFACT_ROOT")
fi

printf "%s" "$input" | "$bash_policy_bin" "${args[@]}"
