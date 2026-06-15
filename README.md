# bash-policy

`bash-policy` exists because Claude Code's `Bash(...)` permissions are too
coarse for real agent workflows. Claude can only configure broad command-family
allow rules, while day-to-day agents mostly run compound shell commands that
either defeat those settings or force unsafe `Bash(*)`-style permissions.

The same policy layer also supports Codex, where the immediate value is
auditability: capture what Bash commands agents actually run, review them as
normalized command shapes, and tighten policy when provider enforcement is
available.

`bash-policy` parses each Bash payload into command units, applies policy to the
actual commands agents are about to run, records dry-run evidence, exports
unresolved policy candidates, and lets teams tighten command access without
losing control.

```bash
bash-policy --help
bash-policy --version
```

## Current CLI Contract

The executable exposes the standalone Bash policy workflow:

```text
bash-policy --help
bash-policy --version
bash-policy init --provider claude|codex|all [--command COMMAND]
bash-policy evaluate --provider claude|codex --mode on|dry-run|off
bash-policy activation on|dry-run|off --provider claude|codex|all [--command COMMAND]
bash-policy validate [--policy-artifact-root DIR]
bash-policy report
bash-policy export
bash-policy codex-readiness
```

Unknown arguments are rejected with a usage diagnostic and exit code `2`.

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for provider hook setup,
policy artifact lifecycle, candidate export, curation, activation, and Codex
readiness.

## Installation

**Quick install (latest release, macOS/Linux):**

```bash
curl -fsSL https://raw.githubusercontent.com/liza-mas/bash-policy/main/install.sh | bash
bash-policy --version
```

**Options:**

```bash
# Explicit release
curl -fsSL https://raw.githubusercontent.com/liza-mas/bash-policy/main/install.sh | VERSION=<release> bash
bash-policy --version

# Build from a branch with caller-provided Go and make
curl -fsSL https://raw.githubusercontent.com/liza-mas/bash-policy/main/install.sh | BRANCH=<branch> bash
bash-policy --version

# Custom install directory
curl -fsSL https://raw.githubusercontent.com/liza-mas/bash-policy/main/install.sh | INSTALL_DIR=<directory> bash
<directory>/bash-policy --version
```

**From a local clone:**

```bash
git clone https://github.com/liza-mas/bash-policy.git
cd bash-policy
make install
bash-policy --version
```

Local clone installs require caller-provided Go and make. Use
`INSTALL_DIR=<directory> make install` to install from a local clone into a
custom directory, then verify with `<directory>/bash-policy --version`.

Build and test:

```bash
make test
make build
```

Build a release artifact whose `--version` output identifies the selected
release:

```bash
make release-build RELEASE_IDENTITY=v1.0.0
./build/bash-policy --version
```
