# bash-policy

`bash-policy` is a Go CLI for bash command policy work. This repository starts
with the same small CLI skeleton used by `../mdtoc`: command entrypoint,
version provenance, build/install targets, distribution validation, and tests.

```bash
bash-policy --help
bash-policy --version
```

## Current CLI Contract

The initial executable exposes only stable help and version output while the
policy model is still undefined.

```text
bash-policy --help
bash-policy --version
```

Unknown arguments are rejected with a usage diagnostic and exit code `2`.

## Installation

**Quick install (latest release, macOS/Linux):**

```bash
curl -fsSL https://raw.githubusercontent.com/tangi-vass/bash-policy/main/install.sh | bash
bash-policy --version
```

**Options:**

```bash
# Explicit release
curl -fsSL https://raw.githubusercontent.com/tangi-vass/bash-policy/main/install.sh | VERSION=<release> bash
bash-policy --version

# Build from a branch with caller-provided Go and make
curl -fsSL https://raw.githubusercontent.com/tangi-vass/bash-policy/main/install.sh | BRANCH=<branch> bash
bash-policy --version

# Custom install directory
curl -fsSL https://raw.githubusercontent.com/tangi-vass/bash-policy/main/install.sh | INSTALL_DIR=<directory> bash
<directory>/bash-policy --version
```

**From a local clone:**

```bash
git clone https://github.com/tangi-vass/bash-policy.git
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
