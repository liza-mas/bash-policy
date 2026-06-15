BINARY_NAME ?= bash-policy
BUILD_DIR ?= build
GO ?= go
INSTALL_DIR ?= $(HOME)/.local/bin
MODULE_PATH ?= github.com/liza-mas/bash-policy
RELEASE_IDENTITY ?=
SOURCE_REF ?= local
SOURCE_REVISION ?= unknown

VERSION_LDFLAGS := \
	-X '$(MODULE_PATH)/internal/version.ReleaseIdentity=$(RELEASE_IDENTITY)' \
	-X '$(MODULE_PATH)/internal/version.SourceRef=$(SOURCE_REF)' \
	-X '$(MODULE_PATH)/internal/version.SourceRevision=$(SOURCE_REVISION)'

.PHONY: build check-testhelpers install release-build sync-embedded test validate-distribution

test:
	$(GO) test ./...

validate-distribution:
	@GO="$(GO)" sh ./scripts/validate-distribution.sh

build:
	@command -v "$(GO)" >/dev/null 2>&1 || { printf 'Go is required for source builds: %s\n' "$(GO)" >&2; exit 1; }
	@mkdir -p "$(BUILD_DIR)"
	@$(GO) build \
		-ldflags "$(VERSION_LDFLAGS)" \
		-o "$(BUILD_DIR)/$(BINARY_NAME)" \
		./cmd/bash-policy || { printf 'source build failed\n' >&2; exit 1; }

release-build:
	@[ -n "$(RELEASE_IDENTITY)" ] || { printf 'RELEASE_IDENTITY is required for release builds\n' >&2; exit 1; }
	@$(MAKE) build RELEASE_IDENTITY="$(RELEASE_IDENTITY)"

install: build
	@dest="$(INSTALL_DIR)/$(BINARY_NAME)"; \
	mkdir -p "$(INSTALL_DIR)" || { printf 'INSTALL_DIR is not usable: %s\n' "$(INSTALL_DIR)" >&2; exit 1; }; \
	cp "$(BUILD_DIR)/$(BINARY_NAME)" "$$dest" || { printf 'INSTALL_DIR is not usable: %s\n' "$(INSTALL_DIR)" >&2; exit 1; }; \
	chmod 0755 "$$dest" || { printf 'INSTALL_DIR is not usable: %s\n' "$(INSTALL_DIR)" >&2; exit 1; }; \
	if [ ! -x "$$dest" ]; then \
		printf 'installed bash-policy is not executable: %s\n' "$$dest" >&2; \
		exit 1; \
	fi; \
	if ! version_output=$$("$$dest" --version 2>&1); then \
		printf 'installed bash-policy at %s failed --version\n' "$$dest" >&2; \
		exit 1; \
	fi; \
	case "$$version_output" in \
	*"source"* ) ;; \
	*) printf 'installed bash-policy at %s did not report source provenance\n' "$$dest" >&2; exit 1 ;; \
	esac; \
	case "$$version_output" in \
	*"$(SOURCE_REF)"*"$(SOURCE_REVISION)"* ) ;; \
	*) printf 'installed bash-policy at %s did not report requested source provenance\n' "$$dest" >&2; exit 1 ;; \
	esac; \
	printf 'Installed bash-policy source ref=%s revision=%s to %s\n' "$(SOURCE_REF)" "$(SOURCE_REVISION)" "$$dest"

sync-embedded:

check-testhelpers:
