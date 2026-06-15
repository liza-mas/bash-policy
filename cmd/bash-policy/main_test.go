package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tangi-vass/bash-policy/internal/version"
)

func TestRunHelpDoesNotRequirePolicyInput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	got := runWithBuildIdentity([]string{"--help"}, &stdout, &stderr, version.BuildIdentity{})

	if got != statusOK {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusOK)
	}
	if !strings.Contains(stdout.String(), "bash-policy --version") {
		t.Fatalf("stdout = %q, want usage", stdout.String())
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

	got := runWithBuildIdentity([]string{"check"}, &stdout, &stderr, version.BuildIdentity{})

	if got != statusUsage {
		t.Fatalf("runWithBuildIdentity() status = %d, want %d", got, statusUsage)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "usage: bash-policy --help | --version") {
		t.Fatalf("stderr = %q, want usage diagnostic", stderr.String())
	}
}
