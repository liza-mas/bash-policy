package version

import (
	"strings"
	"testing"
)

func TestFormatDistinguishesReleaseIdentityFromSourceProvenance(t *testing.T) {
	t.Parallel()

	releaseOutput := Format(BuildIdentity{Release: "v1.2.3"})
	sourceOutput := Format(BuildIdentity{SourceRef: "main", SourceRevision: "abc123"})

	for name, output := range map[string]string{
		"release": releaseOutput,
		"source":  sourceOutput,
	} {
		if output == "" {
			t.Fatalf("%s output is empty", name)
		}
		if !strings.Contains(output, "bash-policy") {
			t.Fatalf("%s output = %q, want executable name", name, output)
		}
	}
	if !strings.Contains(releaseOutput, "release") {
		t.Fatalf("release output = %q, want release build marker", releaseOutput)
	}
	if !strings.Contains(releaseOutput, "v1.2.3") {
		t.Fatalf("release output = %q, want supplied release identity", releaseOutput)
	}
	if !strings.Contains(sourceOutput, "source") {
		t.Fatalf("source output = %q, want source build marker", sourceOutput)
	}
	if !strings.Contains(sourceOutput, "main") {
		t.Fatalf("source output = %q, want supplied source ref", sourceOutput)
	}
	if !strings.Contains(sourceOutput, "abc123") {
		t.Fatalf("source output = %q, want supplied source revision", sourceOutput)
	}
	if strings.Contains(sourceOutput, "release") {
		t.Fatalf("source output = %q, must not masquerade as release build", sourceOutput)
	}
	if releaseOutput == sourceOutput {
		t.Fatal("release and source outputs are identical, want distinguishable build identities")
	}
}

func TestCurrentUsesReleaseIdentityBeforeSourceProvenance(t *testing.T) {
	originalRelease := ReleaseIdentity
	originalSourceRef := SourceRef
	originalSourceRevision := SourceRevision
	t.Cleanup(func() {
		ReleaseIdentity = originalRelease
		SourceRef = originalSourceRef
		SourceRevision = originalSourceRevision
	})

	ReleaseIdentity = "v9.9.9"
	SourceRef = "main"
	SourceRevision = "abc123"

	got := Current()

	if got.Release != "v9.9.9" {
		t.Fatalf("Current().Release = %q, want supplied release identity", got.Release)
	}
	if got.SourceRef != "" {
		t.Fatalf("Current().SourceRef = %q, want release identity to suppress source provenance", got.SourceRef)
	}
	if got.SourceRevision != "" {
		t.Fatalf("Current().SourceRevision = %q, want release identity to suppress source provenance", got.SourceRevision)
	}
}

func TestCurrentFallsBackToSourceProvenance(t *testing.T) {
	originalRelease := ReleaseIdentity
	originalSourceRef := SourceRef
	originalSourceRevision := SourceRevision
	t.Cleanup(func() {
		ReleaseIdentity = originalRelease
		SourceRef = originalSourceRef
		SourceRevision = originalSourceRevision
	})

	ReleaseIdentity = ""
	SourceRef = "feature"
	SourceRevision = "def456"

	got := Current()

	if got.Release != "" {
		t.Fatalf("Current().Release = %q, want empty release identity for source build", got.Release)
	}
	if got.SourceRef != "feature" {
		t.Fatalf("Current().SourceRef = %q, want supplied source ref", got.SourceRef)
	}
	if got.SourceRevision != "def456" {
		t.Fatalf("Current().SourceRevision = %q, want supplied source revision", got.SourceRevision)
	}
}
