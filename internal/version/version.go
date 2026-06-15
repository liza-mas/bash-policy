package version

import (
	"fmt"
	"strings"
)

// ReleaseIdentity, SourceRef, and SourceRevision are build metadata inputs.
// Release/source tooling can set them with Go linker variables.
var (
	ReleaseIdentity string
	SourceRef       = "unknown"
	SourceRevision  = "unknown"
)

// BuildIdentity is the offline identity reported by bash-policy --version.
type BuildIdentity struct {
	Release        string
	SourceRef      string
	SourceRevision string
}

// Current returns release metadata when supplied, otherwise source provenance.
func Current() BuildIdentity {
	release := strings.TrimSpace(ReleaseIdentity)
	if release != "" {
		return BuildIdentity{Release: release}
	}

	return BuildIdentity{
		SourceRef:      fallback(SourceRef),
		SourceRevision: fallback(SourceRevision),
	}
}

// Format renders a human-readable build identity outside the output data path.
func Format(identity BuildIdentity) string {
	release := strings.TrimSpace(identity.Release)
	if release != "" {
		return fmt.Sprintf("bash-policy release %s", release)
	}

	return fmt.Sprintf(
		"bash-policy source ref=%s revision=%s",
		fallback(identity.SourceRef),
		fallback(identity.SourceRevision),
	)
}

func fallback(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}

	return trimmed
}
