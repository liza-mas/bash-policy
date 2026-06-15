package commands

import (
	"fmt"
	"io"

	"github.com/tangi-vass/bash-policy/internal/bashpolicy"
)

// WarnCodexBashPolicyReadiness writes the warning used by callers that need to
// surface degraded Codex bash-policy hook readiness.
func WarnCodexBashPolicyReadiness(projectRoot string, warnings io.Writer) {
	if warnings == nil {
		return
	}
	readiness := bashpolicy.AssessCodexReadiness(projectRoot)
	if readiness.Status == bashpolicy.ReadinessNotConfigured ||
		readiness.Status == bashpolicy.ReadinessOff ||
		readiness.Status == bashpolicy.ReadinessBlockingReady {
		return
	}
	fmt.Fprintf(warnings, "WARNING: Codex Bash policy readiness is %s; unsafe commands are log-only/degraded until hook blocking semantics are verified\n", readiness.Status)
}
