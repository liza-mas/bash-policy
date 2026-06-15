package commands

import (
	"fmt"
	"io"

	"github.com/liza-mas/bash-policy/internal/bashpolicy"
)

type BashPolicyValidateOptions struct {
	PolicyArtifactRoot string
}

func BashPolicyValidateCommand(output io.Writer, opts BashPolicyValidateOptions) error {
	policyRoot, err := bashpolicy.ResolveInteractivePolicyArtifactRoot(opts.PolicyArtifactRoot)
	if err != nil {
		return err
	}
	result, err := bashpolicy.ValidatePolicyRoot(policyRoot)
	if err != nil {
		return err
	}
	if len(result.Issues) > 0 {
		return bashpolicy.PolicyValidationError{Result: result}
	}
	fmt.Fprintf(output, "Bash policy valid: %s (%d rules)\n", result.Path, result.RuleCount)
	return nil
}

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
