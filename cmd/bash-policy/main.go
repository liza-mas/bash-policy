package main

import (
	"fmt"
	"io"
	"os"

	"github.com/tangi-vass/bash-policy/internal/version"
)

type status int

const (
	statusOK    status = 0
	statusUsage status = 2
)

const helpText = `Description:
  Evaluate and enforce bash command policy.

Usage:
  bash-policy --help
  bash-policy --version

Exit codes:
  0  success
  2  usage error
`

func main() {
	os.Exit(int(run(os.Args[1:], os.Stdout, os.Stderr)))
}

func run(args []string, stdout io.Writer, stderr io.Writer) status {
	return runWithBuildIdentity(args, stdout, stderr, version.Current())
}

func runWithBuildIdentity(args []string, stdout io.Writer, stderr io.Writer, buildIdentity version.BuildIdentity) status {
	if len(args) == 1 && args[0] == "--help" {
		if _, err := fmt.Fprint(stdout, helpText); err != nil {
			return writeDiagnostic(stderr, statusUsage, err.Error())
		}
		return statusOK
	}

	if len(args) == 1 && args[0] == "--version" {
		if _, err := fmt.Fprintln(stdout, version.Format(buildIdentity)); err != nil {
			return writeDiagnostic(stderr, statusUsage, err.Error())
		}
		return statusOK
	}

	return writeDiagnostic(stderr, statusUsage, "usage: bash-policy --help | --version")
}

func writeDiagnostic(stderr io.Writer, code status, message string) status {
	fmt.Fprintf(stderr, "bash-policy: %s\n", message)
	return code
}
