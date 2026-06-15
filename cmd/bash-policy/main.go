package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/liza-mas/bash-policy/internal/commands"
	"github.com/liza-mas/bash-policy/internal/gitenv"
	"github.com/liza-mas/bash-policy/internal/version"
)

type status int

const (
	statusOK    status = 0
	statusUsage status = 2
)

const helpText = `Description:
  Evaluate, install, and report provider-aware bash command policy.

Usage:
  bash-policy --help
  bash-policy --version
  bash-policy init [--provider claude|codex|all] [--policy-artifact-root DIR] [--command COMMAND]
  bash-policy evaluate [--provider claude|codex] [--mode on|dry-run|off] --policy-artifact-root DIR --safe-root DIR
  bash-policy activation on|dry-run|off [--provider claude|codex|all] [--policy-artifact-root DIR] [--command COMMAND]
  bash-policy report [--provider claude|codex] [--policy-artifact-root DIR] [--claude-settings PATH]
  bash-policy export [--provider claude|codex] [--policy-artifact-root DIR] [--claude-settings PATH]
  bash-policy codex-readiness [--json]

Exit codes:
  0  success
  2  usage error
`

func main() {
	os.Exit(int(runWithBuildIdentity(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version.Current())))
}

func run(args []string, stdout io.Writer, stderr io.Writer) status {
	return runWithBuildIdentity(args, os.Stdin, stdout, stderr, version.Current())
}

func runWithBuildIdentity(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer, buildIdentity version.BuildIdentity) status {
	if len(args) == 0 || isHelpArg(args[0]) {
		if _, err := fmt.Fprint(stdout, helpText); err != nil {
			return writeDiagnostic(stderr, err.Error())
		}
		return statusOK
	}
	if len(args) == 1 && args[0] == "--version" {
		if _, err := fmt.Fprintln(stdout, version.Format(buildIdentity)); err != nil {
			return writeDiagnostic(stderr, err.Error())
		}
		return statusOK
	}

	var err error
	switch args[0] {
	case "init":
		err = runInit(args[1:], stdin, stdout)
	case "evaluate":
		err = runEvaluate(args[1:], stdin, stdout, stderr)
	case "activation":
		err = runActivation(args[1:], stdin, stdout)
	case "report":
		err = runReport(args[1:], stdin, stdout)
	case "export":
		err = runExport(args[1:], stdout)
	case "codex-readiness":
		err = runCodexReadiness(args[1:], stdout)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		return writeDiagnostic(stderr, err.Error())
	}
	return statusOK
}

func runInit(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlagSet("init")
	provider := fs.String("provider", "all", "provider hook to install: claude, codex, or all")
	policyRoot := fs.String("policy-artifact-root", "", "durable root for bash policy artifacts")
	command := fs.String("command", "", "bash-policy command to write into provider hooks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("init does not accept positional arguments")
	}
	projectRoot, err := requireProjectRoot()
	if err != nil {
		return err
	}
	resolvedPolicyRoot := *policyRoot
	if strings.TrimSpace(resolvedPolicyRoot) == "" {
		resolvedPolicyRoot = projectRoot
	}
	resolvedCommand := *command
	if strings.TrimSpace(resolvedCommand) == "" {
		resolvedCommand, err = defaultExecutableCommand()
		if err != nil {
			return err
		}
	}
	return commands.BashPolicyInitCommand(stdout, projectRoot, commands.BashPolicyInitOptions{
		Provider:           *provider,
		PolicyArtifactRoot: resolvedPolicyRoot,
		Command:            resolvedCommand,
		Reader:             bufio.NewReader(stdin),
	})
}

func runEvaluate(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := newFlagSet("evaluate")
	provider := fs.String("provider", "claude", "provider adapter: claude or codex")
	mode := fs.String("mode", "dry-run", "activation: on, dry-run, or off")
	policyRoot := fs.String("policy-artifact-root", "", "durable root for bash policy artifacts")
	var safeRoots stringArrayFlag
	fs.Var(&safeRoots, "safe-root", "canonical project/worktree root eligible for safe path checks")
	jsonOutput := fs.Bool("json", false, "write evaluation result JSON instead of provider hook output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("evaluate does not accept positional arguments")
	}
	return commands.BashPolicyEvaluateCommand(stdin, stdout, commands.BashPolicyEvaluateOptions{
		Provider:           *provider,
		Mode:               *mode,
		PolicyArtifactRoot: *policyRoot,
		SafeRoots:          safeRoots,
		JSON:               *jsonOutput,
		Diagnostics:        stderr,
	})
}

func runActivation(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("activation requires on, dry-run, or off")
	}
	activation := args[0]
	fs := newFlagSet("activation")
	provider := fs.String("provider", "all", "provider hook to update: claude, codex, or all")
	policyRoot := fs.String("policy-artifact-root", "", "durable root for bash policy artifacts")
	commandFlag := fs.String("command", "", "override bash-policy command written into provider hooks")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("activation accepts exactly one activation argument")
	}
	projectRoot, err := requireProjectRoot()
	if err != nil {
		return err
	}
	commandOverride := flagArgPresent(args[1:], "command")
	command := *commandFlag
	if strings.TrimSpace(command) == "" {
		command, err = defaultExecutableCommand()
	}
	if err != nil {
		return err
	}
	return commands.BashPolicyActivationCommand(stdout, projectRoot, commands.BashPolicyActivationOptions{
		Provider:           *provider,
		Activation:         activation,
		PolicyArtifactRoot: *policyRoot,
		Command:            command,
		CommandOverride:    commandOverride,
		Reader:             bufio.NewReader(stdin),
	})
}

func runReport(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := newFlagSet("report")
	provider := fs.String("provider", "claude", "provider report target")
	policyRoot := fs.String("policy-artifact-root", "", "durable root for bash policy artifacts")
	claudeSettings := fs.String("claude-settings", "", "Claude settings JSON to seed Bash permission migration rows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("report does not accept positional arguments")
	}
	return commands.BashPolicyReportCommand(optionalStdinReader(stdin), stdout, commands.BashPolicyReportOptions{
		Provider:           *provider,
		PolicyArtifactRoot: *policyRoot,
		ClaudeSettings:     *claudeSettings,
	})
}

func runExport(args []string, stdout io.Writer) error {
	fs := newFlagSet("export")
	provider := fs.String("provider", "claude", "provider export target")
	policyRoot := fs.String("policy-artifact-root", "", "durable root for bash policy artifacts")
	claudeSettings := fs.String("claude-settings", "", "Claude settings JSON to seed Bash permission-family candidates")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("export does not accept positional arguments")
	}
	return commands.BashPolicyExportCommand(stdout, commands.BashPolicyExportOptions{
		Provider:           *provider,
		PolicyArtifactRoot: *policyRoot,
		ClaudeSettings:     *claudeSettings,
	})
}

func runCodexReadiness(args []string, stdout io.Writer) error {
	fs := newFlagSet("codex-readiness")
	jsonOutput := fs.Bool("json", false, "write JSON readiness output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("codex-readiness does not accept positional arguments")
	}
	projectRoot, err := requireProjectRoot()
	if err != nil {
		return err
	}
	return commands.BashPolicyCodexReadinessCommand(stdout, projectRoot, *jsonOutput)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("bash-policy "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func requireProjectRoot() (string, error) {
	output, err := gitenv.Output("", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("resolve project root with git rev-parse --show-toplevel: %w", err)
	}
	root := strings.TrimSpace(string(output))
	if root == "" {
		return "", errors.New("git rev-parse --show-toplevel returned empty project root")
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return filepath.Clean(root), nil
}

func defaultExecutableCommand() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	abs, err := filepath.Abs(executable)
	if err != nil {
		return "", fmt.Errorf("resolve current executable path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

func writeDiagnostic(stderr io.Writer, message string) status {
	fmt.Fprintf(stderr, "bash-policy: %s\n", message)
	return statusUsage
}

func isHelpArg(arg string) bool {
	return arg == "--help" || arg == "-h" || arg == "help"
}

func optionalStdinReader(stdin io.Reader) io.Reader {
	file, ok := stdin.(*os.File)
	if !ok {
		return stdin
	}
	info, err := file.Stat()
	if err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return strings.NewReader("")
	}
	return stdin
}

func flagArgPresent(args []string, name string) bool {
	long := "--" + name
	short := "-" + name
	for _, arg := range args {
		if arg == long || strings.HasPrefix(arg, long+"=") || arg == short || strings.HasPrefix(arg, short+"=") {
			return true
		}
	}
	return false
}

type stringArrayFlag []string

func (f *stringArrayFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringArrayFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
