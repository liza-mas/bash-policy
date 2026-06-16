// Package bashpolicy evaluates provider Bash hook commands against a fail-closed
// allow profile. The evaluator rejects globally unsafe shell shapes before
// consulting project policy, then auto-allows only the hardcoded read-only
// inspection profiles listed below.
//
// Built-in top-level command families:
//   - common Unix inspection commands: basename, cat, cd, cut, date, diff,
//     dirname, echo, file, head, ls, pwd, realpath, sha256sum, sort, tail, tr,
//     tree, uniq, wc, which.
//   - rtk: unwrap and evaluate the wrapped command; rtk proxy is denied.
//   - git: allow only modeled read-only subcommands and safe path forms.
//   - rg: allow modeled read-only ripgrep searches.
//   - printenv/env: deny environment dumps; evaluate safe env launchers.
//
// Hardcoded read-only git subcommands:
//   - status
//   - diff
//   - rev-parse
//   - branch
//   - log/show
//   - worktree list

package bashpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionDeny   Decision = "deny"
	DecisionManual Decision = "manual"
	DecisionNoOp   Decision = "no-op"
)

type Request struct {
	Command            string
	ProjectRoot        string
	SafeRoots          []string
	PolicyArtifactRoot string
	Policy             *Policy
}

type Result struct {
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason"`
	Summary       string   `json:"summary"`
	CommandFamily string   `json:"command_family,omitempty"`
	CommandShape  string   `json:"command_shape,omitempty"`
}

func Evaluate(req Request) Result {
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return result(DecisionNoOp, "empty command", nil)
	}

	ev := newEvaluator(req)
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return result(DecisionManual, "shell parse failed", []string{command})
	}
	if len(file.Stmts) == 0 {
		return result(DecisionNoOp, "empty command", nil)
	}
	var res Result
	if len(file.Stmts) != 1 {
		res = ev.evalCompoundStmts(file.Stmts, ev.defaultCWD, "multiple shell statements are not auto-allowed")
	} else {
		res = ev.evalStmt(file.Stmts[0], ev.defaultCWD)
	}
	if res.Summary == "" && res.Decision != DecisionNoOp {
		res.Summary = sanitizeSummary(command)
	}
	return res
}

func CommandFromHookPayload(data []byte) (string, error) {
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("parse hook payload: %w", err)
	}
	if command, ok := findCommandField(payload); ok && strings.TrimSpace(command) != "" {
		return command, nil
	}
	return "", errors.New("hook payload does not contain a command string")
}

func findCommandField(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if raw, ok := typed["command"]; ok {
			if command, ok := raw.(string); ok {
				return command, true
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if command, ok := findCommandField(typed[key]); ok {
				return command, true
			}
		}
	case []any:
		for _, item := range typed {
			if command, ok := findCommandField(item); ok {
				return command, true
			}
		}
	}
	return "", false
}

type evaluator struct {
	roots      []string
	defaultCWD string
	policy     *Policy
}

func newEvaluator(req Request) evaluator {
	var roots []string
	addRoot := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		roots = append(roots, canonicalRoot(path))
	}
	addRoot(req.ProjectRoot)
	for _, root := range req.SafeRoots {
		addRoot(root)
	}
	roots = uniqueStrings(roots)
	defaultCWD := ""
	if len(roots) > 0 {
		defaultCWD = roots[0]
	}
	return evaluator{roots: roots, defaultCWD: defaultCWD, policy: req.Policy}
}
