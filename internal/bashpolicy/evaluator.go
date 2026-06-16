package bashpolicy

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func (ev evaluator) evalStmt(stmt *syntax.Stmt, cwd string) Result {
	if stmt == nil || stmt.Cmd == nil {
		return result(DecisionNoOp, "empty statement", nil)
	}
	if stmt.Negated || stmt.Background || stmt.Coprocess {
		return result(DecisionManual, "shell control modifiers are not auto-allowed", nil)
	}
	if len(stmt.Redirs) > 0 {
		return result(DecisionManual, "shell redirections are not auto-allowed", nil)
	}

	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		argv, ok := literalArgs(cmd.Args)
		if !ok {
			return result(DecisionManual, "dynamic command or argument is not auto-allowed", nil)
		}
		return ev.evalArgv(argv, cwd)
	case *syntax.BinaryCmd:
		return ev.evalCompoundStmts([]*syntax.Stmt{stmt}, cwd, "compound shell command is not auto-allowed")
	default:
		return result(DecisionManual, "compound shell command is not auto-allowed", nil)
	}
}

func (ev evaluator) evalCompoundStmts(stmts []*syntax.Stmt, cwd string, reason string) Result {
	shape, leaves, ok, floor := ev.compoundCommandParts(stmts, cwd)
	if floor.Decision != "" {
		return floor
	}
	if !ok || shape == "" || len(leaves) == 0 {
		return result(DecisionManual, reason, nil)
	}
	for _, leaf := range leaves {
		leafResult := ev.evalArgv(leaf.argv, leaf.cwd)
		if leafResult.Decision == DecisionAllow || leafResult.Decision == DecisionNoOp {
			continue
		}
		if leafResult.Decision == DecisionDeny {
			res := result(DecisionDeny, leafResult.Reason, nil)
			res.CommandShape = shape
			return res
		}
		leafReason := strings.TrimSpace(leafResult.Reason)
		if leafReason == "" {
			leafReason = reason
		}
		res := result(DecisionManual, "compound shell command contains manual command: "+leafReason, nil)
		res.CommandShape = shape
		return res
	}
	res := result(DecisionAllow, "compound shell command with allowed commands", nil)
	res.CommandShape = shape
	return res
}

func (ev evaluator) evalArgv(argv []string, cwd string) Result {
	if len(argv) == 0 {
		return result(DecisionNoOp, "empty command", argv)
	}
	if argvHasSensitiveValue(argv) {
		return result(DecisionDeny, "credential path or secret-looking argument is not safe", argv)
	}
	if floor := ev.evalSafetyFloor(argv, cwd); floor.Decision != "" {
		return floor
	}
	if policyResult, ok := ev.evalConfiguredPolicy(argv, cwd); ok {
		return policyResult
	}

	var res Result
	switch argv[0] {
	case "rtk":
		res = ev.evalRTK(argv, cwd)
	case "env":
		res = ev.evalEnv(argv, cwd)
	case "git":
		res = ev.evalGit(argv[1:], cwd, argv)
	case "rg":
		res = ev.evalRG(argv[1:], cwd, argv)
	case "printenv":
		res = result(DecisionDeny, "environment dump commands are not safe", argv)
	default:
		if readOnlyResult, ok := ev.evalReadOnlyUnix(argv, cwd); ok {
			res = readOnlyResult
			break
		}
		res = result(DecisionManual, "command is not in the safe allow profiles", argv)
	}
	return ev.withCommandShape(res, argv, cwd)
}
