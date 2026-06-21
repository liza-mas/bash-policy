package bashpolicy

import "strings"

type claudeAllowPermission struct {
	prefix []string
}

type claudeDenyPermission struct {
	prefix []string
}

func parseClaudeAllowPermissions(permissions []string) []claudeAllowPermission {
	seen := map[string]bool{}
	out := make([]claudeAllowPermission, 0, len(permissions))
	for _, permission := range permissions {
		prefix, ok := claudeAllowPermissionPrefix(permission)
		if !ok {
			continue
		}
		key := strings.Join(prefix, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, claudeAllowPermission{prefix: prefix})
	}
	return out
}

func parseClaudeDenyPermissions(permissions []string) []claudeDenyPermission {
	seen := map[string]bool{}
	out := make([]claudeDenyPermission, 0, len(permissions))
	for _, permission := range permissions {
		prefix, ok := claudeDenyPermissionPrefix(permission)
		if !ok {
			continue
		}
		key := strings.Join(prefix, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, claudeDenyPermission{prefix: prefix})
	}
	return out
}

func claudeAllowPermissionPrefix(permission string) ([]string, bool) {
	trimmed := strings.TrimSpace(permission)
	if !strings.HasPrefix(trimmed, "Bash(") || !strings.HasSuffix(trimmed, ")") {
		return nil, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "Bash("), ")"))
	if inner == "" {
		return nil, false
	}
	if strings.HasSuffix(inner, ":*") {
		inner = strings.TrimSpace(strings.TrimSuffix(inner, ":*"))
	}
	if inner == "*" {
		return nil, false
	}
	if strings.HasPrefix(inner, "rtk ") {
		wrapped := strings.TrimSpace(strings.TrimPrefix(inner, "rtk "))
		if wrapped != "" && commandFamily(wrapped) != "proxy" {
			inner = wrapped
		}
	}
	fields, ok := commandShapeFields(inner)
	if !ok || len(fields) == 0 {
		return nil, false
	}
	if !claudeAllowPermissionPrefixSupported(fields) {
		return nil, false
	}
	for _, field := range fields {
		if shellOperatorToken(field) {
			return nil, false
		}
	}
	return fields, true
}

func claudeDenyPermissionPrefix(permission string) ([]string, bool) {
	trimmed := strings.TrimSpace(permission)
	if !strings.HasPrefix(trimmed, "Bash(") || !strings.HasSuffix(trimmed, ")") {
		return nil, false
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "Bash("), ")"))
	if inner == "" {
		return nil, false
	}
	if strings.HasSuffix(inner, ":*") {
		inner = strings.TrimSpace(strings.TrimSuffix(inner, ":*"))
	}
	if inner == "*" {
		return []string{"*"}, true
	}
	if strings.HasPrefix(inner, "rtk ") {
		wrapped := strings.TrimSpace(strings.TrimPrefix(inner, "rtk "))
		if wrapped != "" && commandFamily(wrapped) != "proxy" {
			inner = wrapped
		}
	}
	fields, ok := commandShapeFields(inner)
	if !ok || len(fields) == 0 {
		return nil, false
	}
	for _, field := range fields {
		if shellOperatorToken(field) {
			return nil, false
		}
	}
	return fields, true
}

func (ev evaluator) evalConfiguredPolicy(argv []string, cwd string) (Result, bool) {
	shape := ev.policyCommandShape(argv, cwd)
	if shape == "" {
		return Result{}, false
	}
	if denyResult, ok := ev.evalClaudeDenyPermission(shape, argv); ok {
		return denyResult, true
	}
	if policyResult, ok := ev.evalConfiguredCommandShape(shape, argv); ok {
		return policyResult, true
	}
	return ev.evalClaudeAllowPermission(shape, argv)
}

func (ev evaluator) evalConfiguredCommandShape(shape string, argv []string) (Result, bool) {
	if ev.policy == nil {
		return Result{}, false
	}
	rule, ok := ev.policy.CommandRule(shape)
	if !ok {
		return Result{}, false
	}
	switch rule.Decision {
	case DecisionAllow, DecisionDeny, DecisionManual:
		res := result(rule.Decision, "project bash policy command-shape rule", argv)
		res.CommandShape = shape
		return res, true
	default:
		return Result{}, false
	}
}

func (ev evaluator) evalClaudeAllowPermission(shape string, argv []string) (Result, bool) {
	if len(ev.claudeAllowPermissions) == 0 {
		return Result{}, false
	}
	shapeFields, ok := commandShapeFields(shape)
	if !ok || len(shapeFields) == 0 {
		return Result{}, false
	}
	for _, permission := range ev.claudeAllowPermissions {
		if (claudeAllowPrefixMatches(permission.prefix, shapeFields) ||
			claudeAllowPrefixMatches(permission.prefix, argv)) &&
			claudeAllowCommandShapeSupported(shapeFields) {
			res := result(DecisionAllow, "Claude settings Bash permission allow entry", argv)
			res.CommandShape = shape
			return res, true
		}
	}
	return Result{}, false
}

func (ev evaluator) evalClaudeDenyPermission(shape string, argv []string) (Result, bool) {
	if len(ev.claudeDenyPermissions) == 0 {
		return Result{}, false
	}
	shapeFields, ok := commandShapeFields(shape)
	if !ok || len(shapeFields) == 0 {
		return Result{}, false
	}
	for _, permission := range ev.claudeDenyPermissions {
		if claudeDenyPrefixMatches(permission.prefix, shapeFields) ||
			claudeDenyPrefixMatches(permission.prefix, argv) {
			res := result(DecisionDeny, "Claude settings Bash permission deny entry", argv)
			res.CommandShape = shape
			return res, true
		}
	}
	return Result{}, false
}

func claudeAllowPrefixMatches(prefix []string, fields []string) bool {
	if len(prefix) == 0 || len(fields) < len(prefix) {
		return false
	}
	for i := range prefix {
		if prefix[i] != fields[i] {
			return false
		}
	}
	return true
}

func claudeDenyPrefixMatches(prefix []string, fields []string) bool {
	if len(prefix) == 1 && prefix[0] == "*" {
		return true
	}
	return claudeAllowPrefixMatches(prefix, fields)
}

func claudeAllowPermissionPrefixSupported(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	if BuiltInCoversCommandShape(strings.Join(fields, " ")) {
		return true
	}
	return claudeAllowGHPRViewPrefix(fields) || (fields[0] == "grep" && len(fields) > 1)
}

func claudeAllowCommandShapeSupported(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	if BuiltInCoversCommandShape(strings.Join(fields, " ")) {
		return true
	}
	return claudeAllowGHPRViewShape(fields) || claudeAllowGrepCommandShape(fields)
}

func claudeAllowGHPRViewPrefix(fields []string) bool {
	return len(fields) == 3 && fields[0] == "gh" && fields[1] == "pr" && fields[2] == "view"
}

func claudeAllowGHPRViewShape(fields []string) bool {
	return len(fields) == 4 && claudeAllowGHPRViewPrefix(fields[:3]) && fields[3] == "<number>"
}

func claudeAllowGrepCommandShape(fields []string) bool {
	return len(fields) > 1 && fields[0] == "grep"
}
