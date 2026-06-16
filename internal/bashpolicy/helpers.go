package bashpolicy

import (
	"strings"
)

func result(decision Decision, reason string, argv []string) Result {
	summary := redactedSummary(argv)
	family := ""
	if len(argv) > 0 {
		family = argv[0]
	}
	return Result{Decision: decision, Reason: reason, Summary: summary, CommandFamily: family}
}

func isInteger(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksFieldList(value string) bool {
	if value == "" || strings.ContainsAny(value, "/\\") {
		return false
	}
	fields := strings.Split(value, ",")
	if len(fields) < 2 {
		return false
	}
	for _, field := range fields {
		if field == "" {
			return false
		}
		for _, r := range field {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

func stringSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
