package bashpolicy

import (
	"path/filepath"
	"strings"
	"unicode"
)

var sensitiveExtensions = map[string]bool{
	".env":      true,
	".key":      true,
	".pem":      true,
	".p12":      true,
	".pfx":      true,
	".jks":      true,
	".keystore": true,
}

var sensitiveTokenPrefixes = []string{
	"akia",
	"github_pat_",
	"ghp_",
	"gho_",
	"ghu_",
	"glpat-",
	"sk-",
	"xoxb-",
	"xoxp-",
}

var sensitiveBaseNames = map[string]bool{
	"id_dsa":     true,
	"id_ecdsa":   true,
	"id_ed25519": true,
	"id_rsa":     true,
}

var sensitiveBaseSuffixes = []string{
	"_dsa",
	"_ecdsa",
	"_ed25519",
	"_rsa",
}

func LooksSensitive(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	normalized := strings.ReplaceAll(lower, "\\", "/")
	base := filepath.Base(normalized)
	ext := filepath.Ext(base)
	if sensitiveBaseNames[base] {
		return true
	}
	for _, suffix := range sensitiveBaseSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	if sensitiveExtensions[ext] || base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	if strings.Contains(normalized, "/.ssh") ||
		strings.Contains(normalized, "/secrets/") ||
		strings.Contains(normalized, "credentials") ||
		strings.Contains(normalized, "credential") ||
		strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "serviceaccountkey.json") {
		return true
	}
	if strings.Contains(lower, "token") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "password") {
		return true
	}
	for _, prefix := range sensitiveTokenPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if key, _, ok := strings.Cut(value, "="); ok && LooksSensitive(key) {
		return true
	}
	if looksHighEntropyToken(value) {
		return true
	}
	return false
}

func looksHighEntropyToken(value string) bool {
	trimmed := strings.Trim(strings.TrimSpace(value), `"'`)
	if len(trimmed) < 32 || strings.ContainsAny(trimmed, `/\`) {
		return false
	}
	if allHex(trimmed) {
		return false
	}
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false
	for _, r := range trimmed {
		switch {
		case unicode.IsSpace(r):
			return false
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune("-_=+", r):
			hasSymbol = true
		default:
			return false
		}
	}
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			classes++
		}
	}
	return classes >= 3
}

func allHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func argvHasSensitiveValue(argv []string) bool {
	for _, arg := range argv {
		if LooksSensitive(arg) {
			return true
		}
	}
	return false
}

func redactedSummary(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	limit := len(argv)
	if limit > 8 {
		limit = 8
	}
	parts := make([]string, 0, limit+1)
	for _, arg := range argv[:limit] {
		if LooksSensitive(arg) {
			parts = append(parts, "<redacted>")
			continue
		}
		if len(arg) > 80 {
			parts = append(parts, arg[:77]+"...")
			continue
		}
		parts = append(parts, arg)
	}
	if len(argv) > limit {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " ")
}

func sanitizeSummary(summary string) string {
	fields := strings.Fields(summary)
	if len(fields) == 0 {
		return ""
	}
	for i, field := range fields {
		if LooksSensitive(field) {
			fields[i] = "<redacted>"
		}
	}
	return strings.Join(fields, " ")
}
