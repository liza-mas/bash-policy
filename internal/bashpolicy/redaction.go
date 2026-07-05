package bashpolicy

import (
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

var sensitiveExtensions = map[string]bool{
	".env":      true,
	".key":      true,
	".gpg":      true,
	".asc":      true,
	".pem":      true,
	".p12":      true,
	".pfx":      true,
	".pkcs12":   true,
	".ppk":      true,
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
			arg = "<redacted>"
		} else if len(arg) > 80 {
			arg = arg[:77] + "..."
		}
		parts = append(parts, shellQuoteSummaryToken(arg))
	}
	if len(argv) > limit {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " ")
}

func shellQuoteSummaryToken(arg string) string {
	quoted, err := syntax.Quote(arg, syntax.LangBash)
	if err != nil {
		return strconv.Quote(arg)
	}
	return quoted
}

func sanitizeSummary(summary string) string {
	tokens := summaryTokens(summary)
	if len(tokens) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tokens))
	for _, token := range tokens {
		text := summary[token.start:token.end]
		if LooksSensitive(text) || LooksSensitive(dequotedSummaryToken(text)) {
			text = "<redacted>"
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, " ")
}

func dequotedSummaryToken(token string) string {
	if len(token) < 2 {
		return token
	}
	quote := token[0]
	if (quote != '\'' && quote != '"') || token[len(token)-1] != quote {
		return token
	}
	value := token[1 : len(token)-1]
	if quote == '"' {
		value = unescapeDoubleQuotedSummaryToken(value)
	}
	return value
}

func unescapeDoubleQuotedSummaryToken(value string) string {
	var builder strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		builder.WriteByte(value[i])
	}
	return builder.String()
}

type summaryToken struct {
	start int
	end   int
}

func summaryTokens(summary string) []summaryToken {
	tokens := []summaryToken{}
	for i := 0; i < len(summary); {
		for i < len(summary) {
			r, size := rune(summary[i]), 1
			if r >= utf8.RuneSelf {
				r, size = utf8.DecodeRuneInString(summary[i:])
			}
			if !unicode.IsSpace(r) {
				break
			}
			i += size
		}
		if i >= len(summary) {
			break
		}
		start := i
		quote := byte(0)
		for i < len(summary) {
			c := summary[i]
			if quote == 0 {
				r, size := rune(c), 1
				if c >= utf8.RuneSelf {
					r, size = utf8.DecodeRuneInString(summary[i:])
				}
				if unicode.IsSpace(r) {
					break
				}
				if c == '\'' || c == '"' {
					quote = c
					i++
					continue
				}
				if c == '\\' && i+1 < len(summary) {
					i += 2
					continue
				}
				i += size
				continue
			}
			if c == quote {
				quote = 0
				i++
				continue
			}
			if quote == '"' && c == '\\' && i+1 < len(summary) {
				i += 2
				continue
			}
			i++
		}
		tokens = append(tokens, summaryToken{start: start, end: i})
	}
	return tokens
}
