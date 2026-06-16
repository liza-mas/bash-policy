package bashpolicy

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func literalArgs(words []*syntax.Word) ([]string, bool) {
	args := make([]string, 0, len(words))
	for _, word := range words {
		lit, ok := literalWord(word)
		if !ok {
			return nil, false
		}
		args = append(args, lit)
	}
	return args, true
}

func literalWord(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var builder strings.Builder
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			builder.WriteString(typed.Value)
		case *syntax.SglQuoted:
			builder.WriteString(typed.Value)
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				builder.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return builder.String(), true
}
