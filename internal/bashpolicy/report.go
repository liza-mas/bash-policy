package bashpolicy

import (
	"encoding/json"
	"sort"
	"strings"
)

type ReportOptions struct {
	CandidatePermissions []string
	Policy               *Policy
}

type Report struct {
	Total      int                      `json:"total"`
	ByDecision map[Decision]int         `json:"by_decision"`
	ByReason   map[string]int           `json:"by_reason"`
	Examples   []ReportExample          `json:"examples"`
	Aggregates []ReportAggregate        `json:"aggregates"`
	Migration  []PermissionMigrationRow `json:"migration"`
}

type ReportExample struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Summary  string   `json:"summary"`
}

type ReportAggregate struct {
	Identity string   `json:"identity"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
	Count    int      `json:"count"`
}

type PermissionMigrationRow struct {
	Permission     string   `json:"permission"`
	Candidate      string   `json:"candidate"`
	ProposedStatus string   `json:"proposed_status"`
	Rationale      string   `json:"rationale"`
	Examples       []string `json:"examples,omitempty"`
}

func BuildReport(results []Result, opts ReportOptions) Report {
	report := Report{
		Total:      len(results),
		ByDecision: map[Decision]int{},
		ByReason:   map[string]int{},
	}
	aggregates := map[string]ReportAggregate{}
	for _, item := range results {
		report.ByDecision[item.Decision]++
		report.ByReason[item.Reason]++
		identity := sanitizeSummary(resultIdentity(item))
		if identity != "" {
			key := string(item.Decision) + "\x00" + item.Reason + "\x00" + identity
			aggregate := aggregates[key]
			if aggregate.Identity == "" {
				aggregate = ReportAggregate{Identity: identity, Decision: item.Decision, Reason: item.Reason}
			}
			aggregate.Count++
			aggregates[key] = aggregate
		}
		if len(report.Examples) < 20 {
			report.Examples = append(report.Examples, ReportExample{
				Decision: item.Decision,
				Reason:   item.Reason,
				Summary:  sanitizeSummary(item.Summary),
			})
		}
	}
	for _, aggregate := range aggregates {
		report.Aggregates = append(report.Aggregates, aggregate)
	}
	sort.Slice(report.Aggregates, func(i, j int) bool {
		if report.Aggregates[i].Count != report.Aggregates[j].Count {
			return report.Aggregates[i].Count > report.Aggregates[j].Count
		}
		return report.Aggregates[i].Identity < report.Aggregates[j].Identity
	})
	for _, permission := range opts.CandidatePermissions {
		identity := NormalizePermissionFamily(permission)
		if identity == "" || BuiltInCoversPermissionFamily(identity) || opts.Policy.PermissionFamilyResolved(identity) {
			continue
		}
		row := classifyPermission(permission)
		row.Candidate = identity
		row.Examples = examplesForFamily(results, commandFamily(permissionFamilyInner(identity)))
		report.Migration = append(report.Migration, row)
	}
	sort.Slice(report.Migration, func(i, j int) bool {
		return report.Migration[i].Permission < report.Migration[j].Permission
	})
	return report
}

func ExtractBashPermissions(settingsJSON []byte) []string {
	var doc any
	if err := json.Unmarshal(settingsJSON, &doc); err != nil {
		return nil
	}
	var permissions []string
	collectBashPermissions(doc, &permissions)
	sort.Strings(permissions)
	return permissions
}

func collectBashPermissions(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		if strings.HasPrefix(typed, "Bash(") {
			*out = append(*out, typed)
		}
	case []any:
		for _, item := range typed {
			collectBashPermissions(item, out)
		}
	case map[string]any:
		for _, item := range typed {
			collectBashPermissions(item, out)
		}
	}
}

func classifyPermission(permission string) PermissionMigrationRow {
	candidate := strings.TrimPrefix(permission, "Bash(")
	candidate = strings.TrimSuffix(candidate, ")")
	family := commandFamily(candidate)
	row := PermissionMigrationRow{Permission: permission, Candidate: candidate}
	switch family {
	case "git":
		row.ProposedStatus = "specialize"
		row.Rationale = "only read-only git subcommands and modeled path forms can be auto-allowed"
	case "rtk":
		row.ProposedStatus = "specialize"
		row.Rationale = "rtk must be unwrapped and rtk proxy remains deny/manual"
	case "env", "printenv", "bash", "sh", "cat":
		row.ProposedStatus = "deny/manual"
		row.Rationale = "command family can expose secrets or execute unbounded shell behavior"
	case "sed", "awk", "find", "python", "python3", "node", "npm", "npx", "go", "make":
		row.ProposedStatus = "manual"
		row.Rationale = "argument and execution behavior is too broad for first-phase auto-allow"
	default:
		row.ProposedStatus = "manual"
		row.Rationale = "not promoted until a command-specific read-only profile exists"
	}
	return row
}

func commandFamily(candidate string) string {
	family := candidate
	if before, _, ok := strings.Cut(family, ":"); ok {
		family = before
	}
	if before, _, ok := strings.Cut(family, " "); ok {
		family = before
	}
	return family
}

func permissionFamilyInner(identity string) string {
	inner := strings.TrimPrefix(identity, "Bash(")
	return strings.TrimSuffix(inner, ")")
}

func examplesForFamily(results []Result, family string) []string {
	if family == "" {
		return nil
	}
	seen := map[string]bool{}
	var examples []string
	for _, result := range results {
		if result.CommandFamily != family || result.Summary == "" {
			continue
		}
		summary := sanitizeSummary(result.Summary)
		if summary == "" || seen[summary] {
			continue
		}
		seen[summary] = true
		examples = append(examples, summary)
		if len(examples) == 3 {
			break
		}
	}
	return examples
}
