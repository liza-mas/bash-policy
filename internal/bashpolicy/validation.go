package bashpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type PolicyValidationResult struct {
	Path      string
	RuleCount int
	Issues    []PolicyValidationIssue
}

type PolicyValidationIssue struct {
	Line    int
	Column  int
	Message string
}

type PolicyValidationError struct {
	Result PolicyValidationResult
}

func (err PolicyValidationError) Error() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "bash policy validation failed: %s", err.Result.Path)
	for _, issue := range err.Result.Issues {
		fmt.Fprintf(&builder, "\n  - %s", issue.String())
	}
	return builder.String()
}

func (issue PolicyValidationIssue) String() string {
	location := "unknown location"
	if issue.Line > 0 {
		location = fmt.Sprintf("line %d", issue.Line)
		if issue.Column > 0 {
			location = fmt.Sprintf("%s:%d", location, issue.Column)
		}
	}
	return fmt.Sprintf("%s: %s", location, issue.Message)
}

func ValidatePolicyRoot(root string) (PolicyValidationResult, error) {
	if strings.TrimSpace(root) == "" {
		return PolicyValidationResult{}, fmt.Errorf("policy-artifact-root is required")
	}
	return ValidatePolicyFile(filepath.Join(root, PolicyFileName))
}

func ValidatePolicyFile(path string) (PolicyValidationResult, error) {
	result := PolicyValidationResult{Path: path}
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return result, fmt.Errorf("bash policy file not found: %s", path)
	}
	if err != nil {
		return result, fmt.Errorf("read bash policy: %w", err)
	}

	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return result, fmt.Errorf("parse bash policy: %w", err)
	}
	if len(document.Content) == 0 {
		result.addIssue(&document, "policy file must contain a top-level mapping with rules")
		return result, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		result.addIssue(root, "top-level policy must be a mapping")
		return result, nil
	}

	rulesNode := validateTopLevelPolicyMapping(&result, root)
	if rulesNode == nil {
		return result, nil
	}
	validateRulesNode(&result, rulesNode)
	return result, nil
}

func validateTopLevelPolicyMapping(result *PolicyValidationResult, root *yaml.Node) *yaml.Node {
	var rulesNode *yaml.Node
	seen := map[string]*yaml.Node{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		name := strings.TrimSpace(key.Value)
		if first := seen[name]; first != nil {
			result.addIssue(key, "duplicate top-level field %q (first defined at line %d)", name, first.Line)
			continue
		}
		seen[name] = key
		switch name {
		case "rules":
			rulesNode = value
		default:
			result.addIssue(key, "unknown top-level field %q", name)
		}
	}
	if rulesNode == nil {
		result.addIssue(root, "missing top-level \"rules\" sequence")
	}
	return rulesNode
}

func validateRulesNode(result *PolicyValidationResult, rulesNode *yaml.Node) {
	if rulesNode.Kind != yaml.SequenceNode {
		result.addIssue(rulesNode, "top-level \"rules\" must be a sequence")
		return
	}
	seenRules := map[string]*yaml.Node{}
	for index, ruleNode := range rulesNode.Content {
		validatePolicyRuleNode(result, index, ruleNode, seenRules)
	}
}

func validatePolicyRuleNode(result *PolicyValidationResult, index int, node *yaml.Node, seenRules map[string]*yaml.Node) {
	result.RuleCount++
	if node.Kind != yaml.MappingNode {
		result.addIssue(node, "rules[%d] must be a mapping", index)
		return
	}
	fields := policyRuleFields(result, index, node)

	kind, kindOK := requiredRuleStringField(result, index, node, fields, "kind")
	identity, identityOK := requiredRuleStringField(result, index, node, fields, "identity")
	if !kindOK || !identityOK {
		return
	}
	switch kind {
	case "command-shape":
		validateCommandShapeRule(result, index, node, fields, identity)
	case "permission-family":
		validatePermissionFamilyRule(result, index, node, fields, identity)
	default:
		result.addIssue(fields["kind"], "rules[%d].kind must be \"command-shape\" or \"permission-family\"", index)
		return
	}
	key := kind + ":" + identity
	if first := seenRules[key]; first != nil {
		result.addIssue(fields["identity"], "rules[%d] duplicates %s identity %q first defined at line %d", index, kind, identity, first.Line)
		return
	}
	seenRules[key] = fields["identity"]
}

func policyRuleFields(result *PolicyValidationResult, index int, node *yaml.Node) map[string]*yaml.Node {
	fields := map[string]*yaml.Node{}
	seen := map[string]*yaml.Node{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		name := strings.TrimSpace(key.Value)
		if first := seen[name]; first != nil {
			result.addIssue(key, "rules[%d] duplicates field %q (first defined at line %d)", index, name, first.Line)
			continue
		}
		seen[name] = key
		switch name {
		case "kind", "identity", "decision", "status":
			fields[name] = value
		default:
			result.addIssue(key, "rules[%d] has unknown field %q", index, name)
		}
	}
	return fields
}

func validateCommandShapeRule(result *PolicyValidationResult, index int, node *yaml.Node, fields map[string]*yaml.Node, identity string) {
	decision, decisionOK := requiredRuleStringField(result, index, node, fields, "decision")
	if decisionOK {
		switch Decision(decision) {
		case DecisionAllow, DecisionDeny, DecisionManual:
		default:
			result.addIssue(fields["decision"], "rules[%d].decision must be allow, deny, or manual", index)
		}
	}
	if statusNode := fields["status"]; statusNode != nil {
		result.addIssue(statusNode, "rules[%d].status is not supported for command-shape rules", index)
	}
	if !commandShapeIdentityUsable(identity) {
		result.addIssue(fields["identity"], "rules[%d].identity is not a usable command-shape identity", index)
	}
}

func validatePermissionFamilyRule(result *PolicyValidationResult, index int, node *yaml.Node, fields map[string]*yaml.Node, identity string) {
	status, statusOK := requiredRuleStringField(result, index, node, fields, "status")
	if statusOK && status != "resolved" {
		result.addIssue(fields["status"], "rules[%d].status must be resolved", index)
	}
	if decisionNode := fields["decision"]; decisionNode != nil {
		result.addIssue(decisionNode, "rules[%d].decision is not supported for permission-family rules", index)
	}
	if normalized := NormalizePermissionFamily(identity); normalized == "" || normalized != identity {
		result.addIssue(fields["identity"], "rules[%d].identity must be a canonical Bash(<family>:*) permission family", index)
	}
}

func requiredRuleStringField(result *PolicyValidationResult, index int, ruleNode *yaml.Node, fields map[string]*yaml.Node, field string) (string, bool) {
	node := fields[field]
	if node == nil {
		result.addIssue(ruleNode, "rules[%d].%s is required", index, field)
		return "", false
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		result.addIssue(node, "rules[%d].%s must be a string", index, field)
		return "", false
	}
	value := strings.TrimSpace(node.Value)
	if value == "" {
		result.addIssue(node, "rules[%d].%s must not be empty", index, field)
		return "", false
	}
	return value, true
}

func (result *PolicyValidationResult) addIssue(node *yaml.Node, format string, args ...any) {
	issue := PolicyValidationIssue{Message: fmt.Sprintf(format, args...)}
	if node != nil {
		issue.Line = node.Line
		issue.Column = node.Column
	}
	result.Issues = append(result.Issues, issue)
}
