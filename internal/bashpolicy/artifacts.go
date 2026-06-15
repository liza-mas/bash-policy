package bashpolicy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/liza-mas/bash-policy/internal/filelock"
	"github.com/liza-mas/bash-policy/internal/gitenv"
	"gopkg.in/yaml.v3"
)

const (
	ActivationOn     = "on"
	ActivationDryRun = "dry-run"
	ActivationOff    = "off"

	PolicyFileName     = ".bash-policy.yaml"
	DryRunLogFileName  = ".bash-policy-dry-run.jsonl"
	CandidatesFileName = ".bash-policy-candidates.yaml"
)

type Policy struct {
	Rules []PolicyRule `yaml:"rules,omitempty"`
}

type PolicyRule struct {
	Kind     string   `yaml:"kind"`
	Identity string   `yaml:"identity"`
	Decision Decision `yaml:"decision,omitempty"`
	Status   string   `yaml:"status,omitempty"`
}

type Event struct {
	Timestamp     string   `json:"timestamp"`
	Provider      string   `json:"provider"`
	Activation    string   `json:"activation"`
	Decision      Decision `json:"decision"`
	Reason        string   `json:"reason"`
	Summary       string   `json:"summary"`
	CommandShape  string   `json:"command_shape"`
	CommandFamily string   `json:"command_family,omitempty"`
}

type CandidateFile struct {
	Candidates []Candidate `yaml:"candidates"`
}

type Candidate struct {
	Kind         string `yaml:"kind"`
	Identity     string `yaml:"identity"`
	Provider     string `yaml:"provider,omitempty"`
	Source       string `yaml:"source"`
	Observations int    `yaml:"observations,omitempty"`
	Status       string `yaml:"status,omitempty"`
}

func NormalizeActivation(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ActivationDryRun:
		return ActivationDryRun, nil
	case ActivationOn:
		return ActivationOn, nil
	case ActivationOff:
		return ActivationOff, nil
	default:
		return "", fmt.Errorf("unsupported bash policy activation %q (want on, dry-run, or off)", value)
	}
}

func ResolveRequiredPolicyArtifactRoot(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return canonicalArtifactRoot(explicit)
	}
	if envRoot := strings.TrimSpace(os.Getenv("BASH_POLICY_ARTIFACT_ROOT")); envRoot != "" {
		return canonicalArtifactRoot(envRoot)
	}
	return "", fmt.Errorf("policy-artifact-root is required")
}

func ResolveInteractivePolicyArtifactRoot(explicit string) (string, error) {
	if root, err := ResolveRequiredPolicyArtifactRoot(explicit); err == nil {
		return root, nil
	}
	root, err := discoverPolicyArtifactRootFromCWD()
	if err != nil {
		return "", fmt.Errorf("policy-artifact-root is required when %s cannot be discovered upward: %w", PolicyFileName, err)
	}
	return root, nil
}

func discoverPolicyArtifactRootFromCWD() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, PolicyFileName)); err == nil {
			return canonicalArtifactRoot(dir)
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func canonicalArtifactRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve policy-artifact-root: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs), nil
}

func LoadPolicy(root string) (*Policy, error) {
	if root == "" {
		return nil, nil
	}
	content, err := os.ReadFile(filepath.Join(root, PolicyFileName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read bash policy: %w", err)
	}
	var policy Policy
	if err := yaml.Unmarshal(content, &policy); err != nil {
		return nil, fmt.Errorf("parse bash policy: %w", err)
	}
	return &policy, nil
}

func (p *Policy) CommandRule(identity string) (PolicyRule, bool) {
	if p == nil {
		return PolicyRule{}, false
	}
	identity = strings.TrimSpace(identity)
	for _, rule := range p.Rules {
		if rule.Kind == "command-shape" && commandShapeRuleMatches(strings.TrimSpace(rule.Identity), identity) {
			return rule, true
		}
	}
	return PolicyRule{}, false
}

func commandShapeRuleMatches(ruleIdentity string, identity string) bool {
	if ruleIdentity == identity {
		return true
	}
	ruleFields, ok := commandShapeFields(ruleIdentity)
	if !ok {
		return false
	}
	identityFields, ok := commandShapeFields(identity)
	if !ok {
		return false
	}
	if len(ruleFields) == 0 || len(identityFields) < len(ruleFields) {
		return false
	}
	variadic := ruleFields[len(ruleFields)-1]
	if !strings.HasSuffix(variadic, "...") {
		if len(ruleFields) != len(identityFields) {
			return false
		}
		for i := range ruleFields {
			if !commandShapeTokenMatches(ruleFields[i], identityFields[i]) {
				return false
			}
		}
		return true
	}
	repeated := strings.TrimSuffix(variadic, "...")
	if !isCommandShapePlaceholder(repeated) {
		return false
	}
	for i := 0; i < len(ruleFields)-1; i++ {
		if !commandShapeTokenMatches(ruleFields[i], identityFields[i]) {
			return false
		}
	}
	for _, field := range identityFields[len(ruleFields)-1:] {
		if field != repeated {
			return false
		}
	}
	return true
}

func commandShapeTokenMatches(ruleToken string, identityToken string) bool {
	if ruleToken == identityToken {
		return true
	}
	if isCommandShapePlaceholder(ruleToken) {
		return wholeTokenPlaceholderMatches(ruleToken, identityToken)
	}
	if !strings.Contains(ruleToken, "<") {
		return false
	}
	return embeddedPlaceholderTokenMatches(ruleToken, identityToken)
}

func wholeTokenPlaceholderMatches(placeholder string, identityToken string) bool {
	switch placeholder {
	case "<number>":
		return isInteger(identityToken)
	case "<fields>":
		return looksFieldList(identityToken)
	default:
		return false
	}
}

func embeddedPlaceholderTokenMatches(ruleToken string, identityToken string) bool {
	ruleIndex := 0
	identityIndex := 0
	for ruleIndex < len(ruleToken) {
		open := strings.IndexByte(ruleToken[ruleIndex:], '<')
		if open < 0 {
			return strings.HasPrefix(identityToken[identityIndex:], ruleToken[ruleIndex:]) &&
				identityIndex+len(ruleToken[ruleIndex:]) == len(identityToken)
		}
		open += ruleIndex
		literal := ruleToken[ruleIndex:open]
		if !strings.HasPrefix(identityToken[identityIndex:], literal) {
			return false
		}
		identityIndex += len(literal)
		close := strings.IndexByte(ruleToken[open:], '>')
		if close < 0 {
			return false
		}
		close += open
		placeholder := ruleToken[open : close+1]
		consumed, ok := consumeEmbeddedPlaceholder(placeholder, identityToken[identityIndex:])
		if !ok {
			return false
		}
		identityIndex += consumed
		ruleIndex = close + 1
	}
	return identityIndex == len(identityToken)
}

func consumeEmbeddedPlaceholder(placeholder string, value string) (int, bool) {
	switch placeholder {
	case "<number>":
		i := 0
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		return i, i > 0
	case "<fields>":
		i := 0
		for i < len(value) {
			c := value[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '-' || c == ',') {
				break
			}
			i++
		}
		return i, i > 0 && looksFieldList(value[:i])
	default:
		return 0, false
	}
}

func isCommandShapePlaceholder(value string) bool {
	return len(value) > 2 && strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">")
}

func (p *Policy) PermissionFamilyResolved(identity string) bool {
	if p == nil {
		return false
	}
	for _, rule := range p.Rules {
		if rule.Kind == "permission-family" && rule.Identity == identity && rule.Status == "resolved" {
			return true
		}
	}
	return false
}

func AppendDryRunEvent(root string, provider string, activation string, result Result) error {
	if root == "" {
		return fmt.Errorf("policy-artifact-root is required for dry-run logging")
	}
	event := Event{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		Provider:      strings.ToLower(strings.TrimSpace(provider)),
		Activation:    activation,
		Decision:      result.Decision,
		Reason:        result.Reason,
		Summary:       sanitizeSummary(result.Summary),
		CommandShape:  sanitizeSummary(result.CommandShape),
		CommandFamily: result.CommandFamily,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal dry-run event: %w", err)
	}
	logPath := filepath.Join(root, DryRunLogFileName)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("create dry-run log directory: %w", err)
	}
	lock := filelock.New(logPath)
	return lock.WithLockOperation("append-bash-policy-dry-run", func() error {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open dry-run log: %w", err)
		}
		defer file.Close()
		if _, err := file.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("append dry-run log: %w", err)
		}
		return nil
	})
}

func ReadEvents(path string) ([]Event, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open dry-run log: %w", err)
	}
	defer file.Close()
	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("parse dry-run event JSONL: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read dry-run log: %w", err)
	}
	return events, nil
}

func ResultsFromEvents(events []Event) []Result {
	results := make([]Result, 0, len(events))
	for _, event := range events {
		results = append(results, Result{
			Decision:      event.Decision,
			Reason:        event.Reason,
			Summary:       event.Summary,
			CommandShape:  event.CommandShape,
			CommandFamily: event.CommandFamily,
		})
	}
	return results
}

func BuildCandidates(provider string, permissions []string, policy *Policy, events []Event, safeRoots ...string) CandidateFile {
	seen := map[string]Candidate{}
	requestedProvider := strings.ToLower(strings.TrimSpace(provider))
	for _, permission := range permissions {
		identity := NormalizePermissionFamily(permission)
		if identity == "" || BuiltInCoversPermissionFamily(identity) || policy.PermissionFamilyResolved(identity) {
			continue
		}
		seen["permission-family:"+identity] = Candidate{
			Kind:     "permission-family",
			Identity: identity,
			Provider: provider,
			Source:   "claude-settings",
			Status:   "unresolved",
		}
	}
	for _, event := range events {
		if requestedProvider != "" && strings.ToLower(strings.TrimSpace(event.Provider)) != requestedProvider {
			continue
		}
		if event.Decision == DecisionAllow {
			continue
		}
		for _, identity := range eventCommandShapeIdentities(event, safeRoots) {
			if identity == "" || BuiltInCoversCommandShape(identity) {
				continue
			}
			if _, ok := policy.CommandRule(identity); ok {
				continue
			}
			key := "command-shape:" + identity
			candidate := seen[key]
			if candidate.Identity == "" {
				candidate = Candidate{
					Kind:     "command-shape",
					Identity: identity,
					Provider: event.Provider,
					Source:   "dry-run",
					Status:   "unresolved",
				}
			}
			candidate.Observations++
			seen[key] = candidate
		}
	}
	candidates := make([]Candidate, 0, len(seen))
	for _, candidate := range seen {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Kind != candidates[j].Kind {
			return candidates[i].Kind < candidates[j].Kind
		}
		return candidates[i].Identity < candidates[j].Identity
	})
	return CandidateFile{Candidates: candidates}
}

func eventCommandShapeIdentities(event Event, safeRoots []string) []string {
	if len(safeRoots) > 0 {
		identities := usableCommandShapeIdentities(commandShapeLeavesForCommand(event.Summary, safeRoots[0], safeRoots))
		if len(identities) > 0 {
			return identities
		}
	}
	identity := strings.TrimSpace(event.CommandShape)
	if !commandShapeIdentityUsable(identity) {
		return nil
	}
	return commandShapeLeafIdentities(identity)
}

func usableCommandShapeIdentities(identities []string) []string {
	out := make([]string, 0, len(identities))
	for _, identity := range identities {
		identity = strings.TrimSpace(identity)
		if commandShapeIdentityUsable(identity) {
			out = append(out, identity)
		}
	}
	return out
}

func commandShapeLeafIdentities(identity string) []string {
	if !commandShapeIdentityUsable(identity) {
		return nil
	}
	tokens, ok := commandShapeTokens(identity)
	if !ok || len(tokens) == 0 {
		return nil
	}
	leaves := []string{}
	current := []string{}
	for _, token := range tokens {
		if !token.quoted && shellOperatorToken(token.value) {
			if len(current) == 0 {
				return nil
			}
			leaves = append(leaves, joinCommandShapeFields(current))
			current = nil
			continue
		}
		current = append(current, token.value)
	}
	if len(current) == 0 {
		return nil
	}
	leaves = append(leaves, joinCommandShapeFields(current))
	return usableCommandShapeIdentities(leaves)
}

func commandShapeIdentityUsable(identity string) bool {
	if strings.TrimSpace(identity) == "" {
		return false
	}
	tokens, ok := commandShapeTokens(identity)
	if !ok {
		return false
	}
	for _, token := range tokens {
		if !token.quoted && strings.Contains(token.value, "...") && !isVariadicCommandShapePlaceholder(token.value) {
			return false
		}
	}
	return true
}

func shellOperatorToken(token string) bool {
	switch token {
	case ";", "&&", "||", "|":
		return true
	default:
		return false
	}
}

func isVariadicCommandShapePlaceholder(value string) bool {
	repeated := strings.TrimSuffix(value, "...")
	return repeated != value && isCommandShapePlaceholder(repeated)
}

func WriteCandidates(path string, candidates CandidateFile) error {
	content, err := yaml.Marshal(candidates)
	if err != nil {
		return fmt.Errorf("marshal bash policy candidates: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create candidates directory: %w", err)
	}
	return os.WriteFile(path, content, 0o644)
}

func NormalizePermissionFamily(permission string) string {
	trimmed := strings.TrimSpace(permission)
	if !strings.HasPrefix(trimmed, "Bash(") || !strings.HasSuffix(trimmed, ")") {
		return ""
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(trimmed, "Bash("), ")")
	if inner == "" {
		return ""
	}
	inner = normalizePermissionFamilyInner(inner)
	if before, _, ok := strings.Cut(inner, ":"); ok {
		return "Bash(" + strings.TrimSpace(before) + ":*)"
	}
	if before, _, ok := strings.Cut(inner, " "); ok {
		return "Bash(" + strings.TrimSpace(before) + ":*)"
	}
	return "Bash(" + strings.TrimSpace(inner) + ":*)"
}

func BuiltInCoversPermissionFamily(identity string) bool {
	normalized := NormalizePermissionFamily(identity)
	switch normalized {
	case "Bash(rg:*)", "Bash(rtk:*)", "Bash(rtk proxy:*)":
		return true
	default:
		return builtInReadOnlyUnixFamily(commandFamily(permissionFamilyInner(normalized)))
	}
}

func normalizePermissionFamilyInner(inner string) string {
	inner = strings.TrimSpace(inner)
	if inner == "rtk" || strings.HasPrefix(inner, "rtk:") {
		return inner
	}
	if !strings.HasPrefix(inner, "rtk ") {
		return inner
	}
	wrapped := strings.TrimSpace(strings.TrimPrefix(inner, "rtk "))
	if commandFamily(wrapped) == "proxy" {
		return "rtk proxy:*"
	}
	return wrapped
}

func BuiltInCoversCommandShape(identity string) bool {
	if commandShapeHasShellOperators(identity) {
		return false
	}
	fields, ok := commandShapeFields(identity)
	if !ok {
		return false
	}
	if len(fields) == 0 {
		return false
	}
	if fields[0] == "rtk" {
		if len(fields) < 2 {
			return false
		}
		if fields[1] == "git" {
			return gitShapeCoveredByBuiltIn(fields[2:])
		}
		if fields[1] == "rg" {
			return rgShapeCoveredByBuiltIn(fields[2:])
		}
		return unixShapeCoveredByBuiltIn(fields[1], fields[2:])
	}
	if fields[0] == "git" {
		return gitShapeCoveredByBuiltIn(fields[1:])
	}
	if fields[0] == "rg" {
		return rgShapeCoveredByBuiltIn(fields[1:])
	}
	return unixShapeCoveredByBuiltIn(fields[0], fields[1:])
}

func commandShapeHasShellOperators(identity string) bool {
	tokens, ok := commandShapeTokens(identity)
	if !ok {
		return false
	}
	for _, token := range tokens {
		if !token.quoted && shellOperatorToken(token.value) {
			return true
		}
	}
	return false
}

func gitShapeCoveredByBuiltIn(args []string) bool {
	for len(args) >= 2 && args[0] == "-C" {
		if !shapePathOperandCovered(args[1]) {
			return false
		}
		args = args[2:]
	}
	if len(args) == 0 {
		return false
	}
	subcommand := args[0]
	rest := args[1:]
	switch subcommand {
	case "status":
		return gitFlagsAndOptionalPathspecsCovered(rest, gitStatusAllowedFlags)
	case "diff":
		return gitFlagsAndOptionalPathspecsCovered(rest, gitDiffAllowedFlags)
	case "rev-parse":
		return onlyAllowedGitArgs(rest, "--show-toplevel", "--show-current", "--git-dir", "--short", "HEAD")
	case "branch":
		return onlyAllowedGitArgs(rest, "--show-current", "--list", "-a", "-r")
	case "log", "show":
		return gitLogShowShapeCovered(rest)
	case "worktree":
		return len(rest) >= 1 && rest[0] == "list" && onlyAllowedGitArgs(rest[1:], "--porcelain")
	default:
		return false
	}
}

func gitFlagsAndOptionalPathspecsCovered(args []string, allowedFlags map[string]bool) bool {
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" {
			afterDashDash = true
			continue
		}
		if afterDashDash {
			if !shapePathOperandCovered(arg) {
				return false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !allowedFlags[arg] {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func gitLogShowShapeCovered(args []string) bool {
	afterDashDash := false
	for _, arg := range args {
		if arg == "--" {
			afterDashDash = true
			continue
		}
		if afterDashDash {
			if !shapePathOperandCovered(arg) {
				return false
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !gitLogShowAllowedFlags[arg] {
				return false
			}
			continue
		}
		if objectPath, ok := gitObjectPathOperand(arg); ok {
			if !gitObjectPathPathSafe(objectPath) {
				return false
			}
			continue
		}
		if shapePathOperandCovered(arg) {
			continue
		}
		if !gitRevisionOperandCovered(arg) {
			return false
		}
	}
	return true
}

func onlyAllowedGitArgs(args []string, allowed ...string) bool {
	allowedSet := stringSet(allowed...)
	for _, arg := range args {
		if !allowedSet[arg] {
			return false
		}
	}
	return true
}

func rgShapeCoveredByBuiltIn(args []string) bool {
	filesMode := false
	patternSeen := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if rgFlagIsForbidden(arg) {
			return false
		}
		if arg == "--" {
			for _, pathArg := range args[i+1:] {
				if pathArg != "<safe-path>" {
					return false
				}
			}
			return filesMode || patternSeen
		}
		if arg == "--files" {
			filesMode = true
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !rgFlagIsAllowed(arg) {
				return false
			}
			if rgFlagNeedsValue(arg) {
				i++
				if i >= len(args) || args[i] == "<redacted>" {
					return false
				}
			}
			continue
		}
		if !filesMode && !patternSeen {
			if arg == "<redacted>" {
				return false
			}
			patternSeen = true
			continue
		}
		if arg != "<safe-path>" {
			return false
		}
	}
	return filesMode || patternSeen
}

func unixShapeCoveredByBuiltIn(command string, args []string) bool {
	if command == "cd" {
		return len(args) == 1 && shapePathOperandCovered(args[0])
	}
	profile, ok := readOnlyUnixProfiles[command]
	if !ok {
		return false
	}
	operands, parseResult := parseReadOnlyUnixArgs(args, profile, append([]string{command}, args...))
	if parseResult.Decision != "" {
		return false
	}
	if len(operands) < profile.minOperands {
		return false
	}
	if profile.maxOperands >= 0 && len(operands) > profile.maxOperands {
		return false
	}
	for _, operand := range operands {
		if profile.dateFormatOperandOnly && !strings.HasPrefix(operand, "+") {
			return false
		}
		if profile.operandsArePaths {
			if !shapePathOperandCovered(operand) {
				return false
			}
			continue
		}
		if !shapePlainOperandCovered(operand, profile) {
			return false
		}
	}
	return true
}

func shapePathOperandCovered(operand string) bool {
	if operand == "<safe-path>" {
		return true
	}
	if isCommandShapePlaceholder(operand) {
		return false
	}
	if operand == "" || operand == "-" || operand == "<redacted>" || LooksSensitive(operand) || unsafePathPattern(operand) {
		return false
	}
	if filepath.IsAbs(operand) || strings.HasPrefix(operand, "~") || operand == ".." ||
		strings.HasPrefix(operand, "../") || strings.Contains(operand, "/../") {
		return false
	}
	return true
}

func shapePlainOperandCovered(operand string, profile readOnlyUnixProfile) bool {
	if operand == "" {
		return false
	}
	if operand == "<safe-path>" {
		return profile.freeFormOperands
	}
	if strings.Contains(operand, "<redacted>") {
		return profile.freeFormOperands && !LooksSensitive(operand)
	}
	if LooksSensitive(operand) {
		return false
	}
	if isCommandShapePlaceholder(operand) {
		return false
	}
	if argLooksPathLike(operand) {
		return shapePathOperandCovered(operand)
	}
	return true
}

func EnsurePolicyArtifactIgnores(root string) error {
	if root == "" {
		return fmt.Errorf("policy-artifact-root is required")
	}
	gitDirOut, err := gitenv.Output(root, "rev-parse", "--git-dir")
	if err != nil {
		return fmt.Errorf("resolve git dir for policy artifacts: %w", err)
	}
	gitDir := strings.TrimSpace(string(gitDirOut))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}
	excludePath := filepath.Join(gitDir, "info", "exclude")
	return appendMissingExcludeEntries(excludePath, []string{
		DryRunLogFileName,
		DryRunLogFileName + ".lock",
		DryRunLogFileName + ".lock.owner.json",
		CandidatesFileName,
	})
}

func appendMissingExcludeEntries(excludePath string, entries []string) error {
	if err := os.MkdirAll(filepath.Dir(excludePath), 0o755); err != nil {
		return fmt.Errorf("create git exclude directory: %w", err)
	}
	content, err := os.ReadFile(excludePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read git exclude: %w", err)
	}
	existing := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		existing[strings.TrimSpace(line)] = true
	}
	next := append([]byte(nil), content...)
	for _, entry := range entries {
		if existing[entry] {
			continue
		}
		if len(next) > 0 && next[len(next)-1] != '\n' {
			next = append(next, '\n')
		}
		next = append(next, entry...)
		next = append(next, '\n')
	}
	return os.WriteFile(excludePath, next, 0o644)
}

func resultIdentity(result Result) string {
	if strings.TrimSpace(result.CommandShape) != "" {
		return result.CommandShape
	}
	return result.Summary
}
