package bashpolicy

func (ev evaluator) evalConfiguredPolicy(argv []string, cwd string) (Result, bool) {
	shape := ev.policyCommandShape(argv, cwd)
	if shape == "" {
		return Result{}, false
	}
	return ev.evalConfiguredCommandShape(shape, argv)
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
