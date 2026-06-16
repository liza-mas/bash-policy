package bashpolicy

func (ev evaluator) evalRTK(argv []string, cwd string) Result {
	if len(argv) < 2 {
		return result(DecisionManual, "rtk wrapper has no command to evaluate", argv)
	}
	if argv[1] == "proxy" {
		return result(DecisionDeny, "rtk proxy bypass is not safe", argv)
	}
	wrapped := argv[1:]
	wrappedResult := ev.evalArgv(wrapped, cwd)
	wrappedResult.CommandFamily = "rtk"
	if wrappedResult.Summary != "" {
		wrappedResult.Summary = "rtk " + wrappedResult.Summary
	}
	if wrappedResult.Decision == DecisionAllow {
		wrappedResult.Reason = "rtk wrapper around " + wrappedResult.Reason
	}
	return wrappedResult
}
