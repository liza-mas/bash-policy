package gitenv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

var defaultTimeout = 30 * time.Second

func Output(dir string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env()
	output, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("git %v timed out after %s", args, defaultTimeout)
	}
	return output, err
}

func env() []string {
	env := os.Environ()
	for i, entry := range env {
		if strings.HasPrefix(entry, "LC_ALL=") {
			env[i] = "LC_ALL=C"
			return env
		}
	}
	return append(env, "LC_ALL=C")
}
