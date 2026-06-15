package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/liza-mas/liza/internal/bashpolicy"
)

func TestBashPolicyEvaluateCLIJSON(t *testing.T) {
	projectRoot := t.TempDir()
	stdout, stderr, err := executeRootCommandWithStdinCapture(
		t,
		projectRoot,
		`{"command":"git status --short"}`,
		"bash-policy", "evaluate", "--safe-root", projectRoot, "--json",
	)
	if err != nil {
		t.Fatalf("bash-policy evaluate failed: %v\nstderr=%s", err, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty for --json diagnostics", stderr)
	}

	var result bashpolicy.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid result JSON: %v\n%s", err, stdout)
	}
	if result.Decision != bashpolicy.DecisionAllow {
		t.Fatalf("decision = %s, want allow; result=%+v", result.Decision, result)
	}
}

func TestOptionalStdinReaderUsesEmptyReaderForTerminalLikeFile(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	data, err := io.ReadAll(optionalStdinReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("optional stdin data = %q, want empty", string(data))
	}
}

func TestOptionalStdinReaderKeepsPipeInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.WriteString(`{"decision":"manual"}`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(optionalStdinReader(reader))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"decision":"manual"}` {
		t.Fatalf("optional stdin data = %q, want pipe content", string(data))
	}
}

func executeRootCommandWithStdinCapture(t *testing.T, projectRoot string, stdin string, args ...string) (string, string, error) {
	t.Helper()

	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	os.Stdin = stdinReader
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	if _, err := stdinWriter.WriteString(stdin); err != nil {
		t.Fatalf("failed to write stdin: %v", err)
	}
	if err := stdinWriter.Close(); err != nil {
		t.Fatalf("failed to close stdin writer: %v", err)
	}

	cmdErr := executeRootCommand(t, projectRoot, args...)

	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("failed to close stderr writer: %v", err)
	}
	var stdout bytes.Buffer
	if _, err := io.Copy(&stdout, stdoutReader); err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}
	var stderr bytes.Buffer
	if _, err := io.Copy(&stderr, stderrReader); err != nil {
		t.Fatalf("failed to read stderr: %v", err)
	}
	if err := stdinReader.Close(); err != nil {
		t.Fatalf("failed to close stdin reader: %v", err)
	}
	if err := stdoutReader.Close(); err != nil {
		t.Fatalf("failed to close stdout reader: %v", err)
	}
	if err := stderrReader.Close(); err != nil {
		t.Fatalf("failed to close stderr reader: %v", err)
	}

	return stdout.String(), stderr.String(), cmdErr
}
