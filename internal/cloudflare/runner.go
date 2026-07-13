package cloudflare

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode"
)

// Runner executes a command. Implementations must use Command.Stdin rather
// than attempting to reconstruct input from the printable command string and
// must attach a real terminal when Command.Interactive reports true. Sensitive
// stdin must never be copied into argv, environment variables, or logs.
type Runner interface {
	Run(context.Context, Command) (RunResult, error)
}

// InteractiveReadiness is an optional Runner capability used to fail before
// any teardown mutation when a later safe Worker deletion needs a terminal.
type InteractiveReadiness interface {
	InteractiveReady() bool
}

// Command is an argv-based process invocation. Its String and GoString methods
// deliberately never render stdin, so logging a Command cannot expose a Worker
// secret supplied through sensitive stdin.
type Command struct {
	Program string
	Args    []string
	Dir     string

	stdin          []byte
	stdinSet       bool
	sensitiveStdin bool
	interactive    bool
	environment    []string
	stdout         io.Writer
	stderr         io.Writer
}

// Stdin returns a new reader for the command input, or nil if no input was set.
func (c Command) Stdin() io.Reader {
	if !c.stdinSet {
		return nil
	}
	return bytes.NewReader(c.stdin)
}

// HasStdin reports whether the command has process input.
func (c Command) HasStdin() bool {
	return c.stdinSet
}

// SensitiveStdin reports whether stdin must be treated as secret material.
func (c Command) SensitiveStdin() bool {
	return c.sensitiveStdin
}

// Interactive reports whether the process must inherit a real terminal. It is
// used only where cf has no safe noninteractive confirmation flag.
func (c Command) Interactive() bool {
	return c.interactive
}

// Environment returns command-specific environment entries. The printable
// command representation intentionally omits them.
func (c Command) Environment() []string {
	return append([]string(nil), c.environment...)
}

// StdoutWriter returns the streaming stdout destination, if any.
func (c Command) StdoutWriter() io.Writer {
	return c.stdout
}

// StderrWriter returns the streaming stderr destination, if any.
func (c Command) StderrWriter() io.Writer {
	return c.stderr
}

// String returns a safe diagnostic representation. It is not intended to be
// re-parsed by a shell.
func (c Command) String() string {
	parts := make([]string, 0, 1+len(c.Args))
	parts = append(parts, quoteDiagnostic(c.Program))
	for _, arg := range c.Args {
		parts = append(parts, quoteDiagnostic(arg))
	}
	line := strings.Join(parts, " ")
	if c.stdinSet {
		if c.sensitiveStdin {
			line += " < [REDACTED_STDIN]"
		} else {
			line += " < [STDIN]"
		}
	}
	if c.interactive {
		line += " [INTERACTIVE]"
	}
	return line
}

// GoString keeps %#v logging redacted as well.
func (c Command) GoString() string {
	return c.String()
}

func quoteDiagnostic(value string) string {
	if value == "" {
		return `""`
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune(`"'\\`, r) {
			return strconv.Quote(value)
		}
	}
	return value
}

func (c Command) withStdin(input []byte, sensitive bool) Command {
	c.stdin = input
	c.stdinSet = true
	c.sensitiveStdin = sensitive
	c.interactive = false
	return c
}

func (c Command) withWriters(stdout, stderr io.Writer) Command {
	c.stdout = stdout
	c.stderr = stderr
	return c
}

func (c Command) withInteractive() Command {
	c.stdin = nil
	c.stdinSet = false
	c.sensitiveStdin = false
	c.interactive = true
	return c
}

func (c Command) withEnvironment(environment ...string) Command {
	c.environment = append([]string(nil), environment...)
	return c
}

// RunResult contains captured process output. When a streaming writer is set
// on Command, the corresponding string is empty to avoid buffering an
// unbounded log tail.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ExecRunner executes commands without a shell and never logs them.
type ExecRunner struct{}

// InteractiveReady reports whether cf can present its safe confirmation UI.
func (ExecRunner) InteractiveReady() bool {
	if ci, present := os.LookupEnv("CI"); present && ci != "" && !strings.EqualFold(ci, "false") && ci != "0" {
		return false
	}
	stdinInfo, stdinErr := os.Stdin.Stat()
	stdoutInfo, stdoutErr := os.Stdout.Stat()
	return stdinErr == nil && stdoutErr == nil &&
		stdinInfo.Mode()&os.ModeCharDevice != 0 && stdoutInfo.Mode()&os.ModeCharDevice != 0
}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, command Command) (RunResult, error) {
	cmd := exec.CommandContext(ctx, command.Program, command.Args...)
	cmd.Dir = command.Dir
	cmd.Env = removeGlobalAPIKeys(overlayEnvironment(os.Environ(), command.Environment()))
	if command.Interactive() {
		if !(ExecRunner{}).InteractiveReady() {
			return RunResult{ExitCode: -1}, ErrInteractiveTerminalRequired
		}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		var stderr bytes.Buffer
		if command.StderrWriter() != nil {
			cmd.Stderr = io.MultiWriter(command.StderrWriter(), &stderr)
		} else {
			cmd.Stderr = io.MultiWriter(os.Stderr, &stderr)
		}
		err := cmd.Run()
		result := RunResult{Stderr: stderr.String()}
		if err == nil {
			return result, nil
		}
		result.ExitCode = -1
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			result.ExitCode = exitError.ExitCode()
		}
		return result, err
	}

	cmd.Stdin = command.Stdin()

	var stdout bytes.Buffer
	if command.StdoutWriter() != nil {
		cmd.Stdout = command.StdoutWriter()
	} else {
		cmd.Stdout = &stdout
	}

	var stderr bytes.Buffer
	if command.StderrWriter() != nil {
		cmd.Stderr = command.StderrWriter()
	} else {
		cmd.Stderr = &stderr
	}

	err := cmd.Run()
	result := RunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}
	if err == nil {
		return result, nil
	}

	result.ExitCode = -1
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
	}
	return result, err
}

func removeGlobalAPIKeys(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "CLOUDFLARE_GLOBAL_TOKEN") || strings.EqualFold(key, "CLOUDFLARE_API_KEY") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func overlayEnvironment(base, overrides []string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, entry := range overrides {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = struct{}{}
	}
	environment := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := keys[key]; !overridden {
			environment = append(environment, entry)
		}
	}
	return append(environment, overrides...)
}
