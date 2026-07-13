package clientintegration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maximumVersionLength = 160

var ErrClientExited = errors.New("client exited before requested shutdown")

type Command struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

type Executor interface {
	Run(context.Context, Command) ([]byte, error)
}

type OSExecutor struct{}

func (OSExecutor) Run(ctx context.Context, command Command) ([]byte, error) {
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	process.Dir = command.Dir
	if command.Env != nil {
		process.Env = command.Env
	}
	output, err := process.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("run %s: %w", filepath.Base(command.Name), err)
	}
	return output, nil
}

type Process interface {
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

type ProcessStarter interface {
	Start(context.Context, Command, io.Writer, io.Writer) (Process, error)
}

type OSProcessStarter struct{}

func (OSProcessStarter) Start(ctx context.Context, command Command, stdout, stderr io.Writer) (Process, error) {
	process := exec.CommandContext(ctx, command.Name, command.Args...)
	process.Dir = command.Dir
	if command.Env != nil {
		process.Env = command.Env
	}
	process.Stdout = stdout
	process.Stderr = stderr
	if err := process.Start(); err != nil {
		return nil, err
	}
	return &commandProcess{command: process}, nil
}

type commandProcess struct{ command *exec.Cmd }

func (process *commandProcess) Wait() error { return process.command.Wait() }
func (process *commandProcess) Signal(signal os.Signal) error {
	return process.command.Process.Signal(signal)
}
func (process *commandProcess) Kill() error { return process.command.Process.Kill() }

type Runner struct {
	Executor       Executor
	Starter        ProcessStarter
	StartupTimeout time.Duration
	StopTimeout    time.Duration
}

func (runner Runner) Version(ctx context.Context, specification Spec) (string, error) {
	if err := validateSpec(specification); err != nil {
		return "", err
	}
	executor := runner.Executor
	if executor == nil {
		executor = OSExecutor{}
	}
	output, err := executor.Run(ctx, Command{Name: specification.Binary, Args: specification.VersionArgs})
	if err != nil {
		return "", errors.New("client version command failed")
	}
	version := sanitizeVersion(string(output))
	if version == "" {
		return "", errors.New("client version output is empty")
	}
	return version, nil
}

func sanitizeVersion(output string) string {
	version := strings.Join(strings.Fields(output), " ")
	if len(version) > maximumVersionLength {
		version = version[:maximumVersionLength]
	}
	return version
}

func (runner Runner) Start(ctx context.Context, specification Spec) (*ClientProcess, error) {
	if err := validateSpec(specification); err != nil {
		return nil, err
	}
	executor := runner.Executor
	if executor == nil {
		executor = OSExecutor{}
	}
	if _, err := executor.Run(ctx, Command{Name: specification.Binary, Args: specification.CheckArgs}); err != nil {
		return nil, errors.New("client rejected generated configuration")
	}
	starter := runner.Starter
	if starter == nil {
		starter = OSProcessStarter{}
	}
	process, err := starter.Start(ctx, Command{Name: specification.Binary, Args: specification.RunArgs}, io.Discard, io.Discard)
	if err != nil {
		return nil, errors.New("start client process")
	}
	stopTimeout := runner.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = 5 * time.Second
	}
	client := &ClientProcess{process: process, done: make(chan struct{}), stopTimeout: stopTimeout}
	go func() {
		err := process.Wait()
		client.mutex.Lock()
		client.waitError = err
		client.mutex.Unlock()
		close(client.done)
	}()
	startupTimeout := runner.StartupTimeout
	if startupTimeout <= 0 {
		startupTimeout = 10 * time.Second
	}
	if err := waitForTCP(ctx, specification.SOCKSAddress, startupTimeout, client.done); err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		_ = client.Stop(stopContext)
		return nil, err
	}
	return client, nil
}

type ClientProcess struct {
	process       Process
	done          chan struct{}
	stopTimeout   time.Duration
	mutex         sync.Mutex
	waitError     error
	stopRequested bool
}

func (client *ClientProcess) Stop(ctx context.Context) error {
	if client == nil {
		return nil
	}
	client.mutex.Lock()
	alreadyStopping := client.stopRequested
	if !alreadyStopping {
		select {
		case <-client.done:
			client.mutex.Unlock()
			return ErrClientExited
		default:
			client.stopRequested = true
		}
	}
	client.mutex.Unlock()
	if !alreadyStopping {
		select {
		case <-client.done:
			return ErrClientExited
		default:
		}
		if err := client.process.Signal(os.Interrupt); err != nil {
			_ = client.process.Kill()
		}
	}
	timer := time.NewTimer(client.stopTimeout)
	defer timer.Stop()
	select {
	case <-client.done:
		return nil
	case <-ctx.Done():
		_ = client.process.Kill()
		return ctx.Err()
	case <-timer.C:
		_ = client.process.Kill()
		select {
		case <-client.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func validateSpec(specification Spec) error {
	if !specification.Name.Valid() || specification.Binary == "" || specification.ConfigPath == "" || len(specification.CheckArgs) == 0 || len(specification.RunArgs) == 0 || len(specification.VersionArgs) == 0 {
		return errors.New("client specification is invalid")
	}
	info, err := os.Stat(specification.Binary)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return errors.New("client binary is unavailable")
	}
	info, err = os.Stat(specification.ConfigPath)
	if err != nil || info.IsDir() || info.Mode().Perm() != 0o600 {
		return errors.New("private client configuration is unavailable")
	}
	if _, _, err := net.SplitHostPort(specification.SOCKSAddress); err != nil {
		return errors.New("client SOCKS address is invalid")
	}
	return nil
}

func waitForTCP(ctx context.Context, address string, timeout time.Duration, processDone <-chan struct{}) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("client startup canceled")
		case <-processDone:
			return errors.New("client exited before SOCKS listener became ready")
		case <-deadline.C:
			return errors.New("client SOCKS listener startup timed out")
		case <-ticker.C:
		}
	}
}
