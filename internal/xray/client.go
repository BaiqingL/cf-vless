package xray

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

var ErrClientExited = errors.New("Xray client exited before requested shutdown")

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

type commandProcess struct {
	command *exec.Cmd
}

func (process *commandProcess) Wait() error { return process.command.Wait() }
func (process *commandProcess) Signal(signal os.Signal) error {
	return process.command.Process.Signal(signal)
}
func (process *commandProcess) Kill() error { return process.command.Process.Kill() }

type ClientRunner struct {
	Executor       Executor
	Starter        ProcessStarter
	StartupTimeout time.Duration
	StopTimeout    time.Duration
}

// ClientProcess owns a running, unmodified Xray client. Subprocess output is
// discarded so Xray cannot persist credentials or destinations in this tool.
type ClientProcess struct {
	process       Process
	done          chan struct{}
	stopTimeout   time.Duration
	mutex         sync.Mutex
	waitError     error
	stopRequested bool
}

func (runner ClientRunner) Start(ctx context.Context, binaryPath, configPath, socksAddress string) (*ClientProcess, error) {
	if err := validateRunnableFile(binaryPath); err != nil {
		return nil, errors.New("Xray binary is unavailable")
	}
	if err := validateReadableFile(configPath); err != nil {
		return nil, errors.New("Xray config is unavailable")
	}
	if _, _, err := net.SplitHostPort(socksAddress); err != nil {
		return nil, errors.New("Xray SOCKS address is invalid")
	}
	executor := runner.Executor
	if executor == nil {
		executor = OSExecutor{}
	}
	if _, err := executor.Run(ctx, Command{
		Name: binaryPath,
		Args: []string{"run", "-test", "-format=json", "-c", configPath},
	}); err != nil {
		return nil, errors.New("Xray rejected generated client config")
	}
	starter := runner.Starter
	if starter == nil {
		starter = OSProcessStarter{}
	}
	process, err := starter.Start(ctx, Command{
		Name: binaryPath,
		Args: []string{"run", "-format=json", "-c", configPath},
	}, io.Discard, io.Discard)
	if err != nil {
		return nil, errors.New("start Xray client")
	}
	stopTimeout := runner.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = 5 * time.Second
	}
	client := &ClientProcess{
		process:     process,
		done:        make(chan struct{}),
		stopTimeout: stopTimeout,
	}
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
	if err := waitForTCP(ctx, socksAddress, startupTimeout, client.done); err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		_ = client.Stop(stopContext)
		return nil, err
	}
	return client, nil
}

func (client *ClientProcess) Wait(ctx context.Context) error {
	if client == nil {
		return errors.New("Xray client is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-client.done:
		client.mutex.Lock()
		defer client.mutex.Unlock()
		return client.waitError
	}
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
			return errors.New("Xray startup canceled")
		case <-processDone:
			return errors.New("Xray exited before SOCKS listener became ready")
		case <-deadline.C:
			return errors.New("Xray SOCKS listener startup timed out")
		case <-ticker.C:
		}
	}
}

func validateRunnableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return errors.New("not executable")
	}
	return nil
}

func validateReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return errors.New("not a file")
	}
	return nil
}
