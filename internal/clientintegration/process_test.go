package clientintegration

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeExecutor struct {
	calls []Command
	run   func(Command) ([]byte, error)
}

func (executor *fakeExecutor) Run(_ context.Context, command Command) ([]byte, error) {
	executor.calls = append(executor.calls, command)
	return executor.run(command)
}

type fakeStarter struct {
	command Command
	process *fakeProcess
}

func (starter *fakeStarter) Start(_ context.Context, command Command, _, _ io.Writer) (Process, error) {
	starter.command = command
	return starter.process, nil
}

type fakeProcess struct {
	done     chan struct{}
	once     sync.Once
	signaled bool
}

func (process *fakeProcess) Wait() error {
	<-process.done
	return nil
}

func (process *fakeProcess) Signal(os.Signal) error {
	process.signaled = true
	process.once.Do(func() { close(process.done) })
	return nil
}

func (process *fakeProcess) Kill() error {
	process.once.Do(func() { close(process.done) })
	return nil
}

func TestRunnerChecksStartsWaitsAndStopsClient(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	directory := t.TempDir()
	binaryPath := filepath.Join(directory, "client")
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	specification := Spec{
		Name:             SingBox,
		Binary:           binaryPath,
		ConfigPath:       configPath,
		WorkingDirectory: directory,
		SOCKSAddress:     listener.Addr().String(),
		CheckArgs:        []string{"check", "-c", configPath},
		RunArgs:          []string{"run", "-c", configPath},
		VersionArgs:      []string{"version"},
	}
	executor := &fakeExecutor{run: func(command Command) ([]byte, error) {
		return []byte("sing-box version 1.12.0\n"), nil
	}}
	process := &fakeProcess{done: make(chan struct{})}
	starter := &fakeStarter{process: process}
	runner := Runner{Executor: executor, Starter: starter, StartupTimeout: time.Second, StopTimeout: time.Second}
	version, err := runner.Version(context.Background(), specification)
	if err != nil || version != "sing-box version 1.12.0" {
		t.Fatalf("version=%q err=%v", version, err)
	}
	client, err := runner.Start(context.Background(), specification)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(starter.command.Args, specification.RunArgs) {
		t.Fatalf("start args = %q", starter.command.Args)
	}
	if len(executor.calls) != 2 || executor.calls[1].Dir != directory || starter.command.Dir != directory {
		t.Fatalf("client working directories = check:%q run:%q", executor.calls[1].Dir, starter.command.Dir)
	}
	if err := client.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !process.signaled {
		t.Fatal("client process was not signaled")
	}
}

func TestSanitizeVersionBoundsAndFlattensOutput(t *testing.T) {
	t.Parallel()

	input := "  client\nversion\t" + strings.Repeat(" ", 400)
	version := sanitizeVersion(input)
	if len(version) > maximumVersionLength || version != "client version" {
		t.Fatalf("version = %q", version)
	}
}
