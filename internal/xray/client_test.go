package xray

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

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

func TestClientRunnerValidatesStartsWaitsAndStops(t *testing.T) {
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
	binaryPath := filepath.Join(directory, "xray")
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(binaryPath, []byte("fake"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{run: func(command Command) ([]byte, error) {
		if command.Name != binaryPath || !slices.Contains(command.Args, "-test") {
			t.Fatalf("config validation command = %+v", command)
		}
		return []byte("Configuration OK.\n"), nil
	}}
	process := &fakeProcess{done: make(chan struct{})}
	starter := &fakeStarter{process: process}
	client, err := (ClientRunner{
		Executor:       executor,
		Starter:        starter,
		StartupTimeout: time.Second,
		StopTimeout:    time.Second,
	}).Start(context.Background(), binaryPath, configPath, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(starter.command.Args, []string{"run", "-format=json", "-c", configPath}) {
		t.Fatalf("start args = %q", starter.command.Args)
	}
	if err := client.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !process.signaled {
		t.Fatal("process was not signaled")
	}
}
