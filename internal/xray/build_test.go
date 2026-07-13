package xray

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeExecutor struct {
	calls []Command
	run   func(Command) ([]byte, error)
}

func (f *fakeExecutor) Run(_ context.Context, command Command) ([]byte, error) {
	f.calls = append(f.calls, command)
	return f.run(command)
}

func TestBuilderVerifiesPinAndBuildsMain(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "main"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(repo, "go.mod"), filepath.Join(repo, "main", "main.go")} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(t.TempDir(), "xray")
	fake := &fakeExecutor{}
	fake.run = func(command Command) ([]byte, error) {
		switch {
		case command.Name == "git" && slices.Contains(command.Args, "rev-parse"):
			return []byte(PinnedCommit + "\n"), nil
		case command.Name == "git" && slices.Contains(command.Args, "status"):
			return nil, nil
		case command.Name == "go" && len(command.Args) > 0 && command.Args[0] == "version":
			return []byte("go version go1.26.5 test/arch\n"), nil
		case command.Name == "go" && slices.Contains(command.Args, "build"):
			if err := os.WriteFile(output, []byte("binary"), 0o700); err != nil {
				return nil, err
			}
			return nil, nil
		case command.Name == output && slices.Equal(command.Args, []string{"version"}):
			return []byte("Xray 26.7.11 (Xray, Penetrates Everything.)\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}

	result, err := (Builder{RepoDir: repo, OutputPath: output, Executor: fake}).Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Commit != PinnedCommit || result.Tag != PinnedTag || result.Path != output {
		t.Fatalf("result = %+v", result)
	}
	foundBuild := false
	for _, command := range fake.calls {
		if command.Name == "go" && slices.Contains(command.Args, "build") {
			foundBuild = true
			if command.Dir != repo || !slices.Contains(command.Args, "./main") {
				t.Fatalf("build command = %+v", command)
			}
		}
	}
	if !foundBuild {
		t.Fatal("go build was not called")
	}
}

func TestBuilderRejectsWrongCommitBeforeBuild(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "main"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(repo, "go.mod"), filepath.Join(repo, "main", "main.go")} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fake := &fakeExecutor{run: func(command Command) ([]byte, error) {
		if command.Name == "git" && slices.Contains(command.Args, "rev-parse") {
			return []byte(strings.Repeat("0", 40) + "\n"), nil
		}
		return nil, errors.New("must not continue")
	}}
	_, err := (Builder{RepoDir: repo, OutputPath: filepath.Join(t.TempDir(), "xray"), Executor: fake}).Build(context.Background())
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("error = %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("calls = %d", len(fake.calls))
	}
}
