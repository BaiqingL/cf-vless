package xray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	PinnedCommit = "50231eaff98ccc31b5cbd247a721c16e97fe5ec1"
	PinnedTag    = "v26.7.11"
)

var (
	ErrPinMismatch   = errors.New("Xray submodule commit does not match the repository pin")
	ErrDirtyUpstream = errors.New("Xray submodule contains modifications or untracked files")
)

// Command is a subprocess invocation that can be replaced in unit tests.
type Command struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

// Executor runs bounded, noninteractive subprocesses.
type Executor interface {
	Run(context.Context, Command) ([]byte, error)
}

// OSExecutor is the production Executor.
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

// Builder verifies the official submodule pin and builds the unmodified Xray
// main package. OutputPath is replaced atomically by the Go toolchain.
type Builder struct {
	RepoDir    string
	OutputPath string
	GitBinary  string
	GoBinary   string
	Executor   Executor
}

type BuildResult struct {
	Path      string `json:"path"`
	Commit    string `json:"commit"`
	Tag       string `json:"tag"`
	GoVersion string `json:"go_version"`
}

func (builder Builder) Build(ctx context.Context) (BuildResult, error) {
	if err := builder.validateInputs(); err != nil {
		return BuildResult{}, err
	}
	executor := builder.executor()
	gitBinary := builder.GitBinary
	if gitBinary == "" {
		gitBinary = "git"
	}
	goBinary := builder.GoBinary
	if goBinary == "" {
		goBinary = "go"
	}

	commitOutput, err := executor.Run(ctx, Command{
		Name: gitBinary,
		Args: []string{"-C", builder.RepoDir, "rev-parse", "HEAD"},
	})
	if err != nil {
		return BuildResult{}, errors.New("inspect Xray submodule commit")
	}
	commit := strings.TrimSpace(string(commitOutput))
	if commit != PinnedCommit {
		return BuildResult{}, fmt.Errorf("%w", ErrPinMismatch)
	}
	statusOutput, err := executor.Run(ctx, Command{
		Name: gitBinary,
		Args: []string{"-C", builder.RepoDir, "status", "--porcelain"},
	})
	if err != nil {
		return BuildResult{}, errors.New("inspect Xray submodule status")
	}
	if strings.TrimSpace(string(statusOutput)) != "" {
		return BuildResult{}, fmt.Errorf("%w", ErrDirtyUpstream)
	}
	goVersionOutput, err := executor.Run(ctx, Command{Name: goBinary, Args: []string{"version"}, Dir: builder.RepoDir})
	if err != nil {
		return BuildResult{}, errors.New("Go toolchain is unavailable")
	}

	outputPath, err := filepath.Abs(builder.OutputPath)
	if err != nil {
		return BuildResult{}, errors.New("resolve Xray output path")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return BuildResult{}, errors.New("create Xray output directory")
	}
	_, err = executor.Run(ctx, Command{
		Name: goBinary,
		Args: []string{"build", "-trimpath", "-ldflags=-s -w", "-o", outputPath, "./main"},
		Dir:  builder.RepoDir,
		Env:  os.Environ(),
	})
	if err != nil {
		return BuildResult{}, errors.New("build pinned Xray client")
	}
	info, err := os.Stat(outputPath)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return BuildResult{}, errors.New("Xray build did not produce an executable")
	}
	postBuildStatus, err := executor.Run(ctx, Command{
		Name: gitBinary,
		Args: []string{"-C", builder.RepoDir, "status", "--porcelain"},
	})
	if err != nil {
		return BuildResult{}, errors.New("inspect Xray submodule after build")
	}
	if strings.TrimSpace(string(postBuildStatus)) != "" {
		return BuildResult{}, fmt.Errorf("%w", ErrDirtyUpstream)
	}
	if err := ValidateBinary(ctx, executor, outputPath); err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		Path:      outputPath,
		Commit:    commit,
		Tag:       PinnedTag,
		GoVersion: strings.TrimSpace(string(goVersionOutput)),
	}, nil
}

func ValidateBinary(ctx context.Context, executor Executor, binaryPath string) error {
	if executor == nil {
		executor = OSExecutor{}
	}
	output, err := executor.Run(ctx, Command{Name: binaryPath, Args: []string{"version"}})
	if err != nil {
		return errors.New("execute Xray version check")
	}
	want := "Xray " + strings.TrimPrefix(PinnedTag, "v")
	if !strings.Contains(string(output), want) {
		return errors.New("Xray binary version does not match pinned tag")
	}
	return nil
}

func (builder Builder) validateInputs() error {
	if builder.RepoDir == "" || builder.OutputPath == "" {
		return errors.New("Xray source and output paths are required")
	}
	for _, path := range []string{filepath.Join(builder.RepoDir, "go.mod"), filepath.Join(builder.RepoDir, "main", "main.go")} {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return errors.New("Xray submodule is not initialized")
		}
	}
	return nil
}

func (builder Builder) executor() Executor {
	if builder.Executor != nil {
		return builder.Executor
	}
	return OSExecutor{}
}
