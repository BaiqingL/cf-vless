package xray

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// This opt-in test is used by the repository research/upgrade gate. It builds
// the exact gitlink and asks that binary to parse the generated client config;
// it performs no network access beyond Go module downloads needed by the build.
func TestPinnedXrayBuildAcceptsGeneratedClientConfig(t *testing.T) {
	if os.Getenv("CF_VLESS_TEST_PINNED_XRAY") != "1" {
		t.Skip("set CF_VLESS_TEST_PINNED_XRAY=1 to build the pinned submodule")
	}
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	binaryPath := filepath.Join(t.TempDir(), "xray")
	result, err := (Builder{
		RepoDir:    filepath.Join(repositoryRoot, "third_party", "xray-core"),
		OutputPath: binaryPath,
	}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Commit != PinnedCommit {
		t.Fatalf("commit = %q", result.Commit)
	}
	configPath := filepath.Join(t.TempDir(), "client.json")
	config := validClientConfig()
	config.LogLevel = "none"
	config.SOCKSPort, err = ReserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteClientConfig(configPath, config); err != nil {
		t.Fatal(err)
	}
	if _, err := (OSExecutor{}).Run(ctx, Command{
		Name: binaryPath,
		Args: []string{"run", "-test", "-format=json", "-c", configPath},
	}); err != nil {
		t.Fatal(err)
	}
	client, err := (ClientRunner{StartupTimeout: 10 * time.Second}).Start(ctx, binaryPath, configPath, config.SOCKSAddress())
	if err != nil {
		t.Fatal(err)
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := client.Stop(stopContext); err != nil {
		t.Fatal(err)
	}
}
