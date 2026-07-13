package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testGlobalAPIKey = "0123456789abcdef0123456789abcdef01234"

func writePrivateDotEnv(t *testing.T, directory, contents string) string {
	t.Helper()
	path := filepath.Join(directory, ".env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadGlobalAPIKeyReadsOnlyPrivateDotEnv(t *testing.T) {
	directory := t.TempDir()
	writePrivateDotEnv(t, directory, "UNRELATED=value\nCLOUDFLARE_GLOBAL_TOKEN='"+testGlobalAPIKey+"'\n")
	key, err := loadGlobalAPIKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
	if !bytes.Equal(key, []byte(testGlobalAPIKey)) {
		t.Fatal("loaded Global API Key does not match the private input")
	}
}

func TestLoadGlobalAPIKeyAllowsAbsentDotEnv(t *testing.T) {
	key, err := loadGlobalAPIKey(t.TempDir())
	if err != nil || key != nil {
		t.Fatalf("loadGlobalAPIKey() = %v, %v", key, err)
	}
}

func TestLoadGlobalAPIKeyRejectsUnsafeFiles(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "permissions",
			setup: func(t *testing.T, directory string) {
				path := writePrivateDotEnv(t, directory, globalAPIKeyVariable+"="+testGlobalAPIKey)
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, directory string) {
				target := filepath.Join(directory, "target")
				if err := os.WriteFile(target, []byte(globalAPIKeyVariable+"="+testGlobalAPIKey), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(directory, ".env")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate",
			setup: func(t *testing.T, directory string) {
				writePrivateDotEnv(t, directory, globalAPIKeyVariable+"="+testGlobalAPIKey+"\n"+globalAPIKeyVariable+"="+testGlobalAPIKey)
			},
		},
		{
			name: "oversize",
			setup: func(t *testing.T, directory string) {
				writePrivateDotEnv(t, directory, strings.Repeat("x", maximumDotEnvSize+1))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			test.setup(t, directory)
			_, err := loadGlobalAPIKey(directory)
			if err == nil {
				t.Fatal("unsafe .env was accepted")
			}
			if strings.Contains(err.Error(), testGlobalAPIKey) {
				t.Fatal("error exposed the Global API Key")
			}
		})
	}
}

func TestNewCloudflareClientRejectsInvalidLoadedKeyWithoutEchoingIt(t *testing.T) {
	const invalidKey = "not-a-global-key"
	deps := testDependencies(&recordingRunner{})
	deps.loadGlobalAPIKey = func(string) ([]byte, error) { return []byte(invalidKey), nil }
	_, err := newCloudflareClient(deps, resolvedPaths{root: t.TempDir(), template: t.TempDir()}, "", false)
	if err == nil || strings.Contains(err.Error(), invalidKey) {
		t.Fatalf("newCloudflareClient error = %v", err)
	}
}

func TestLoadGlobalAPIKeyReadFailureIsSafe(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, ".env")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := loadGlobalAPIKey(directory)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadGlobalAPIKey error = %v", err)
	}
}

func TestLocalCommandEnvironmentStripsGlobalKeys(t *testing.T) {
	const first = "first-secret"
	const second = "second-secret"
	environment := localCommandEnvironment([]string{
		"PATH=/usr/bin",
		globalAPIKeyVariable + "=" + first,
		"Cloudflare_Api_Key=" + second,
		"VISIBLE=yes",
	})
	joined := strings.Join(environment, "\n")
	if strings.Contains(joined, first) || strings.Contains(joined, second) ||
		strings.Contains(joined, globalAPIKeyVariable+"=") || strings.Contains(strings.ToLower(joined), "cloudflare_api_key=") {
		t.Fatal("Global API Key remained in a local child environment")
	}
	if !strings.Contains(joined, "VISIBLE=yes") || !strings.Contains(joined, "PATH=/usr/bin") {
		t.Fatal("unrelated environment was removed")
	}
}
