package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BaiqingL/cf-vless/internal/config"
)

type failingOperationLock struct {
	err error
}

func (lock failingOperationLock) Release() error {
	return lock.err
}

func TestRunWritesAllSecretArtifactsWithoutPrintingCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(temp dir) error = %v", err)
	}
	configPath := filepath.Join(dir, "deployment.json")
	outDir := filepath.Join(dir, "clients")
	cfg := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "My Edge",
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{
			Current: config.Credential{UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Path: "/random-path-0001"},
		},
	}
	if err := config.SaveNew(configPath, &cfg); err != nil {
		t.Fatalf("SaveNew() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", configPath, "-out", outDir}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), cfg.Credentials.Current.UUID) || strings.Contains(stderr.String(), cfg.Credentials.Current.UUID) {
		t.Fatal("config-gen printed the UUID")
	}

	for _, name := range []string{"vless.txt", "xray.json", "sing-box.json", "mihomo.yaml", "vless.png"} {
		path := filepath.Join(outDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s) error = %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("mode for %s = %#o, want 0600", name, got)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}
		if name != "vless.png" && !bytes.Contains(data, []byte(cfg.Credentials.Current.UUID)) {
			t.Fatalf("%s does not contain current UUID", name)
		}
	}
}

func TestRunRefusesSiblingPendingCredentialStateWithoutWritingArtifacts(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "deployment.json")
	pendingPath := filepath.Join(dir, "deployment.pending.json")
	outDir := filepath.Join(dir, "clients")
	cfg := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "My Edge",
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Path: "/random-path-0001",
		}},
	}
	if err := config.SaveNew(configPath, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveNew(pendingPath, &cfg); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-config", configPath, "-out", outDir}, &stdout, &stderr); code != 1 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), config.ErrCredentialOperationPending.Error()) {
		t.Fatalf("stderr = %q, want pending-state refusal", stderr.String())
	}
	if _, err := os.Lstat(outDir); !os.IsNotExist(err) {
		t.Fatalf("pending state produced artifacts: %v", err)
	}
}

func TestRunRefusesOverwriteUnlessForced(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(temp dir) error = %v", err)
	}
	configPath := filepath.Join(dir, "deployment.json")
	outDir := filepath.Join(dir, "clients")
	cfg := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "My Edge",
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{
			Current: config.Credential{UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Path: "/random-path-0001"},
		},
	}
	if err := config.SaveNew(configPath, &cfg); err != nil {
		t.Fatalf("SaveNew() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"-config", configPath, "-out", outDir}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("first run() code = %d, stderr = %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Fatalf("second run() code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("second run stderr = %q, want already exists", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(append(args, "-force"), &stdout, &stderr); code != 0 {
		t.Fatalf("forced run() code = %d, stderr = %s", code, stderr.String())
	}
}

func TestRunRequiresConfigFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("run() code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "-config is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunHelpSucceeds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run(-h) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "usage: config-gen") {
		t.Fatalf("help output = %q", stderr.String())
	}
}

func TestRunReportsOperationLockReleaseFailureWithoutDetails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "deployment.json")
	outDir := filepath.Join(dir, "clients")
	cfg := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "My Edge",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Path: "/random-path-0001",
		}},
	}
	if err := config.SaveNew(configPath, &cfg); err != nil {
		t.Fatal(err)
	}

	const sensitive = "sensitive lock path /private/operation.lock"
	var stdout, stderr bytes.Buffer
	code := runWithOperationLock(
		[]string{"-config", configPath, "-out", outDir},
		&stdout,
		&stderr,
		func(string) (operationLock, error) {
			return failingOperationLock{err: errors.New(sensitive)}, nil
		},
	)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "release operation lock failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stdout.String(), sensitive) || strings.Contains(stderr.String(), sensitive) {
		t.Fatal("lock release failure exposed sensitive details")
	}
}
