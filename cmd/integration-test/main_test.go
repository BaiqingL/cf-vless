package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiqingL/cf-vless/internal/config"
)

func TestRunFailsClosedAndEmitsJSONWhenRequiredGatesAreMissing(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)
	if code == 0 {
		t.Fatal("missing live prerequisites reported success")
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v; %q", err, stdout.String())
	}
	if passed, _ := report["passed"].(bool); passed {
		t.Fatal("failure report says passed")
	}
}

func TestHelpAndFailureReportDoNotExposeDeploymentCredential(t *testing.T) {
	var help bytes.Buffer
	_, _ = parseOptions([]string{"-help"}, &help)
	if strings.Contains(help.String(), "-uuid") || strings.Contains(help.String(), "-path") || strings.Contains(help.String(), "CF_VLESS_UUID") || strings.Contains(help.String(), "CF_VLESS_PATH") {
		t.Fatal("help exposes a credential-bearing interface")
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	deploymentPath := filepath.Join(directory, "deployment.json")
	deployment := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Integration",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
			Path: "/integration-path-01",
		}},
	}
	if err := config.SaveNew(deploymentPath, &deployment); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--deployment=" + deploymentPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("missing live probes unexpectedly passed")
	}
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) || strings.Contains(stdout.String(), deployment.Credentials.Current.Path) || strings.Contains(stderr.String(), deployment.Credentials.Current.UUID) || strings.Contains(stderr.String(), deployment.Credentials.Current.Path) {
		t.Fatal("failure output exposed credentials")
	}
}

func TestRunRefusesSiblingPendingCredentialState(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	deploymentPath := filepath.Join(directory, "deployment.json")
	pendingPath := filepath.Join(directory, "deployment.pending.json")
	deployment := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Integration",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b", Path: "/integration-path-01",
		}},
	}
	if err := config.SaveNew(deploymentPath, &deployment); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveNew(pendingPath, &deployment); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-deployment", deploymentPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code = %d, stderr = %s", code, stderr.String())
	}
	var report integrationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Gates) != 1 || report.Gates[0].Error != "credential_operation_pending" {
		t.Fatalf("report = %+v", report)
	}
	for _, secret := range []string{deployment.Credentials.Current.UUID, deployment.Credentials.Current.Path} {
		if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatal("pending-state refusal exposed a credential")
		}
	}
}

func TestExplicitClientSelectionReportsMissingBinaryWithoutSkipping(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	deploymentPath := filepath.Join(directory, "deployment.json")
	deployment := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Integration",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
			Path: "/integration-path-01",
		}},
	}
	if err := config.SaveNew(deploymentPath, &deployment); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"-deployment", deploymentPath,
		"-clients", "sing-box",
		"-sing-box-binary", filepath.Join(directory, "missing-sing-box"),
		"-https-url", "https://probe.example/",
		"-download-url", "https://probe.example/download",
		"-upload-url", "https://probe.example/upload",
		"-tcp-echo", "echo.example:443",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("missing selected client unexpectedly passed")
	}
	var report integrationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Passed || len(report.Clients) != 1 || report.Clients[0].Name != "sing-box" || report.Clients[0].Passed {
		t.Fatalf("report = %+v", report)
	}
	if len(report.Clients[0].Gates) != 1 || report.Clients[0].Gates[0].Error != "client_binary_unavailable" {
		t.Fatalf("client gates = %+v", report.Clients[0].Gates)
	}
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) || strings.Contains(stdout.String(), deployment.Credentials.Current.Path) {
		t.Fatal("multi-client report exposed credentials")
	}
}

func TestInvalidClientSelectionFailsBeforeDeploymentAccess(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{"-deployment", "does-not-exist", "-clients", "unknown"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code = %d", code)
	}
	var report integrationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Gates) != 1 || report.Gates[0].Error != "client_selection_invalid" {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunSurfacesPrivateWorkspaceCleanupFailureWithoutDetails(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	deploymentPath := filepath.Join(directory, "deployment.json")
	deployment := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Integration",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
			Path: "/integration-path-01",
		}},
	}
	if err := config.SaveNew(deploymentPath, &deployment); err != nil {
		t.Fatal(err)
	}

	workspace := filepath.Join(directory, "private-sensitive-workspace")
	cleanupCalled := false
	operations := privateWorkspaceOperations{
		create: func(string, string) (string, error) {
			if err := os.Mkdir(workspace, 0o700); err != nil {
				return "", err
			}
			return workspace, nil
		},
		removeAll: func(path string) error {
			cleanupCalled = true
			if path != workspace {
				t.Fatalf("cleanup path = %q", path)
			}
			return errors.New("sensitive cleanup detail: /secret/client/config.json")
		},
	}

	var stdout, stderr bytes.Buffer
	code := runWithPrivateWorkspaceOperations([]string{
		"-deployment", deploymentPath,
		"-clients", "sing-box",
		"-sing-box-binary", filepath.Join(directory, "missing-sing-box"),
		"-https-url", "https://probe.example/",
		"-download-url", "https://probe.example/download",
		"-upload-url", "https://probe.example/upload",
		"-tcp-echo", "echo.example:443",
	}, &stdout, &stderr, operations)
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !cleanupCalled {
		t.Fatal("private workspace cleanup was not attempted")
	}
	var report integrationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("cleanup failure report says passed")
	}
	if len(report.Gates) != 1 || report.Gates[0].Name != "cleanup" || report.Gates[0].Error != "private_workspace_cleanup_failed" {
		t.Fatalf("global gates = %+v", report.Gates)
	}
	for _, sensitive := range []string{
		workspace,
		"sensitive cleanup detail",
		deployment.Credentials.Current.UUID,
		deployment.Credentials.Current.Path,
	} {
		if strings.Contains(stdout.String(), sensitive) || strings.Contains(stderr.String(), sensitive) {
			t.Fatalf("cleanup failure output exposed sensitive value")
		}
	}
}

type failingOperationLock struct {
	err error
}

func (lock failingOperationLock) Release() error {
	return lock.err
}

func TestRunSurfacesOperationLockReleaseFailureWithoutDetails(t *testing.T) {
	const sensitive = "sensitive lock path /private/operation.lock"
	started := time.Now().UTC()
	inputReport := integrationReport{
		SchemaVersion: 2,
		StartedAt:     started,
		Clients: []clientReport{{
			Name:   "synthetic-passing-client",
			Passed: true,
		}},
	}
	var stdout, stderr bytes.Buffer
	code := finishIntegrationRun(&stdout, &stderr, started, inputReport, nil, failingOperationLock{err: errors.New(sensitive)})
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	var report integrationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Gates) != 1 || report.Gates[0].Name != "operation_lock" || report.Gates[0].Error != "operation_lock_release_failed" {
		t.Fatalf("global gates = %+v", report.Gates)
	}
	if !strings.Contains(stderr.String(), "operation lock cleanup failed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stdout.String(), sensitive) || strings.Contains(stderr.String(), sensitive) {
		t.Fatal("lock release failure exposed sensitive details")
	}
}
