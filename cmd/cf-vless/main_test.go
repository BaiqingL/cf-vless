package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiqingL/cf-vless/internal/cloudflare"
	"github.com/BaiqingL/cf-vless/internal/config"
)

const (
	testAccountID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testZoneID    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type recordingRunner struct {
	commands                 []cloudflare.Command
	cfVersion                string
	secretStdin              []byte
	workerPresent            bool
	secretPresent            bool
	domainBound              bool
	extraDomainBound         bool
	certificatePackPresent   bool
	failCertificateDelete    bool
	deferCertificateDelete   bool
	certificateDeleteSeen    bool
	certificatePendingPolls  int
	deferCertificateIssuance bool
	certificatePackStatus    string
	dnsConflict              bool
	ownershipMarker          string
}

type replacementDomainRunner struct {
	*recordingRunner
	domainListCalls int
}

type workspaceSnapshot struct {
	wranglerHasDomain   bool
	cloudflareHasDomain bool
}

type workspaceRecordingRunner struct {
	*recordingRunner
	deployments []workspaceSnapshot
}

func (runner *workspaceRecordingRunner) Run(ctx context.Context, command cloudflare.Command) (cloudflare.RunResult, error) {
	if strings.HasPrefix(strings.Join(command.Args, " "), "deploy") {
		wranglerConfig, err := os.ReadFile(filepath.Join(command.Dir, "wrangler.jsonc"))
		if err != nil {
			return cloudflare.RunResult{}, err
		}
		var wrangler struct {
			Routes []struct {
				Pattern      string `json:"pattern"`
				ZoneName     string `json:"zone_name"`
				CustomDomain bool   `json:"custom_domain"`
			} `json:"routes"`
		}
		if err := json.Unmarshal(wranglerConfig, &wrangler); err != nil {
			return cloudflare.RunResult{}, err
		}
		cloudflareConfig, err := os.ReadFile(filepath.Join(command.Dir, "cloudflare.config.ts"))
		if err != nil {
			return cloudflare.RunResult{}, err
		}
		runner.deployments = append(runner.deployments, workspaceSnapshot{
			wranglerHasDomain: len(wrangler.Routes) == 1 &&
				wrangler.Routes[0].Pattern == "edge.example.com" &&
				wrangler.Routes[0].ZoneName == "example.com" &&
				wrangler.Routes[0].CustomDomain,
			cloudflareHasDomain: strings.Contains(string(cloudflareConfig), `domains: ["edge.example.com"]`),
		})
	}
	return runner.recordingRunner.Run(ctx, command)
}

func (runner *replacementDomainRunner) Run(ctx context.Context, command cloudflare.Command) (cloudflare.RunResult, error) {
	result, err := runner.recordingRunner.Run(ctx, command)
	if err != nil || !strings.HasPrefix(strings.Join(command.Args, " "), "workers domains list") {
		return result, err
	}
	runner.domainListCalls++
	if runner.domainListCalls == 2 {
		result.Stdout = `{"result":[{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","cert_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hostname":"edge.example.com","service":"cf-vless","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"}]}`
	}
	return result, nil
}

func (runner *recordingRunner) Run(_ context.Context, command cloudflare.Command) (cloudflare.RunResult, error) {
	runner.commands = append(runner.commands, command)
	joined := strings.Join(command.Args, " ")
	switch {
	case joined == "--version":
		version := runner.cfVersion
		if version == "" {
			version = cloudflare.SupportedCFVersion
		}
		return cloudflare.RunResult{Stdout: "cf version " + version}, nil
	case strings.HasPrefix(joined, "zones list"):
		return cloudflare.RunResult{Stdout: `{"result":[{"id":"` + testZoneID + `","name":"example.com","status":"active","account":{"id":"` + testAccountID + `","name":"Test"}}]}`}, nil
	case joined == "workers scripts list":
		if runner.workerPresent {
			return cloudflare.RunResult{Stdout: `{"result":[{"id":"cf-vless","routes":null,"tail_consumers":null,"logpush":false,"has_assets":false}]}`}, nil
		}
		return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
	case strings.HasPrefix(joined, "workers scripts schedules get"):
		return cloudflare.RunResult{Stdout: `{"schedules":[]}`}, nil
	case strings.HasPrefix(joined, "workers scripts settings get"):
		return cloudflare.RunResult{Stdout: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":{"enabled":false,"head_sampling_rate":0,"logs":{"enabled":false,"head_sampling_rate":0,"invocation_logs":false,"persist":false},"traces":{"enabled":false,"head_sampling_rate":0,"persist":false}}}`}, nil
	case strings.HasPrefix(joined, "workers scripts subdomain get"):
		return cloudflare.RunResult{Stdout: `{"enabled":false,"previews_enabled":false}`}, nil
	case strings.HasPrefix(joined, "workers deployments list"):
		return cloudflare.RunResult{Stdout: `{"result":[{"id":"deployment-1"}]}`}, nil
	case strings.HasPrefix(joined, "workers scripts script-and-version-settings get"):
		return cloudflare.RunResult{Stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + runner.ownershipMarker + `"}]}}`}, nil
	case strings.HasPrefix(joined, "workers domains list"):
		if runner.domainBound {
			if runner.extraDomainBound {
				return cloudflare.RunResult{Stdout: `{"result":[{"id":"cccccccccccccccccccccccccccccccc","cert_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hostname":"edge.example.com","service":"cf-vless","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"},{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","cert_id":"1fdf92c8-64c2-4a3d-b1af-e15304961145","hostname":"other.example.com","service":"cf-vless","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"}]}`}, nil
			}
			return cloudflare.RunResult{Stdout: `{"result":[{"id":"cccccccccccccccccccccccccccccccc","cert_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hostname":"edge.example.com","service":"cf-vless","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"}]}`}, nil
		}
		return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
	case strings.HasPrefix(joined, "ssl certificate-packs list"):
		if runner.certificatePackPresent {
			if runner.certificateDeleteSeen {
				if runner.certificatePendingPolls == 0 {
					runner.certificatePackPresent = false
					return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
				}
				runner.certificatePendingPolls--
				return cloudflare.RunResult{Stdout: `{"result":[{"id":"dddddddddddddddddddddddddddddddd","type":"advanced","status":"pending_deletion","hosts":["edge.example.com"],"certificates":[{"id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hosts":["edge.example.com"]}]}]}`}, nil
			}
			status := runner.certificatePackStatus
			if status == "" {
				status = "active"
			}
			return cloudflare.RunResult{Stdout: `{"result":[{"id":"dddddddddddddddddddddddddddddddd","type":"advanced","status":"` + status + `","hosts":["edge.example.com"],"certificates":[{"id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hosts":["edge.example.com"]}]}]}`}, nil
		}
		return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
	case strings.HasPrefix(joined, "dns records list"):
		if runner.dnsConflict {
			return cloudflare.RunResult{Stdout: `{"result":[{"id":"dns-conflict","type":"CNAME","name":"edge.example.com","content":"other.example.net"}]}`}, nil
		}
		return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
	case strings.HasPrefix(joined, "workers routes list"):
		return cloudflare.RunResult{Stdout: `[]`}, nil
	case strings.HasPrefix(joined, "workers domains update"):
		if !strings.Contains(joined, "--dry-run") {
			runner.domainBound = true
			if !runner.deferCertificateIssuance {
				runner.certificatePackPresent = true
			}
		}
		return cloudflare.RunResult{Stdout: `{"result":{"id":"cccccccccccccccccccccccccccccccc","cert_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","hostname":"edge.example.com","service":"cf-vless","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"}}`}, nil
	case strings.HasPrefix(joined, "workers domains delete"):
		if !strings.Contains(joined, "--dry-run") {
			runner.domainBound = false
		}
		return cloudflare.RunResult{}, nil
	case strings.HasPrefix(joined, "ssl certificate-packs delete"):
		if !strings.Contains(joined, "--dry-run") && runner.failCertificateDelete {
			runner.failCertificateDelete = false
			return cloudflare.RunResult{ExitCode: 1, Stderr: "injected certificate deletion failure"}, errors.New("injected failure")
		}
		if !strings.Contains(joined, "--dry-run") {
			if runner.deferCertificateDelete {
				runner.certificateDeleteSeen = true
			} else {
				runner.certificatePackPresent = false
			}
		}
		return cloudflare.RunResult{}, nil
	case strings.HasPrefix(joined, "workers secrets list"):
		if !runner.secretPresent {
			return cloudflare.RunResult{Stdout: `{"result":[]}`}, nil
		}
		return cloudflare.RunResult{Stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`}, nil
	case strings.Contains(joined, "secret put"), strings.HasPrefix(joined, "workers secrets update"):
		content, err := io.ReadAll(command.Stdin())
		if err != nil {
			return cloudflare.RunResult{ExitCode: 1}, err
		}
		runner.secretStdin = append([]byte(nil), content...)
		runner.secretPresent = true
		return cloudflare.RunResult{}, nil
	case strings.HasPrefix(joined, "workers secrets delete"):
		if !strings.Contains(joined, "--dry-run") {
			runner.secretPresent = false
		}
		return cloudflare.RunResult{}, nil
	case strings.HasPrefix(joined, "workers scripts delete"):
		if !strings.Contains(joined, "--dry-run") {
			runner.workerPresent = false
		}
		return cloudflare.RunResult{}, nil
	case strings.HasPrefix(joined, "deploy"):
		if !strings.Contains(joined, "--dry-run") {
			runner.workerPresent = true
		}
		return cloudflare.RunResult{Stdout: "deployed"}, nil
	default:
		return cloudflare.RunResult{}, errors.New("unexpected command: " + command.String())
	}
}

func testDependencies(runner cloudflare.Runner) dependencies {
	return dependencies{
		cloudflareRunner: runner,
		runLocal: func(_ context.Context, _ string, _ string, _ []string, _, _ io.Writer) error {
			return nil
		},
		now:              func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
		probePublicHTTPS: func(context.Context, string) error { return nil },
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(workingDirectory, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "worker", "package.json")); err != nil {
		t.Fatalf("repository root unavailable: %v", err)
	}
	return root
}

func initializeForTest(t *testing.T, runner *recordingRunner) (string, string, string) {
	t.Helper()
	root := repositoryRoot(t)
	stateDirectory := filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(stateDirectory, "deployment.json")
	args := []string{
		"init",
		"--project-root", root,
		"--config", configPath,
		"--hostname", "edge.example.com",
		"--zone", "example.com",
		"--name", "Personal Edge",
		"--account-id", testAccountID,
		"--zone-id", testZoneID,
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner)); code != 0 {
		t.Fatalf("init code = %d, stderr = %s", code, stderr.String())
	}
	deployment, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	runner.ownershipMarker = deployment.OwnershipMarker
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) || strings.Contains(stdout.String(), deployment.Credentials.Current.Path) {
		t.Fatal("init output exposed generated credentials")
	}
	return root, configPath, stateDirectory
}

func recordManagedDomainForTest(t *testing.T, configPath string) {
	t.Helper()
	deployment, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	deployment.ManagedDomain = &config.ManagedDomain{
		DomainID:             "cccccccccccccccccccccccccccccccc",
		InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
		CertificatePackID:    "dddddddddddddddddddddddddddddddd",
	}
	if err := config.Save(configPath, deployment); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverInterruptedDomainRequiresExplicitOwned40HexIdentity(t *testing.T) {
	deployment, err := config.New(config.InitOptions{
		WorkerName: "cf-vless", AccountID: testAccountID, ZoneID: testZoneID,
		ZoneName: "example.com", Hostname: "edge.example.com", DisplayName: "Personal Edge",
	})
	if err != nil {
		t.Fatal(err)
	}
	const domainID = "cccccccccccccccccccccccccccccccccccccccc"
	status := cloudflare.WorkerStatus{
		Name:            deployment.WorkerName,
		Exists:          true,
		OwnershipMarker: deployment.OwnershipMarker,
		Domains: []cloudflare.DomainBinding{{
			ID: domainID, CertID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
			Hostname: deployment.Hostname, Service: deployment.WorkerName, Environment: "production",
			ZoneID: deployment.ZoneID, ZoneName: deployment.ZoneName,
		}},
		Secrets: []cloudflare.SecretBinding{{Name: config.WorkerSecretName, Type: "secret_text"}},
	}
	managed, err := recoverInterruptedDomain(status, deployment, domainID)
	if err != nil {
		t.Fatal(err)
	}
	if managed.DomainID != domainID || managed.InitialCertificateID != "9fdf92c8-64c2-4a3d-b1af-e15304961145" {
		t.Fatalf("managed domain = %#v", managed)
	}
	if _, err := recoverInterruptedDomain(status, deployment, strings.Repeat("d", 40)); err == nil {
		t.Fatal("recovery accepted a different explicit Domain ID")
	}
	status.Secrets = nil
	if _, err := recoverInterruptedDomain(status, deployment, domainID); err == nil {
		t.Fatal("recovery accepted a Worker without the managed secret")
	}
}

func TestHelpListsTheRequiredCommandSurface(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &stdout, &stderr, testDependencies(&recordingRunner{})); code != 0 {
		t.Fatalf("help code = %d", code)
	}
	for _, command := range []string{"doctor", "init", "deploy", "status", "test", "config", "rotate", "logs", "remove"} {
		if !strings.Contains(stdout.String(), command) {
			t.Fatalf("help omitted %s: %q", command, stdout.String())
		}
	}
	for _, expected := range []string{
		"doctor   verify local tools and Cloudflare access",
		"deploy   preflight or publish the managed Worker",
		"test     run executable-client integration gates",
		"exit status: 0 success; 1 operational failure; 2 invalid usage",
		"cf-vless <command> --help",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("help omitted %q: %q", expected, stdout.String())
		}
	}
}

func TestDoctorRequiresZoneAndHostnameBeforeInitialization(t *testing.T) {
	runner := &recordingRunner{}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"doctor",
		"--project-root", repositoryRoot(t),
		"--config", filepath.Join(t.TempDir(), "deployment.json"),
	}, &stdout, &stderr, testDependencies(runner))
	if code != 2 || !strings.Contains(stderr.String(), "requires --zone and --hostname before init") {
		t.Fatalf("doctor code/output = %d / %q", code, stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("doctor reached Cloudflare before validating its target: %#v", runner.commands)
	}
}

func TestLocalDoctorIncludesSecurityScannerDependency(t *testing.T) {
	foundScanner := false
	foundSupportedGo := false
	foundSupportedNode := false
	foundSupportedNPM := false
	for _, check := range localDoctorChecks() {
		if check.name == "rg" && check.program == "rg" {
			foundScanner = true
		}
		if check.name == "go" && check.minimum == "1.26" {
			foundSupportedGo = true
		}
		if check.name == "node" && check.minimum == "22.18" && check.unsupportedMajor == 23 {
			foundSupportedNode = true
		}
		if check.name == "npm" && check.minimum == "11.0" {
			foundSupportedNPM = true
		}
	}
	if !foundScanner {
		t.Fatal("doctor does not require rg for test/security/no-secrets.sh")
	}
	if !foundSupportedGo {
		t.Fatal("doctor does not enforce the supported Go release floor")
	}
	if !foundSupportedNode {
		t.Fatal("doctor does not enforce the supported Node release range")
	}
	if !foundSupportedNPM {
		t.Fatal("doctor does not enforce the npm version required by the install-script allowlist")
	}
}

func TestLocalVersionSupportedRejectsExcludedMajor(t *testing.T) {
	tests := []struct {
		output           string
		minimum          string
		unsupportedMajor int
		want             bool
	}{
		{output: "v22.18.0", minimum: "22.18", unsupportedMajor: 23, want: true},
		{output: "v22.17.9", minimum: "22.18", unsupportedMajor: 23, want: false},
		{output: "v23.11.1", minimum: "22.18", unsupportedMajor: 23, want: false},
		{output: "v24.0.0", minimum: "22.18", unsupportedMajor: 23, want: true},
	}
	for _, test := range tests {
		if got := localVersionSupported(test.output, test.minimum, test.unsupportedMajor); got != test.want {
			t.Errorf("localVersionSupported(%q, %q, %d) = %t, want %t", test.output, test.minimum, test.unsupportedMajor, got, test.want)
		}
	}
}

func TestInitCreatesPrivateStateAndGeneratedWorkerWithoutPrintingSecrets(t *testing.T) {
	runner := &recordingRunner{}
	_, configPath, stateDirectory := initializeForTest(t, runner)
	for _, path := range []string{configPath, filepath.Join(stateDirectory, "worker", "wrangler.jsonc"), filepath.Join(stateDirectory, "worker", "src", "index.ts")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode for %s = %#o, want 0600", path, info.Mode().Perm())
		}
	}
	workspaceInfo, err := os.Stat(filepath.Join(stateDirectory, "worker"))
	if err != nil {
		t.Fatalf("workspace stat error = %v", err)
	}
	if workspaceInfo.Mode().Perm() != 0o700 {
		t.Fatalf("workspace mode = %#o, want 0700", workspaceInfo.Mode().Perm())
	}
	if len(runner.commands) != 6 || !strings.HasPrefix(strings.Join(runner.commands[0].Args, " "), "zones list") ||
		strings.Join(runner.commands[1].Args, " ") != "workers scripts list" ||
		!strings.HasPrefix(strings.Join(runner.commands[2].Args, " "), "ssl certificate-packs list") ||
		!strings.HasPrefix(strings.Join(runner.commands[3].Args, " "), "workers domains list") ||
		!strings.HasPrefix(strings.Join(runner.commands[4].Args, " "), "dns records list") ||
		!strings.HasPrefix(strings.Join(runner.commands[5].Args, " "), "workers routes list") {
		t.Fatalf("init commands = %#v", runner.commands)
	}
}

func TestInitRefusesExistingSameNamedWorkerBeforeWritingState(t *testing.T) {
	runner := &recordingRunner{workerPresent: true}
	root := repositoryRoot(t)
	configPath := filepath.Join(t.TempDir(), "state", "deployment.json")
	args := []string{
		"init", "--project-root", root, "--config", configPath,
		"--hostname", "edge.example.com", "--zone", "example.com", "--name", "Personal Edge",
		"--account-id", testAccountID, "--zone-id", testZoneID,
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner)); code == 0 {
		t.Fatalf("init unexpectedly accepted an existing Worker: %s", stdout.String())
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init wrote local state before rejecting the Worker: %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if joined == "deploy" || strings.HasPrefix(joined, "deploy ") ||
			strings.HasPrefix(joined, "workers domains update") ||
			strings.HasPrefix(joined, "workers secrets update") ||
			strings.HasPrefix(joined, "workers scripts delete") {
			t.Fatalf("init attempted mutation %q", joined)
		}
	}
}

func TestInitRefusesPreexistingExactAdvancedCertificateBeforeWritingState(t *testing.T) {
	runner := &recordingRunner{certificatePackPresent: true}
	root := repositoryRoot(t)
	configPath := filepath.Join(t.TempDir(), "state", "deployment.json")
	args := []string{
		"init", "--project-root", root, "--config", configPath,
		"--hostname", "edge.example.com", "--zone", "example.com", "--name", "Personal Edge",
		"--account-id", testAccountID, "--zone-id", testZoneID,
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner)); code == 0 ||
		!strings.Contains(stderr.String(), "Advanced Certificate") {
		t.Fatalf("init code/output = %d / %q", code, stderr.String())
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init wrote local state before rejecting the certificate conflict: %v", err)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if strings.Contains(joined, " update") || strings.Contains(joined, " delete") || strings.HasPrefix(joined, "deploy") {
			t.Fatalf("init attempted mutation %q", joined)
		}
	}
}

func TestConfigWritesFivePrivateArtifactsAndNeverPrintsUUID(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, runner)
	outputDirectory := filepath.Join(stateDirectory, "clients")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"config", "--project-root", root, "--config", configPath, "--output", outputDirectory,
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("config code = %d, stderr = %s", code, stderr.String())
	}
	deployment, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) || strings.Contains(stderr.String(), deployment.Credentials.Current.UUID) {
		t.Fatal("config output exposed UUID")
	}
	for _, name := range []string{"vless.txt", "vless.png", "xray.json", "sing-box.json", "mihomo.yaml"} {
		info, err := os.Stat(filepath.Join(outputDirectory, name))
		if err != nil {
			t.Fatalf("artifact %s stat error = %v", name, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact %s mode = %#o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestCredentialConsumersRefusePendingRotationBeforeProducingOutput(t *testing.T) {
	for _, command := range []string{"config", "test"} {
		t.Run(command, func(t *testing.T) {
			runner := &recordingRunner{}
			root, configPath, stateDirectory := initializeForTest(t, runner)
			deployment, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := config.SaveNew(filepath.Join(stateDirectory, "deployment.pending.json"), deployment); err != nil {
				t.Fatal(err)
			}
			localRuns := 0
			deps := testDependencies(runner)
			deps.runLocal = func(_ context.Context, _ string, _ string, _ []string, _, _ io.Writer) error {
				localRuns++
				return nil
			}
			args := []string{command, "--project-root", root, "--config", configPath}
			outputDirectory := filepath.Join(stateDirectory, "clients")
			if command == "config" {
				args = append(args, "--output", outputDirectory)
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, deps); code != 1 {
				t.Fatalf("%s code = %d, stderr = %s", command, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), config.ErrCredentialOperationPending.Error()) {
				t.Fatalf("%s stderr = %q, want pending-state refusal", command, stderr.String())
			}
			if localRuns != 0 {
				t.Fatalf("%s launched a credential consumer while rotation was pending", command)
			}
			if _, err := os.Lstat(outputDirectory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s produced credential output: %v", command, err)
			}
		})
	}
}

func TestRotateUsesSensitiveStdinAndPromotesPendingState(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, runner)
	runner.workerPresent = true
	before, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"rotate", "--project-root", root, "--config", configPath, "--overlap", "2h",
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("rotate code = %d, stderr = %s", code, stderr.String())
	}
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Credentials.Previous == nil || after.Credentials.Previous.UUID != before.Credentials.Current.UUID || after.Credentials.Current.UUID == before.Credentials.Current.UUID {
		t.Fatalf("rotation state = %#v", after.Credentials)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, "deployment.pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state remains after success: %v", err)
	}
	if len(runner.secretStdin) == 0 || !bytes.HasSuffix(runner.secretStdin, []byte("\n")) {
		t.Fatal("rotation did not provide protected secret stdin")
	}
	for _, command := range runner.commands {
		if strings.Contains(command.String(), before.Credentials.Current.UUID) || strings.Contains(command.String(), after.Credentials.Current.UUID) {
			t.Fatal("printable command exposed credential")
		}
	}
	for _, output := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(output, before.Credentials.Current.UUID) || strings.Contains(output, after.Credentials.Current.UUID) {
			t.Fatal("rotation output exposed credential")
		}
	}
}

func TestRotateRefusesWhileAnotherCredentialOperationHoldsTheLock(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, runner)
	runner.workerPresent = true
	operationLock, err := config.AcquireOperationLock(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer operationLock.Release()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"rotate", "--project-root", root, "--config", configPath,
	}, &stdout, &stderr, testDependencies(runner))
	if code == 0 || !strings.Contains(stderr.String(), config.ErrOperationInProgress.Error()) {
		t.Fatalf("rotate code/output = %d / %q", code, stderr.String())
	}
}

func TestEmergencyRotateRevokesWithoutOverlap(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	runner.workerPresent = true
	before, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"rotate", "--project-root", root, "--config", configPath, "--emergency-revoke",
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("emergency rotate code = %d, stderr = %s", code, stderr.String())
	}
	after, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if after.Credentials.Previous != nil || after.Credentials.Current == before.Credentials.Current {
		t.Fatalf("emergency credentials = %#v", after.Credentials)
	}
	if !strings.Contains(stdout.String(), "revoked immediately") {
		t.Fatalf("emergency output = %q", stdout.String())
	}
}

func TestPendingRotationMustPreserveEveryNoncredentialField(t *testing.T) {
	current, err := config.New(config.InitOptions{
		WorkerName: "cf-vless", AccountID: testAccountID, ZoneID: testZoneID,
		ZoneName: "example.com", Hostname: "edge.example.com", DisplayName: "Edge",
	})
	if err != nil {
		t.Fatal(err)
	}
	pending := current
	if err := pending.RotateCredential(time.Now().UTC(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if !validPendingRotation(current, pending) {
		t.Fatal("valid pending rotation was rejected")
	}
	pending.AllowedPorts = []uint16{443}
	if validPendingRotation(current, pending) {
		t.Fatal("pending rotation changed destination policy")
	}
	pending = current
	if err := pending.RotateCredential(time.Now().UTC(), time.Hour); err != nil {
		t.Fatal(err)
	}
	pending.DisplayName = "Changed"
	if validPendingRotation(current, pending) {
		t.Fatal("pending rotation changed display metadata")
	}
	current.ManagedDomain = &config.ManagedDomain{
		DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
		CertificatePackID: "dddddddddddddddddddddddddddddddd",
	}
	pending = current
	if err := pending.RotateCredential(time.Now().UTC(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if !validPendingRotation(current, pending) {
		t.Fatal("pending rotation did not preserve managed resource provenance")
	}
	pending.ManagedDomain = &config.ManagedDomain{
		DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
		CertificatePackID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
	}
	if validPendingRotation(current, pending) {
		t.Fatal("pending rotation changed managed certificate-pack provenance")
	}
}

func TestDeployDryRunDoesNotSetSecretOrBindDomain(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	runner.commands = nil
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath, "--dry-run",
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("deploy dry-run code = %d, stderr = %s", code, stderr.String())
	}
	if len(runner.commands) != 7 || strings.Join(runner.commands[0].Args, " ") != "--version" ||
		strings.Join(runner.commands[1].Args, " ") != "workers scripts list" ||
		!strings.HasPrefix(strings.Join(runner.commands[2].Args, " "), "ssl certificate-packs list") ||
		!strings.HasPrefix(strings.Join(runner.commands[3].Args, " "), "workers domains list") ||
		!strings.HasPrefix(strings.Join(runner.commands[4].Args, " "), "dns records list") ||
		!strings.HasPrefix(strings.Join(runner.commands[5].Args, " "), "workers routes list") ||
		!strings.Contains(strings.Join(runner.commands[6].Args, " "), "--dry-run") {
		t.Fatalf("dry-run commands = %#v", runner.commands)
	}
	if len(runner.secretStdin) != 0 {
		t.Fatal("dry-run supplied a secret")
	}
}

func TestMutatingCommandsRejectUnsupportedCFVersionBeforeAnyPlanningOrMutation(t *testing.T) {
	for _, command := range []string{"deploy", "rotate", "remove"} {
		t.Run(command, func(t *testing.T) {
			runner := &recordingRunner{cfVersion: "0.3.0"}
			root, configPath, stateDirectory := initializeForTest(t, runner)
			if command == "remove" {
				recordManagedDomainForTest(t, configPath)
			}
			runner.commands = nil
			localRuns := 0
			deps := testDependencies(runner)
			deps.runLocal = func(_ context.Context, _ string, _ string, _ []string, _, _ io.Writer) error {
				localRuns++
				return nil
			}
			args := []string{command, "--project-root", root, "--config", configPath}
			if command == "remove" {
				args = append(args, "--yes")
			}
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, deps); code != 1 {
				t.Fatalf("%s code = %d, stderr = %s", command, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "does not match required version "+cloudflare.SupportedCFVersion) {
				t.Fatalf("%s stderr = %q", command, stderr.String())
			}
			if len(runner.commands) != 1 || strings.Join(runner.commands[0].Args, " ") != "--version" {
				t.Fatalf("%s reached provider planning or mutation: %#v", command, runner.commands)
			}
			if localRuns != 0 {
				t.Fatalf("%s ran local build preparation before version preflight", command)
			}
			for _, pending := range []string{"deployment.pending.json", "removal.pending.json"} {
				if _, err := os.Lstat(filepath.Join(stateDirectory, pending)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s created %s before version preflight: %v", command, pending, err)
				}
			}
		})
	}
}

func TestRotateReconcilesCompletedPendingStateWithoutStartingAnotherOperation(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "normal", args: nil},
		{name: "emergency", args: []string{"--emergency-revoke"}},
		{name: "finalize", args: []string{"--finalize"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingRunner{}
			root, configPath, stateDirectory := initializeForTest(t, runner)
			deployment, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			pendingPath := filepath.Join(stateDirectory, "deployment.pending.json")
			if err := config.SaveNew(pendingPath, deployment); err != nil {
				t.Fatal(err)
			}
			runner.commands = nil
			args := []string{"rotate", "--project-root", root, "--config", configPath}
			args = append(args, test.args...)
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner)); code != 0 {
				t.Fatalf("rotate code = %d, stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "no new rotation performed") {
				t.Fatalf("stdout = %q", stdout.String())
			}
			if len(runner.commands) != 1 || strings.Join(runner.commands[0].Args, " ") != "--version" {
				t.Fatalf("reconciliation reached the Worker secret: %#v", runner.commands)
			}
			if _, err := os.Lstat(pendingPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed pending marker remains: %v", err)
			}
			after, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !sameCredentialSet(after.Credentials, deployment.Credentials) {
				t.Fatal("reconciliation changed canonical credentials")
			}
		})
	}
}

func TestDeployRechecksHostnameAndStopsBeforeCloudflareMutation(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	runner.commands = nil
	runner.dnsConflict = true
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath,
	}, &stdout, &stderr, testDependencies(runner))
	if code == 0 || !strings.Contains(stderr.String(), "hostname became unavailable") {
		t.Fatalf("deploy code/output = %d / %q", code, stderr.String())
	}
	if len(runner.commands) != 6 || strings.Join(runner.commands[0].Args, " ") != "--version" {
		t.Fatalf("deploy hostname-race commands = %#v", runner.commands)
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if strings.HasPrefix(joined, "deploy") || strings.Contains(joined, " update") || strings.Contains(joined, " delete") {
			t.Fatalf("deploy mutated Cloudflare after hostname conflict: %s", joined)
		}
	}
}

func TestDeployBootstrapsMissingSecretAtomicallyBeforeBindingDomain(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	runner.commands = nil
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath,
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("deploy code = %d, stderr = %s", code, stderr.String())
	}
	deployment, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if deployment.ManagedDomain == nil || deployment.ManagedDomain.DomainID != "cccccccccccccccccccccccccccccccc" ||
		deployment.ManagedDomain.InitialCertificateID != "9fdf92c8-64c2-4a3d-b1af-e15304961145" ||
		deployment.ManagedDomain.CertificatePackID != "dddddddddddddddddddddddddddddddd" {
		t.Fatalf("deploy did not persist exact Custom Domain provenance: %#v", deployment.ManagedDomain)
	}
	var bootstrapPreflight, bootstrapDeploy, secretIndex, protectedDeploy, domainIndex = -1, -1, -1, -1, -1
	var domainPublicationPreflight, domainPublicationDeploy = -1, -1
	for index, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if strings.HasPrefix(joined, "deploy") && strings.Contains(joined, "--dry-run") && bootstrapPreflight < 0 {
			bootstrapPreflight = index
		}
		if strings.HasPrefix(joined, "deploy") && strings.Contains(joined, "unroutable bootstrap") {
			bootstrapDeploy = index
			for _, argument := range command.Args {
				if strings.Contains(argument, deployment.Credentials.Current.UUID) || strings.Contains(argument, deployment.Credentials.Current.Path) {
					t.Fatal("bootstrap argv exposed deployment credential")
				}
			}
		}
		if strings.HasPrefix(joined, "workers secrets update") {
			secretIndex = index
		}
		if strings.HasPrefix(joined, "deploy") && strings.Contains(joined, "protected deployment") && !strings.Contains(joined, "preflight") {
			protectedDeploy = index
		}
		if strings.HasPrefix(joined, "workers domains update") && !strings.Contains(joined, "--dry-run") {
			domainIndex = index
		}
		if strings.HasPrefix(joined, "deploy") && strings.Contains(joined, "managed-domain publication preflight") {
			domainPublicationPreflight = index
		}
		if strings.HasPrefix(joined, "deploy") && strings.Contains(joined, "managed-domain publication") &&
			!strings.Contains(joined, "preflight") {
			domainPublicationDeploy = index
		}
	}
	if bootstrapPreflight < 0 || bootstrapDeploy <= bootstrapPreflight || secretIndex <= bootstrapDeploy ||
		protectedDeploy <= secretIndex || domainIndex <= protectedDeploy ||
		domainPublicationPreflight <= domainIndex || domainPublicationDeploy <= domainPublicationPreflight {
		t.Fatalf("unsafe bootstrap order: preflight=%d bootstrap=%d secret=%d protected=%d domain=%d domain_preflight=%d domain_deploy=%d commands=%#v",
			bootstrapPreflight, bootstrapDeploy, secretIndex, protectedDeploy, domainIndex,
			domainPublicationPreflight, domainPublicationDeploy, runner.commands)
	}
	generated, err := os.ReadFile(filepath.Join(filepath.Dir(configPath), "worker", "wrangler.jsonc"))
	if err != nil {
		t.Fatal(err)
	}
	var wrangler struct {
		Routes []struct {
			Pattern      string `json:"pattern"`
			ZoneName     string `json:"zone_name"`
			CustomDomain bool   `json:"custom_domain"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(generated, &wrangler); err != nil {
		t.Fatal(err)
	}
	if len(wrangler.Routes) != 1 || wrangler.Routes[0].Pattern != deployment.Hostname ||
		wrangler.Routes[0].ZoneName != deployment.ZoneName || !wrangler.Routes[0].CustomDomain {
		t.Fatalf("final protected workspace omitted its managed Custom Domain: %#v", wrangler.Routes)
	}
	for _, command := range runner.commands {
		if strings.Contains(strings.Join(command.Args, " "), "wrangler deploy") {
			t.Fatal("bootstrap unexpectedly bypassed cf deploy")
		}
	}
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) || strings.Contains(stderr.String(), deployment.Credentials.Current.UUID) {
		t.Fatal("deploy output exposed credential")
	}
}

func TestDeployRegeneratesProtectedWorkspaceAfterInterruptedResourceRecovery(t *testing.T) {
	base := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, base)
	base.commands = nil
	base.workerPresent = true
	base.secretPresent = true
	base.domainBound = true
	base.certificatePackPresent = true
	runner := &workspaceRecordingRunner{recordingRunner: base}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath,
		"--recover-domain-id", "cccccccccccccccccccccccccccccccc",
		"--recover-certificate-pack-id", "dddddddddddddddddddddddddddddddd",
	}, &stdout, &stderr, testDependencies(runner))
	if code != 0 {
		t.Fatalf("recovery deploy code = %d, stderr = %s", code, stderr.String())
	}
	if len(runner.deployments) == 0 {
		t.Fatal("recovery did not reach a deployment preflight")
	}
	for index, snapshot := range runner.deployments {
		if !snapshot.wranglerHasDomain || !snapshot.cloudflareHasDomain {
			t.Fatalf("recovery deployment %d used pre-recovery workspace: %#v", index, snapshot)
		}
	}
}

func TestDeployRefusesSuccessWhenPublicHTTPSIsNotReady(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	deployment, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	deps := testDependencies(runner)
	probeCalls := 0
	deps.probePublicHTTPS = func(_ context.Context, hostname string) error {
		probeCalls++
		if hostname != deployment.Hostname {
			t.Fatalf("readiness hostname = %q", hostname)
		}
		return errors.New("public HTTPS endpoint is not ready (HTTP 522)")
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath,
	}, &stdout, &stderr, deps)
	if code == 0 || probeCalls != 1 {
		t.Fatalf("deploy code/probe calls = %d/%d", code, probeCalls)
	}
	if !strings.Contains(stderr.String(), "public HTTPS readiness verification failed") ||
		!strings.Contains(stderr.String(), "HTTP 522") {
		t.Fatalf("readiness failure missing from stderr: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), deployment.Credentials.Current.UUID) ||
		strings.Contains(stderr.String(), deployment.Credentials.Current.UUID) ||
		strings.Contains(stdout.String(), deployment.Credentials.Current.Path) ||
		strings.Contains(stderr.String(), deployment.Credentials.Current.Path) {
		t.Fatal("readiness failure exposed deployment credentials")
	}
	if strings.Contains(stdout.String(), "deployed Worker") {
		t.Fatalf("failed readiness was reported as deployed: %q", stdout.String())
	}
}

func TestStatusReportsPublicHTTPSReadiness(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	var deployOut, deployErr bytes.Buffer
	if code := run(context.Background(), []string{
		"deploy", "--project-root", root, "--config", configPath,
	}, &deployOut, &deployErr, testDependencies(runner)); code != 0 {
		t.Fatalf("deploy code = %d, stderr = %s", code, deployErr.String())
	}

	deps := testDependencies(runner)
	deps.probePublicHTTPS = func(context.Context, string) error {
		return errors.New("public HTTPS endpoint is not ready (HTTP 522)")
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"status", "--project-root", root, "--config", configPath,
	}, &stdout, &stderr, deps)
	if code == 0 {
		t.Fatal("status accepted an unready public endpoint")
	}
	if !strings.Contains(stdout.String(), "certificate_proven=true endpoint_ready=false") {
		t.Fatalf("status output = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "public HTTPS readiness verification failed") {
		t.Fatalf("status stderr = %q", stderr.String())
	}
}

func TestDeployPersistsPartialProvenanceAndResumesIssuanceWithoutRebinding(t *testing.T) {
	runner := &recordingRunner{deferCertificateIssuance: true}
	root, configPath, _ := initializeForTest(t, runner)
	runner.commands = nil
	args := []string{"deploy", "--project-root", root, "--config", configPath}
	var firstOut, firstErr bytes.Buffer
	if code := run(context.Background(), args, &firstOut, &firstErr, testDependencies(runner)); code == 0 ||
		!strings.Contains(firstErr.String(), "still pending") {
		t.Fatalf("pending issuance code/output = %d / %q", code, firstErr.String())
	}
	partial, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if partial.ManagedDomain == nil || partial.ManagedDomain.DomainID == "" || partial.ManagedDomain.InitialCertificateID == "" ||
		partial.ManagedDomain.CertificatePackID != "" {
		t.Fatalf("partial provenance = %#v", partial.ManagedDomain)
	}

	runner.deferCertificateIssuance = false
	runner.certificatePackPresent = true
	runner.commands = nil
	var retryOut, retryErr bytes.Buffer
	if code := run(context.Background(), args, &retryOut, &retryErr, testDependencies(runner)); code != 0 {
		t.Fatalf("issuance resume code = %d, stderr = %s", code, retryErr.String())
	}
	complete, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if complete.ManagedDomain == nil || complete.ManagedDomain.CertificatePackID != "dddddddddddddddddddddddddddddddd" {
		t.Fatalf("completed provenance = %#v", complete.ManagedDomain)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(strings.Join(command.Args, " "), "workers domains update") {
			t.Fatalf("issuance resume rebound the existing domain: %#v", command.Args)
		}
	}
}

func TestStatusCompleteRequiresActiveManagedCertificate(t *testing.T) {
	deployment := config.Deployment{
		WorkerName:      "cf-vless",
		ZoneID:          testZoneID,
		Hostname:        "edge.example.com",
		OwnershipMarker: "0123456789abcdef0123456789abcdef",
		ManagedDomain: &config.ManagedDomain{
			DomainID:             "cccccccccccccccccccccccccccccccc",
			InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
			CertificatePackID:    "dddddddddddddddddddddddddddddddd",
		},
	}
	status := cloudflare.WorkerStatus{
		Exists: true, OwnershipMarker: deployment.OwnershipMarker, DeploymentCount: 1,
		Domains: []cloudflare.DomainBinding{{
			ID: "cccccccccccccccccccccccccccccccc", CertID: deployment.ManagedDomain.InitialCertificateID,
			Hostname: deployment.Hostname, Service: deployment.WorkerName, Environment: "production", ZoneID: deployment.ZoneID,
		}},
		Secrets: []cloudflare.SecretBinding{{Name: config.WorkerSecretName, Type: "secret_text"}},
	}
	packs := []cloudflare.CertificatePack{{
		ID: deployment.ManagedDomain.CertificatePackID, Type: "advanced", Status: "pending_deployment",
		Hosts: []string{deployment.Hostname}, Certificates: []cloudflare.CertificatePackCertificate{{
			ID: deployment.ManagedDomain.InitialCertificateID, Hosts: []string{deployment.Hostname},
		}},
	}}
	if statusComplete(status, deployment, packs) {
		t.Fatal("pending certificate pack was reported as a complete HTTPS deployment")
	}
	packs[0].Status = "active"
	if !statusComplete(status, deployment, packs) {
		t.Fatal("active exact certificate pack was not reported complete")
	}
}

func TestDeployRefusesOwnedDomainWithoutCreationTimeProvenance(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	runner.workerPresent = true
	runner.secretPresent = true
	runner.domainBound = true
	runner.certificatePackPresent = true
	runner.commands = nil
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"deploy", "--project-root", root, "--config", configPath},
		&stdout, &stderr, testDependencies(runner))
	if code == 0 || !strings.Contains(stderr.String(), "without creation-time provenance") {
		t.Fatalf("unproven domain code/output = %d / %q", code, stderr.String())
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if strings.HasPrefix(joined, "deploy") || strings.HasPrefix(joined, "workers domains update") ||
			strings.HasPrefix(joined, "workers secrets update") {
			t.Fatalf("unproven domain reached a mutation: %q", joined)
		}
	}
}

func TestDeployRefusesAdditionalServiceDomainBeforeMutation(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, _ := initializeForTest(t, runner)
	recordManagedDomainForTest(t, configPath)
	runner.workerPresent = true
	runner.secretPresent = true
	runner.domainBound = true
	runner.extraDomainBound = true
	runner.certificatePackPresent = true
	runner.commands = nil
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"deploy", "--project-root", root, "--config", configPath},
		&stdout, &stderr, testDependencies(runner))
	if code == 0 || !strings.Contains(stderr.String(), "service-wide Custom Domain inventory") {
		t.Fatalf("extra domain code/output = %d / %q", code, stderr.String())
	}
	for _, command := range runner.commands {
		joined := strings.Join(command.Args, " ")
		if strings.HasPrefix(joined, "deploy") || strings.HasPrefix(joined, "workers domains update") ||
			strings.HasPrefix(joined, "workers secrets update") {
			t.Fatalf("extra domain reached a mutation: %q", joined)
		}
	}
}

func TestRemovePrintsTheExactNonSecretPlanForDryRunAndRemoval(t *testing.T) {
	for _, test := range []struct {
		name   string
		args   []string
		dryRun bool
	}{
		{name: "dry run", args: []string{"--dry-run"}, dryRun: true},
		{name: "confirmed removal", args: []string{"--yes"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &recordingRunner{}
			root, configPath, stateDirectory := initializeForTest(t, runner)
			runner.workerPresent = true
			runner.secretPresent = true
			runner.domainBound = true
			runner.certificatePackPresent = true
			recordManagedDomainForTest(t, configPath)
			runner.commands = nil

			args := []string{"remove", "--project-root", root, "--config", configPath}
			args = append(args, test.args...)
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner))
			if code != 0 {
				t.Fatalf("remove code = %d, stderr = %s", code, stderr.String())
			}

			const prefix = "deletion plan: "
			line := strings.SplitN(stdout.String(), "\n", 2)[0]
			if !strings.HasPrefix(line, prefix) {
				t.Fatalf("remove output omitted deletion plan: %q", stdout.String())
			}
			var plan cloudflare.RemovalPlan
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, prefix)), &plan); err != nil {
				t.Fatalf("decode removal plan: %v", err)
			}
			if plan.Worker != "cf-vless" || !plan.DeleteWorker || plan.Hostname != "edge.example.com" ||
				len(plan.DomainIDs) != 1 || plan.DomainIDs[0] != "cccccccccccccccccccccccccccccccc" ||
				len(plan.CertificatePackIDs) != 1 || plan.CertificatePackIDs[0] != "dddddddddddddddddddddddddddddddd" ||
				len(plan.SecretNames) != 1 || plan.SecretNames[0] != config.WorkerSecretName {
				t.Fatalf("removal plan = %#v", plan)
			}
			deployment, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{deployment.Credentials.Current.UUID, deployment.Credentials.Current.Path} {
				if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
					t.Fatalf("remove output exposed a credential value")
				}
			}
			if test.dryRun {
				if !runner.workerPresent || !runner.secretPresent || !runner.domainBound || !runner.certificatePackPresent {
					t.Fatal("dry-run changed remote fixture state")
				}
				if _, err := os.Stat(filepath.Join(stateDirectory, "removal.pending.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("dry-run persisted removal checkpoint: %v", err)
				}
			} else if runner.workerPresent || runner.secretPresent || runner.domainBound || runner.certificatePackPresent {
				t.Fatal("confirmed removal did not delete every planned fixture resource")
			} else if _, err := os.Stat(filepath.Join(stateDirectory, "removal.pending.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed removal retained checkpoint: %v", err)
			}
		})
	}
}

func TestRemoveResumesCertificateCleanupFromPrivateCheckpoint(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, runner)
	runner.workerPresent = true
	runner.secretPresent = true
	runner.domainBound = true
	runner.certificatePackPresent = true
	recordManagedDomainForTest(t, configPath)
	runner.failCertificateDelete = true
	runner.commands = nil

	args := []string{"remove", "--project-root", root, "--config", configPath, "--yes"}
	var firstOut, firstErr bytes.Buffer
	if code := run(context.Background(), args, &firstOut, &firstErr, testDependencies(runner)); code == 0 {
		t.Fatal("injected partial removal unexpectedly succeeded")
	}
	checkpointPath := filepath.Join(stateDirectory, "removal.pending.json")
	checkpoint, err := config.LoadRemovalCheckpoint(checkpointPath)
	if err != nil {
		t.Fatalf("load retained checkpoint: %v", err)
	}
	if checkpoint.DomainID != "cccccccccccccccccccccccccccccccc" ||
		checkpoint.CertificatePackID != "dddddddddddddddddddddddddddddddd" {
		t.Fatalf("checkpoint = %#v", checkpoint)
	}
	if runner.domainBound || !runner.certificatePackPresent || !runner.workerPresent || !runner.secretPresent {
		t.Fatalf("unexpected partial state: domain=%t cert=%t worker=%t secret=%t",
			runner.domainBound, runner.certificatePackPresent, runner.workerPresent, runner.secretPresent)
	}

	runner.commands = nil
	var retryOut, retryErr bytes.Buffer
	if code := run(context.Background(), args, &retryOut, &retryErr, testDependencies(runner)); code != 0 {
		t.Fatalf("checkpointed retry code = %d, stderr = %s", code, retryErr.String())
	}
	if runner.domainBound || runner.certificatePackPresent || runner.workerPresent || runner.secretPresent {
		t.Fatal("checkpointed retry did not finish every remaining resource")
	}
	if _, err := os.Stat(checkpointPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint was not removed after retry: %v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(strings.Join(command.Args, " "), "workers domains delete") {
			t.Fatal("retry attempted to delete a replacement/absent domain")
		}
	}
}

func TestRemoveRefusesReplacementDomainBetweenCheckpointAndLiveDelete(t *testing.T) {
	base := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, base)
	base.workerPresent = true
	base.secretPresent = true
	base.domainBound = true
	base.certificatePackPresent = true
	recordManagedDomainForTest(t, configPath)
	base.commands = nil
	runner := &replacementDomainRunner{recordingRunner: base}

	args := []string{"remove", "--project-root", root, "--config", configPath, "--yes"}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr, testDependencies(runner)); code == 0 {
		t.Fatal("replacement Custom Domain unexpectedly passed the checkpointed live preflight")
	}
	if !strings.Contains(stderr.String(), "Custom Domain does not match the removal checkpoint") {
		t.Fatalf("replacement-domain refusal missing from stderr: %s", stderr.String())
	}
	if !base.domainBound || !base.certificatePackPresent || !base.workerPresent || !base.secretPresent {
		t.Fatalf("replacement-domain conflict changed remote fixture state: domain=%t cert=%t worker=%t secret=%t",
			base.domainBound, base.certificatePackPresent, base.workerPresent, base.secretPresent)
	}
	checkpointPath := filepath.Join(stateDirectory, "removal.pending.json")
	checkpoint, err := config.LoadRemovalCheckpoint(checkpointPath)
	if err != nil {
		t.Fatalf("load retained checkpoint: %v", err)
	}
	if checkpoint.DomainID != "cccccccccccccccccccccccccccccccc" {
		t.Fatalf("checkpoint domain ID = %q", checkpoint.DomainID)
	}
	for _, command := range base.commands {
		joined := strings.Join(command.Args, " ")
		if strings.HasPrefix(joined, "workers domains delete") && !strings.Contains(joined, "--dry-run") {
			t.Fatalf("replacement domain reached a live delete: %q", joined)
		}
	}
}

func TestRemoveRetainsCheckpointUntilCertificateDeletionConverges(t *testing.T) {
	runner := &recordingRunner{}
	root, configPath, stateDirectory := initializeForTest(t, runner)
	runner.workerPresent = true
	runner.secretPresent = true
	runner.domainBound = true
	runner.certificatePackPresent = true
	recordManagedDomainForTest(t, configPath)
	runner.deferCertificateDelete = true
	runner.certificatePendingPolls = 1
	runner.commands = nil

	args := []string{"remove", "--project-root", root, "--config", configPath, "--yes"}
	var firstOut, firstErr bytes.Buffer
	if code := run(context.Background(), args, &firstOut, &firstErr, testDependencies(runner)); code == 0 {
		t.Fatal("asynchronous certificate deletion unexpectedly reported convergence")
	}
	checkpointPath := filepath.Join(stateDirectory, "removal.pending.json")
	if _, err := config.LoadRemovalCheckpoint(checkpointPath); err != nil {
		t.Fatalf("load retained checkpoint: %v", err)
	}
	if !runner.certificatePackPresent || runner.workerPresent || runner.secretPresent || runner.domainBound {
		t.Fatalf("unexpected asynchronous state: domain=%t cert=%t worker=%t secret=%t",
			runner.domainBound, runner.certificatePackPresent, runner.workerPresent, runner.secretPresent)
	}

	runner.commands = nil
	var retryOut, retryErr bytes.Buffer
	if code := run(context.Background(), args, &retryOut, &retryErr, testDependencies(runner)); code != 0 {
		t.Fatalf("convergence retry code = %d, stderr = %s", code, retryErr.String())
	}
	if runner.certificatePackPresent {
		t.Fatal("certificate pack did not converge before checkpoint removal")
	}
	if _, err := os.Stat(checkpointPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkpoint was not removed after convergence: %v", err)
	}
}

func TestExactAdvancedCertificateIgnoresDeletedInventoryEntries(t *testing.T) {
	packs := []cloudflare.CertificatePack{{
		ID: "dddddddddddddddddddddddddddddddd", Type: "advanced", Status: "deleted", Hosts: []string{"edge.example.com"},
	}}
	if hasExactAdvancedCertificate(packs, "edge.example.com") {
		t.Fatal("deleted certificate inventory entry blocked hostname reuse")
	}
	packs[0].Status = "active"
	if !hasExactAdvancedCertificate(packs, "edge.example.com") {
		t.Fatal("active exact Advanced Certificate pack was not detected")
	}
}

func TestParsePortsSortsAndRejectsProhibitedValues(t *testing.T) {
	ports, err := parsePorts("443,22,80")
	if err != nil || len(ports) != 3 || ports[0] != 22 || ports[1] != 80 || ports[2] != 443 {
		t.Fatalf("parsePorts() = %#v, %v", ports, err)
	}
	for _, value := range []string{"", "25", "80,80", "0", "not-a-port"} {
		if _, err := parsePorts(value); err == nil {
			t.Fatalf("parsePorts(%q) unexpectedly succeeded", value)
		}
	}
}

func TestVersionAtLeastUnderstandsGoAndNodeOutput(t *testing.T) {
	for _, test := range []struct {
		output  string
		minimum string
		want    bool
	}{
		{output: "go version go1.24.3 darwin/arm64", minimum: "1.24", want: true},
		{output: "go version go1.23.9 darwin/arm64", minimum: "1.24", want: false},
		{output: "v22.18.0", minimum: "22.18", want: true},
		{output: "v22.17.9", minimum: "22.18", want: false},
	} {
		if got := versionAtLeast(test.output, test.minimum); got != test.want {
			t.Fatalf("versionAtLeast(%q, %q) = %t", test.output, test.minimum, got)
		}
	}
}

func TestLogSanitizerRedactsRequestMetadataAndFreeFormStrings(t *testing.T) {
	var output bytes.Buffer
	sanitizer := &logSanitizer{output: &output}
	input := `{"outcome":"ok","level":"info","event":{"request":{"url":"https://edge.example.com/random-path","headers":{"CF-Connecting-IP":"203.0.113.9"}},"destination":"secret.example:443"},"message":"dial secret.example:443","count":2}` + "\nnot-json\n"

	split := len(input) / 3
	for _, part := range []string{input[:split], input[split : split*2], input[split*2:]} {
		if _, err := sanitizer.Write([]byte(part)); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	if err := sanitizer.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	result := output.String()
	for _, secret := range []string{"edge.example.com", "random-path", "203.0.113.9", "secret.example"} {
		if strings.Contains(result, secret) {
			t.Fatalf("sanitized output leaked %q: %s", secret, result)
		}
	}
	for _, safe := range []string{`"outcome":"ok"`, `"level":"info"`, `"count":2`, `"event":"unparsed_log_redacted"`} {
		if !strings.Contains(result, safe) {
			t.Fatalf("sanitized output omitted %s: %s", safe, result)
		}
	}
}

func TestLogSanitizerRedactsBytePayloadsAndSensitiveDynamicKeys(t *testing.T) {
	var output bytes.Buffer
	sanitizer := &logSanitizer{output: &output}
	input := `{"level":"info","payload":[65,66,67],"frame":{"bytes":[1,2,3]},"attributes":{"550e8400-e29b-41d4-a716-446655440000":[9,8,7],"https://secret.example/private":42,"edge.secret.example":99},"count":4}` + "\n"
	if _, err := sanitizer.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if err := sanitizer.Flush(); err != nil {
		t.Fatal(err)
	}

	result := output.String()
	for _, sensitive := range []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"https://secret.example/private",
		"edge.secret.example",
		`[65,66,67]`,
		`[9,8,7]`,
	} {
		if strings.Contains(result, sensitive) {
			t.Fatalf("sanitized output leaked %q: %s", sensitive, result)
		}
	}
	for _, safe := range []string{`"level":"info"`, `"payload":"[REDACTED]"`, `"frame":"[REDACTED]"`, `"[REDACTED_KEY]":"[REDACTED]"`, `"count":4`} {
		if !strings.Contains(result, safe) {
			t.Fatalf("sanitized output omitted %s: %s", safe, result)
		}
	}
}
