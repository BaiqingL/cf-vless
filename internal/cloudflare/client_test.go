package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const (
	testAccountID                  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testZoneID                     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDomainID                   = "cccccccccccccccccccccccccccccccc"
	testCertificateID              = "9fdf92c8-64c2-4a3d-b1af-e15304961145"
	testCertificatePack            = "dddddddddddddddddddddddddddddddd"
	testProject                    = ".cf-vless/worker"
	testOwnershipMarker            = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testManagedScriptInventoryItem = `{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":false,"has_assets":false}`
)

type runStep struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

type recordedCommand struct {
	program        string
	args           []string
	dir            string
	environment    []string
	stdin          []byte
	hasStdin       bool
	sensitiveStdin bool
	interactive    bool
	printable      string
	goPrintable    string
	streamingOut   bool
	streamingErr   bool
}

type scriptedRunner struct {
	t                      *testing.T
	steps                  []runStep
	calls                  []recordedCommand
	scriptAttachmentChecks bool
}

type nonInteractiveRunner struct {
	*scriptedRunner
}

func (nonInteractiveRunner) InteractiveReady() bool { return false }

func (r *scriptedRunner) Run(_ context.Context, command Command) (RunResult, error) {
	r.t.Helper()
	if !r.scriptAttachmentChecks {
		if result, ok := implicitManagedAttachmentResponse(command); ok {
			return result, nil
		}
	}
	if len(r.calls) >= len(r.steps) {
		r.t.Fatalf("unexpected command %s", command.String())
	}
	step := r.steps[len(r.calls)]

	var stdin []byte
	if command.HasStdin() {
		var err error
		stdin, err = io.ReadAll(command.Stdin())
		if err != nil {
			r.t.Fatalf("read command stdin: %v", err)
		}
	}
	r.calls = append(r.calls, recordedCommand{
		program:        command.Program,
		args:           append([]string(nil), command.Args...),
		dir:            command.Dir,
		environment:    command.Environment(),
		stdin:          append([]byte(nil), stdin...),
		hasStdin:       command.HasStdin(),
		sensitiveStdin: command.SensitiveStdin(),
		interactive:    command.Interactive(),
		printable:      command.String(),
		goPrintable:    fmt.Sprintf("%#v", command),
		streamingOut:   command.StdoutWriter() != nil,
		streamingErr:   command.StderrWriter() != nil,
	})

	result := RunResult{ExitCode: step.exitCode}
	if command.StdoutWriter() == nil {
		result.Stdout = step.stdout
	} else if _, err := io.WriteString(command.StdoutWriter(), step.stdout); err != nil {
		r.t.Fatalf("write streamed stdout: %v", err)
	}
	if command.StderrWriter() == nil {
		result.Stderr = step.stderr
	} else if _, err := io.WriteString(command.StderrWriter(), step.stderr); err != nil {
		r.t.Fatalf("write streamed stderr: %v", err)
	}
	return result, step.err
}

func implicitManagedAttachmentResponse(command Command) (RunResult, bool) {
	switch strings.Join(command.Args, " ") {
	case "workers scripts schedules get --worker cf-vless-edge":
		return RunResult{Stdout: `{"schedules":[]}`}, true
	case "workers scripts settings get --worker cf-vless-edge":
		return RunResult{Stdout: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":{"enabled":false,"head_sampling_rate":0,"logs":{"enabled":false,"head_sampling_rate":0,"invocation_logs":false,"persist":false},"traces":{"enabled":false,"head_sampling_rate":0,"persist":false}}}`}, true
	case "workers scripts subdomain get --worker cf-vless-edge":
		return RunResult{Stdout: `{"enabled":false,"previews_enabled":false}`}, true
	default:
		return RunResult{}, false
	}
}

func (r *scriptedRunner) assertDone(t *testing.T) {
	t.Helper()
	if len(r.calls) != len(r.steps) {
		t.Fatalf("runner used %d of %d scripted steps", len(r.calls), len(r.steps))
	}
}

func newTestClient(t *testing.T, runner Runner) *Client {
	t.Helper()
	client, err := NewClient(runner, Options{
		ProjectDir: testProject,
		AccountID:  testAccountID,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func assertCall(t *testing.T, call recordedCommand, program, dir string, args []string) {
	t.Helper()
	if call.program != program {
		t.Errorf("program = %q, want %q", call.program, program)
	}
	if call.dir != dir {
		t.Errorf("dir = %q, want %q", call.dir, dir)
	}
	if !reflect.DeepEqual(call.args, args) {
		t.Errorf("args = %#v, want %#v", call.args, args)
	}
}

func TestBuildAndDeployConstructExactCFCommands(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: "built"}, {stdout: "deployed"}}}
	client := newTestClient(t, runner)

	if _, err := client.Build(context.Background(), BuildOptions{Mode: "production"}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := client.Deploy(context.Background(), DeployOptions{
		Mode:     "production",
		Prebuilt: true,
		Tag:      "release-7",
		Message:  "credential rotation",
		DryRun:   true,
	}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", testProject, []string{"build", "--mode", "production"})
	assertCall(t, runner.calls[1], "cf", testProject, []string{
		"deploy", "--mode", "production", "--prebuilt", "--tag", "release-7", "--message", "credential rotation", "--dry-run",
	})
	for _, call := range runner.calls {
		if !reflect.DeepEqual(call.environment, []string{"CLOUDFLARE_ACCOUNT_ID=" + testAccountID}) {
			t.Errorf("environment = %#v", call.environment)
		}
	}
}

func TestRequireSupportedCFVersionUsesExactPreviewVersion(t *testing.T) {
	for _, test := range []struct {
		name    string
		output  string
		wantErr bool
	}{
		{name: "exact", output: "cf version " + SupportedCFVersion},
		{name: "newer is unsupported", output: "cf version 0.3.0", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, steps: []runStep{{stdout: test.output}}}
			client := newTestClient(t, runner)
			err := client.RequireSupportedCFVersion(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("RequireSupportedCFVersion() error = %v, wantErr %t", err, test.wantErr)
			}
			if test.wantErr && !strings.Contains(err.Error(), "required version "+SupportedCFVersion) {
				t.Fatalf("version error = %q", err.Error())
			}
			runner.assertDone(t)
			assertCall(t, runner.calls[0], "cf", "", []string{"--version"})
		})
	}
}

func TestRequireSupportedCFVersionCannotBeRelaxedByDoctorExpectation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: "cf version 0.3.0"}}}
	client, err := NewClient(runner, Options{ExpectedCFVersion: "0.3.0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RequireSupportedCFVersion(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "required version "+SupportedCFVersion) {
		t.Fatalf("RequireSupportedCFVersion() error = %v", err)
	}
	runner.assertDone(t)
}

func TestSetSecretUsesCFProtectedStdinAndRedactsEveryDiagnostic(t *testing.T) {
	const secretText = `{"current":{"uuid":"efb7a5ec-6b0f-4d85-8ffd-cad102494f2c","path":"/edge"},"previous":{"uuid":"27848739-7e62-4138-9fd3-098a63964b6b","path":"/old-edge","expiresAt":"2030-01-01T00:00:00Z"}}`
	secretBacking := append([]byte(secretText), 0x7f)
	secret := secretBacking[:len(secretText)]
	escapedSecret := strconv.Quote(secretText)
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{
			stdout:   "echoed " + secretText,
			stderr:   "rejected " + escapedSecret,
			exitCode: 23,
			err:      errors.New("runner exposed " + escapedSecret),
		},
	}}
	client := newTestClient(t, runner)

	operation, err := client.SetSecret(context.Background(), SecretRequest{
		Worker:          "cf-vless-edge",
		OwnershipMarker: testOwnershipMarker,
		Name:            "VLESS_CREDENTIALS",
		Value:           secret,
	})
	if err == nil {
		t.Fatal("SetSecret unexpectedly succeeded")
	}
	if string(secret) != secretText {
		t.Fatal("SetSecret modified the caller-owned secret buffer")
	}
	if secretBacking[len(secret)] != 0x7f {
		t.Fatal("SetSecret modified caller-owned capacity beyond the secret")
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", testProject, []string{"workers", "scripts", "list"})
	assertCall(t, runner.calls[1], "cf", testProject, []string{
		"workers", "scripts", "script-and-version-settings", "get", "--worker", "cf-vless-edge",
	})
	call := runner.calls[2]
	assertCall(t, call, "cf", testProject, []string{
		"workers", "secrets", "update", "VLESS_CREDENTIALS", "--worker", "cf-vless-edge", "--type", "secret_text",
	})
	if !reflect.DeepEqual(call.environment, []string{"CLOUDFLARE_ACCOUNT_ID=" + testAccountID}) {
		t.Errorf("environment = %#v", call.environment)
	}
	if !call.hasStdin || !call.sensitiveStdin {
		t.Fatalf("stdin flags = has:%v sensitive:%v", call.hasStdin, call.sensitiveStdin)
	}
	if want := append(append([]byte(nil), secret...), '\n'); !bytes.Equal(call.stdin, want) {
		t.Errorf("stdin does not equal secret plus newline")
	}

	for label, diagnostic := range map[string]string{
		"operation command": operation.Command,
		"operation stdout":  operation.Stdout,
		"operation stderr":  operation.Stderr,
		"error":             err.Error(),
		"command String":    call.printable,
		"command GoString":  call.goPrintable,
	} {
		if strings.Contains(diagnostic, secretText) || strings.Contains(diagnostic, escapedSecret[1:len(escapedSecret)-1]) {
			t.Errorf("%s exposed the secret", label)
		}
	}
	var commandError *CommandError
	if !errors.As(err, &commandError) || strings.Contains(commandError.Cause, escapedSecret[1:len(escapedSecret)-1]) {
		t.Errorf("sanitized command cause = %#v", commandError)
	}
	for _, arg := range call.args {
		if strings.Contains(arg, secretText) {
			t.Errorf("argv exposed the secret: %q", arg)
		}
		if arg == "--text" || arg == "--body" || strings.Contains(arg, secretText) {
			t.Errorf("unsafe cf secret argument used: %q", arg)
		}
	}
	if !strings.Contains(operation.Stdout, "[REDACTED]") || !strings.Contains(operation.Stderr, "[REDACTED]") {
		t.Errorf("captured output was not visibly redacted: %#v", operation)
	}
	if operation.Provider != ProviderCF || operation.FallbackReason != "" {
		t.Errorf("fallback metadata = %#v", operation)
	}
}

func TestCapabilitiesLabelOnlyNecessaryOperationsAsWranglerFallbacks(t *testing.T) {
	client := newTestClient(t, &scriptedRunner{t: t})
	report := client.Capabilities(SupportedCFVersion, "4.110.0")

	for _, capability := range []Capability{CapabilityLiveLogs} {
		var found *CapabilityStatus
		for i := range report.Items {
			if report.Items[i].Capability == capability {
				found = &report.Items[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("missing capability %s", capability)
		}
		if found.Provider != ProviderWrangler || !found.Fallback || !found.Available || !found.Required {
			t.Errorf("capability %s = %#v", capability, *found)
		}
	}
	for _, item := range report.Items {
		if item.Capability == CapabilitySingleSecret && (item.Provider != ProviderCF || item.Fallback || !item.Available || !item.Required) {
			t.Errorf("single secret capability = %#v", item)
		}
	}
}

func TestWranglerAuthenticationChecksAccountWithoutReturningPII(t *testing.T) {
	const discardedEmail = "discard-me@example.com"
	const discardedAccountName = "Discarded Account Name"
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: `{
		"loggedIn":true,
		"authType":"OAuth Token",
		"email":"` + discardedEmail + `",
		"accounts":[{"id":"` + testAccountID + `","name":"` + discardedAccountName + `"}],
		"tokenPermissions":["account:read","workers:write"]
	}`}}}
	client := newTestClient(t, runner)

	info, err := client.WranglerAuthentication(context.Background(), testAccountID)
	if err != nil {
		t.Fatalf("WranglerAuthentication: %v", err)
	}
	if !info.LoggedIn || !info.AccountAccessible {
		t.Fatalf("Wrangler authentication = %#v", info)
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, pii := range []string{discardedEmail, discardedAccountName, "OAuth Token", "workers:write"} {
		if bytes.Contains(encoded, []byte(pii)) {
			t.Fatalf("returned authentication state retained %q: %s", pii, encoded)
		}
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "npx", testProject, []string{"--no-install", "wrangler", "whoami", "--json"})
}

func TestSetSecretRefusesWranglerDraftCreationForMissingWorker(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: `{"result":[]}`}}}
	client := newTestClient(t, runner)

	operation, err := client.SetSecret(context.Background(), SecretRequest{
		Worker:          "cf-vless-edge",
		OwnershipMarker: testOwnershipMarker,
		Name:            "VLESS_CREDENTIALS",
		Value:           []byte(`{"current":{"uuid":"efb7a5ec-6b0f-4d85-8ffd-cad102494f2c","path":"/edge"}}`),
	})
	if !errors.Is(err, ErrWorkerNotFound) {
		t.Fatalf("error = %v, want ErrWorkerNotFound", err)
	}
	if operation.Provider != ProviderCF {
		t.Errorf("preflight operation = %#v", operation)
	}
	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", testProject, []string{"workers", "scripts", "list"})
}

func TestBindCustomDomainUsesCF020OptionalFieldWorkaround(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[]}`},
		{stdout: `[]`},
		{stdout: `{"result":{"id":"` + testDomainID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production","zone_id":"` + testZoneID + `","zone_name":"example.com"}}`},
	}}
	client := newTestClient(t, runner)

	result, err := client.BindCustomDomain(context.Background(), CustomDomainRequest{
		Hostname: "EDGE.EXAMPLE.COM.",
		Worker:   "cf-vless-edge",
		ZoneID:   testZoneID,
		ZoneName: "EXAMPLE.COM.",
	})
	if err != nil {
		t.Fatalf("BindCustomDomain: %v", err)
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", testProject, []string{
		"workers", "domains", "list",
		"--zone-id", testZoneID,
		"--zone-name", "example.com",
		"--hostname", "edge.example.com",
	})
	assertCall(t, runner.calls[1], "cf", "", []string{
		"dns", "records", "list", "--name", "edge.example.com", "--zone", testZoneID,
	})
	assertCall(t, runner.calls[2], "cf", "", []string{
		"workers", "routes", "list", "--zone", testZoneID,
	})
	assertCall(t, runner.calls[3], "cf", testProject, []string{
		"workers", "domains", "update",
		"--hostname", "edge.example.com",
		"--service", "cf-vless-edge",
		"--environment", "production",
		"--zone-id", testZoneID,
		"--zone-name", "example.com",
	})
	if !result.Changed || result.Existing || result.Binding.ID != testDomainID || len(result.Operations) != 4 {
		t.Errorf("result = %#v", result)
	}
}

func TestBindCustomDomainRefusesDNSRecordThatAppearsBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[{"id":"dns-race","type":"CNAME","name":"edge.example.com","content":"other.example.net"}]}`},
	}}
	client := newTestClient(t, runner)

	result, err := client.BindCustomDomain(context.Background(), CustomDomainRequest{
		Hostname: "edge.example.com",
		Worker:   "cf-vless-edge",
		ZoneID:   testZoneID,
		ZoneName: "example.com",
	})
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("error = %v, want ErrResourceConflict", err)
	}
	if result.Changed || len(result.Operations) != 2 {
		t.Fatalf("result = %#v", result)
	}
	runner.assertDone(t)
}

func TestBindCustomDomainRefusesWorkerRouteThatAppearsBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[]}`},
		{stdout: `[{"id":"route-race","pattern":"*example.com/*","script":"other-worker"}]`},
	}}
	client := newTestClient(t, runner)

	result, err := client.BindCustomDomain(context.Background(), CustomDomainRequest{
		Hostname: "edge.example.com",
		Worker:   "cf-vless-edge",
		ZoneID:   testZoneID,
		ZoneName: "example.com",
	})
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("error = %v, want ErrResourceConflict", err)
	}
	if result.Changed || len(result.Operations) != 3 {
		t.Fatalf("result = %#v", result)
	}
	runner.assertDone(t)
}

func TestBindCustomDomainRefusesDifferentOwnerBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{
		stdout: `{"result":[{"id":"` + testDomainID + `","hostname":"edge.example.com","service":"someone-else","environment":"production"}]}`,
	}}}
	client := newTestClient(t, runner)

	_, err := client.BindCustomDomain(context.Background(), CustomDomainRequest{
		Hostname: "edge.example.com",
		Worker:   "cf-vless-edge",
		ZoneID:   testZoneID,
		ZoneName: "example.com",
	})
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("error = %v, want ErrResourceConflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 1 {
		t.Fatalf("mutation was attempted after conflict")
	}
}

func TestHostnameAvailabilityChecksCustomDomainAndExactDNS(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[]}`},
		{stdout: `[]`},
	}}
	client := newTestClient(t, runner)
	check, err := client.CheckHostnameAvailability(context.Background(), HostnameCheckOptions{
		Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
		Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
	})
	if err != nil || !check.Available || check.Owned {
		t.Fatalf("hostname check = %#v, %v", check, err)
	}
	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", testProject, []string{
		"workers", "domains", "list", "--zone-id", testZoneID, "--zone-name", "example.com", "--hostname", "edge.example.com",
	})
	assertCall(t, runner.calls[1], "cf", "", []string{
		"dns", "records", "list", "--name", "edge.example.com", "--zone", testZoneID,
	})
}

func TestHostnameAvailabilityRejectsExistingDNSRecord(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[{"id":"dns-1","type":"CNAME","name":"edge.example.com","content":"other.example.net"}]}`},
		{stdout: `[]`},
	}}
	client := newTestClient(t, runner)
	check, err := client.CheckHostnameAvailability(context.Background(), HostnameCheckOptions{
		Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
	})
	if err != nil || check.Available || len(check.Records) != 1 {
		t.Fatalf("hostname conflict = %#v, %v", check, err)
	}
}

func TestHostnameAvailabilityRejectsOverlappingWorkerRoute(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[]}`},
		{stdout: `[{"id":"route-1","pattern":"*.example.com/*","script":"other-worker"}]`},
	}}
	client := newTestClient(t, runner)
	check, err := client.CheckHostnameAvailability(context.Background(), HostnameCheckOptions{
		Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
	})
	if err != nil || check.Available || len(check.Routes) != 1 {
		t.Fatalf("route conflict = %#v, %v", check, err)
	}
	runner.assertDone(t)
}

func TestListCertificatePacksReadsEveryBoundedPage(t *testing.T) {
	firstPage := make([]map[string]any, 0, 50)
	for index := 0; index < 50; index++ {
		firstPage = append(firstPage, map[string]any{
			"id": fmt.Sprintf("%032x", index+1), "type": "advanced", "hosts": []string{"other.example.com"},
		})
	}
	firstJSON, err := json.Marshal(map[string]any{"result": firstPage})
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(map[string]any{"result": []map[string]any{{
		"id": testCertificatePack, "type": "advanced", "hosts": []string{"edge.example.com"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: string(firstJSON)}, {stdout: string(secondJSON)}}}
	client := newTestClient(t, runner)
	packs, _, err := client.ListCertificatePacks(context.Background(), testZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 51 || packs[50].ID != testCertificatePack {
		t.Fatalf("certificate packs = %#v", packs)
	}
	for index, page := range []string{"1", "2"} {
		assertCall(t, runner.calls[index], "cf", "", []string{
			"ssl", "certificate-packs", "list", "--status", "all", "--page", page, "--per-page", "50", "--zone", testZoneID,
		})
	}
	runner.assertDone(t)
}

func TestWorkerStatusUsesReadOnlyExactQueries(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `,{"id":"unrelated"}]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"deploy-2"},{"id":"deploy-1"}]}`},
		{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"},{"name":"UNRELATED","type":"secret_text"}]}`},
	}}
	client := newTestClient(t, runner)

	status, err := client.WorkerStatus(context.Background(), "cf-vless-edge")
	if err != nil {
		t.Fatalf("WorkerStatus: %v", err)
	}
	if !status.Exists || status.OwnershipMarker != testOwnershipMarker || status.DeploymentCount != 2 || len(status.Domains) != 1 || len(status.Secrets) != 2 {
		t.Errorf("status = %#v", status)
	}

	runner.assertDone(t)
	wants := [][]string{
		{"workers", "scripts", "list"},
		{"workers", "scripts", "script-and-version-settings", "get", "--worker", "cf-vless-edge"},
		{"workers", "deployments", "list", "--worker", "cf-vless-edge"},
		{"workers", "domains", "list", "--service", "cf-vless-edge"},
		{"workers", "secrets", "list", "--worker", "cf-vless-edge"},
	}
	for i, want := range wants {
		dir := testProject
		if want[0] == "ssl" {
			dir = ""
		}
		assertCall(t, runner.calls[i], "cf", dir, want)
	}
}

func TestWorkerStatusRefusesUnplannedBindingBeforeFurtherReads(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"},{"name":"USER_KV","type":"kv_namespace","namespace_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.WorkerStatus(context.Background(), "cf-vless-edge")
	if !errors.Is(err, ErrResourceConflict) || !strings.Contains(err.Error(), "unplanned binding") {
		t.Fatalf("error = %v, want unplanned-binding conflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 2 {
		t.Fatalf("status continued after unplanned binding: %#v", runner.calls)
	}
}

func TestTailLogsUsesPinnedWranglerAndStreams(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{
		stdout: `{"event":"ok"}` + "\n",
		stderr: "connected\n",
	}}}
	client := newTestClient(t, runner)
	var stdout, stderr bytes.Buffer
	rate := 0.25

	operation, err := client.TailLogs(context.Background(), LogsOptions{
		Worker:       "cf-vless-edge",
		Statuses:     []string{"ok", "error", "ok"},
		Search:       "upgrade",
		SamplingRate: &rate,
		Stdout:       &stdout,
		Stderr:       &stderr,
	})
	if err != nil {
		t.Fatalf("TailLogs: %v", err)
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "npx", testProject, []string{
		"--no-install", "wrangler", "tail", "cf-vless-edge", "--format", "json",
		"--status", "ok", "--status", "error", "--search", "upgrade", "--sampling-rate", "0.25",
	})
	if !runner.calls[0].streamingOut || !runner.calls[0].streamingErr {
		t.Errorf("streaming flags = stdout:%v stderr:%v", runner.calls[0].streamingOut, runner.calls[0].streamingErr)
	}
	if stdout.String() != `{"event":"ok"}`+"\n" || stderr.String() != "connected\n" {
		t.Errorf("streamed output = %q / %q", stdout.String(), stderr.String())
	}
	if operation.Provider != ProviderWrangler || operation.FallbackReason != liveLogsFallbackReason {
		t.Errorf("fallback metadata = %#v", operation)
	}
}

func TestRemoveNamedOnlyDeletesPreflightedExactResources(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `,{"id":"unrelated-worker"}]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
		{stdout: `{"result":[{"id":"` + testCertificatePack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`},
		{},
		{},
		{},
		{},
	}}
	client := newTestClient(t, runner)

	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		Confirm: true,
		Resources: NamedResources{
			Worker:          "cf-vless-edge",
			OwnershipMarker: testOwnershipMarker,
			Hostname:        "edge.example.com",
			ZoneID:          testZoneID,
			ZoneName:        "example.com",
			SecretNames:     []string{"VLESS_CREDENTIALS", "VLESS_CREDENTIALS"},
		},
	})
	if err != nil {
		t.Fatalf("RemoveNamed: %v", err)
	}
	if !reflect.DeepEqual(result.RemovedDomainIDs, []string{testDomainID}) ||
		!reflect.DeepEqual(result.RemovedCertificatePackIDs, []string{testCertificatePack}) ||
		!reflect.DeepEqual(result.RemovedSecrets, []string{"VLESS_CREDENTIALS"}) || !result.WorkerRemoved {
		t.Errorf("result = %#v", result)
	}
	wantPlan := RemovalPlan{
		Worker:             "cf-vless-edge",
		DeleteWorker:       true,
		Hostname:           "edge.example.com",
		DomainIDs:          []string{testDomainID},
		CertificatePackIDs: []string{testCertificatePack},
		SecretNames:        []string{"VLESS_CREDENTIALS"},
	}
	if !reflect.DeepEqual(result.Plan, wantPlan) {
		t.Errorf("plan = %#v, want %#v", result.Plan, wantPlan)
	}

	runner.assertDone(t)
	wants := [][]string{
		{"workers", "scripts", "list"},
		{"workers", "scripts", "script-and-version-settings", "get", "--worker", "cf-vless-edge"},
		{"workers", "domains", "list", "--service", "cf-vless-edge"},
		{"ssl", "certificate-packs", "list", "--status", "all", "--page", "1", "--per-page", "50", "--zone", testZoneID},
		{"workers", "secrets", "list", "--worker", "cf-vless-edge"},
		{"workers", "domains", "delete", testDomainID, "--force"},
		{"ssl", "certificate-packs", "delete", testCertificatePack, "--zone", testZoneID, "--force"},
		{"workers", "secrets", "delete", "VLESS_CREDENTIALS", "--worker", "cf-vless-edge", "--force"},
		{"workers", "scripts", "delete", "--worker", "cf-vless-edge"},
	}
	for i, want := range wants {
		dir := testProject
		if want[0] == "ssl" {
			dir = ""
		}
		assertCall(t, runner.calls[i], "cf", dir, want)
	}
	if runner.calls[8].hasStdin || !runner.calls[8].interactive {
		t.Errorf("Worker delete stdin/interactive = %v/%v", runner.calls[8].hasStdin, runner.calls[8].interactive)
	}
	if containsString(runner.calls[8].args, "--force") {
		t.Error("Worker delete used dangerous --force")
	}
	for _, call := range runner.calls[5:] {
		joined := strings.Join(call.args, " ")
		if strings.Contains(joined, "unrelated-worker") || strings.Contains(joined, "UNRELATED") {
			t.Errorf("mutation included an unrelated resource: %s", joined)
		}
	}
}

func TestRemoveNamedDryRunReturnsExactPlanWithoutReportingRemoval(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
		{stdout: `{"result":[{"id":"` + testCertificatePack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`},
		{},
		{},
		{},
		{},
	}}
	client := newTestClient(t, runner)

	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker:          "cf-vless-edge",
			OwnershipMarker: testOwnershipMarker,
			Hostname:        "edge.example.com",
			ZoneID:          testZoneID,
			ZoneName:        "example.com",
			SecretNames:     []string{"VLESS_CREDENTIALS"},
		},
	})
	if err != nil {
		t.Fatalf("RemoveNamed dry run: %v", err)
	}
	wantPlan := RemovalPlan{
		Worker:             "cf-vless-edge",
		DeleteWorker:       true,
		Hostname:           "edge.example.com",
		DomainIDs:          []string{testDomainID},
		CertificatePackIDs: []string{testCertificatePack},
		SecretNames:        []string{"VLESS_CREDENTIALS"},
	}
	if !result.DryRun || !reflect.DeepEqual(result.Plan, wantPlan) {
		t.Fatalf("dry-run result = %#v, want plan %#v", result, wantPlan)
	}
	if result.WorkerRemoved || len(result.RemovedDomainIDs) != 0 || len(result.RemovedCertificatePackIDs) != 0 || len(result.RemovedSecrets) != 0 {
		t.Fatalf("dry run reported removals: %#v", result)
	}

	runner.assertDone(t)
	for _, call := range runner.calls[5:] {
		if !containsString(call.args, "--dry-run") {
			t.Errorf("planned mutation omitted --dry-run: %#v", call.args)
		}
	}
}

func TestRemoveNamedRetryUsesExpectedCertificatePackAfterDomainIsGone(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[{"id":"` + testCertificatePack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`},
		{},
		{},
		{},
	}}
	client := newTestClient(t, runner)

	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		Confirm: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"}, ExpectedDomainID: testDomainID,
			ExpectedCertificatePackID: testCertificatePack,
		},
	})
	if err != nil {
		t.Fatalf("RemoveNamed retry: %v", err)
	}
	if len(result.Plan.DomainIDs) != 0 || !reflect.DeepEqual(result.Plan.CertificatePackIDs, []string{testCertificatePack}) ||
		!reflect.DeepEqual(result.RemovedCertificatePackIDs, []string{testCertificatePack}) || !result.WorkerRemoved {
		t.Fatalf("retry result = %#v", result)
	}
	runner.assertDone(t)
	for _, call := range runner.calls {
		if len(call.args) >= 3 && reflect.DeepEqual(call.args[:3], []string{"workers", "domains", "delete"}) {
			t.Fatalf("retry attempted to delete an already-absent domain: %#v", call.args)
		}
	}
}

func TestRemoveNamedRefusesReplacementDomainAfterCheckpoint(t *testing.T) {
	const replacementDomainID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"` + replacementDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"}, ExpectedDomainID: testDomainID,
			ExpectedCertificatePackID: testCertificatePack,
		},
	})
	if !errors.Is(err, ErrResourceConflict) || !strings.Contains(err.Error(), "Custom Domain") {
		t.Fatalf("error = %v, want checkpointed Custom Domain conflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 3 {
		t.Fatalf("command ran after replacement-domain conflict: %#v", runner.calls)
	}
}

func TestRemoveNamedRefusesDomainThatAppearsAfterCheckpointedAbsence(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"}, EnforceExpectedDomainID: true,
		},
	})
	if !errors.Is(err, ErrResourceConflict) || !strings.Contains(err.Error(), "Custom Domain") {
		t.Fatalf("error = %v, want checkpointed-absence Custom Domain conflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 3 {
		t.Fatalf("command ran after domain appeared following checkpointed absence: %#v", runner.calls)
	}
}

func TestRemoveNamedValidatesExpectedDomainIDBeforeRemoteReads(t *testing.T) {
	runner := &scriptedRunner{t: t}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			SecretNames: []string{"VLESS_CREDENTIALS"}, ExpectedDomainID: "not-an-id",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "expected domain ID") {
		t.Fatalf("error = %v, want expected-domain-ID validation error", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("remote reads ran with an invalid expected domain ID: %#v", runner.calls)
	}
}

func TestWorkerDomainIDValidationAcceptsObserved40HexForm(t *testing.T) {
	if err := validateWorkerDomainID("domain ID", "cccccccccccccccccccccccccccccccccccccccc"); err != nil {
		t.Fatal(err)
	}
	if err := validateWorkerDomainID("domain ID", "ccccccccccccccccccccccccccccccccccccccc"); err == nil {
		t.Fatal("39-character Domain ID was accepted")
	}
}

func TestRemoveNamedRequiresConfirmationBeforeAnyCommand(t *testing.T) {
	runner := &scriptedRunner{t: t}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		Resources: NamedResources{Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker},
	})
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("error = %v, want ErrConfirmationRequired", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("commands ran without confirmation: %d", len(runner.calls))
	}
}

func TestRemoveNamedTreatsCFInteractiveAbortAsNotRemoved(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[]}`},
		{stderr: "Aborted.\n"},
	}}
	client := newTestClient(t, runner)

	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		Confirm: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			SecretNames: []string{"VLESS_CREDENTIALS"},
		},
	})
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("error = %v, want ErrConfirmationRequired", err)
	}
	if result.WorkerRemoved {
		t.Fatal("aborted Worker was reported removed")
	}
	runner.assertDone(t)
	if !runner.calls[4].interactive || containsString(runner.calls[4].args, "--force") {
		t.Errorf("unsafe Worker delete call = %#v", runner.calls[4])
	}
}

func TestRemoveNamedFailsBeforeMutationsWithoutInteractiveTerminal(t *testing.T) {
	scripted := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
		{stdout: `{"result":[{"id":"` + testCertificatePack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`},
	}}
	client := newTestClient(t, nonInteractiveRunner{scripted})

	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		Confirm: true,
		Resources: NamedResources{
			Worker:          "cf-vless-edge",
			OwnershipMarker: testOwnershipMarker,
			Hostname:        "edge.example.com",
			ZoneID:          testZoneID,
			ZoneName:        "example.com",
			SecretNames:     []string{"VLESS_CREDENTIALS"},
		},
	})
	if !errors.Is(err, ErrInteractiveTerminalRequired) {
		t.Fatalf("error = %v, want ErrInteractiveTerminalRequired", err)
	}
	if result.WorkerRemoved || len(result.RemovedDomainIDs) != 0 || len(result.RemovedCertificatePackIDs) != 0 || len(result.RemovedSecrets) != 0 {
		t.Errorf("resources were reported removed: %#v", result)
	}
	scripted.assertDone(t)
}

func TestRemoveNamedRefusesUnplannedServiceDomainBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[{"id":"other-domain","hostname":"other.example.com","service":"cf-vless-edge","environment":"production"}]}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"},
		},
	})
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("error = %v, want ErrResourceConflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 3 {
		t.Fatalf("mutation was attempted after domain conflict: %#v", runner.calls)
	}
}

func TestRemoveNamedRefusesUnplannedSecretBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"},{"name":"UNRELATED","type":"secret_text"}]}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"},
		},
	})
	if !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("error = %v, want ErrResourceConflict", err)
	}
	runner.assertDone(t)
}

func TestRemoveNamedRefusesUnmanagedWorkerBindingBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name     string
		bindings string
	}{
		{
			name: "unknown binding",
			bindings: `[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker +
				`"},{"name":"UNRELATED_KV","type":"kv_namespace","namespace_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}]`,
		},
		{
			name: "managed name with wrong type",
			bindings: `[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker +
				`"},{"name":"EXPECTED_HOST","type":"secret_text"}]`,
		},
		{
			name: "duplicate managed binding",
			bindings: `[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker +
				`"},{"name":"EXPECTED_HOST","type":"plain_text","text":"edge.example.com"},` +
				`{"name":"EXPECTED_HOST","type":"plain_text","text":"other.example.com"}]`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, steps: []runStep{
				{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
				{stdout: `{"result":{"bindings":` + test.bindings + `}}`},
			}}
			client := newTestClient(t, runner)

			_, err := client.RemoveNamed(context.Background(), RemoveOptions{
				DryRun: true,
				Resources: NamedResources{
					Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
					SecretNames: []string{"VLESS_CREDENTIALS"},
				},
			})
			if !errors.Is(err, ErrResourceConflict) {
				t.Fatalf("error = %v, want ErrResourceConflict", err)
			}
			runner.assertDone(t)
			if len(runner.calls) != 2 {
				t.Fatalf("command ran after binding conflict: %#v", runner.calls)
			}
		})
	}
}

func TestRemoveNamedRefusesMalformedWorkerBindingInventoryBeforeMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"},42]}}`},
	}}
	client := newTestClient(t, runner)

	_, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			SecretNames: []string{"VLESS_CREDENTIALS"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "binding inventory") {
		t.Fatalf("error = %v, want binding-inventory decode refusal", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 2 {
		t.Fatalf("command ran after malformed binding response: %#v", runner.calls)
	}
}

func TestRemoveNamedRefusesMissingOrAmbiguousCertificatePackBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name  string
		packs string
	}{
		{name: "missing", packs: `{"result":[]}`},
		{name: "ambiguous", packs: `{"result":[
			{"id":"` + testCertificatePack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]},
			{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}
		]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := &scriptedRunner{t: t, steps: []runStep{
				{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
				{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
				{stdout: `{"result":[{"id":"` + testDomainID + `","cert_id":"` + testCertificateID + `","hostname":"edge.example.com","service":"cf-vless-edge","environment":"production"}]}`},
				{stdout: test.packs},
			}}
			client := newTestClient(t, runner)

			_, err := client.RemoveNamed(context.Background(), RemoveOptions{
				DryRun: true,
				Resources: NamedResources{
					Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
					Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
					SecretNames: []string{"VLESS_CREDENTIALS"},
				},
			})
			if err == nil || (!strings.Contains(err.Error(), "certificate pack") && !strings.Contains(err.Error(), "certificate packs")) {
				t.Fatalf("error = %v, want safe certificate-pack refusal", err)
			}
			runner.assertDone(t)
		})
	}
}

func TestCorrelateGeneratedCertificatePackAcceptsOnlyUUIDHexEquivalence(t *testing.T) {
	pack := CertificatePack{
		ID: "dddddddddddddddddddddddddddddddd", Type: "advanced", Hosts: []string{"edge.example.com"},
		Certificates: []CertificatePackCertificate{{
			ID: "9fdf92c864c24a3db1afe15304961145", Hosts: []string{"edge.example.com"},
		}},
	}
	selected, err := CorrelateGeneratedCertificatePack([]CertificatePack{pack}, testCertificateID, "edge.example.com")
	if err != nil || selected.ID != pack.ID {
		t.Fatalf("UUID/hex correlation = %#v, %v", selected, err)
	}
	pack.Certificates[0].ID = "certificate-alias"
	if _, err := CorrelateGeneratedCertificatePack([]CertificatePack{pack}, testCertificateID, "edge.example.com"); !errors.Is(err, ErrCertificatePackPending) {
		t.Fatalf("opaque certificate alias error = %v, want ErrCertificatePackPending", err)
	}
	pack.Certificates[0].ID = strings.ToUpper(strings.ReplaceAll(testCertificateID, "-", ""))
	if _, err := CorrelateGeneratedCertificatePack([]CertificatePack{pack}, testCertificateID, "edge.example.com"); err != nil {
		t.Fatalf("uppercase hex correlation failed: %v", err)
	}
}

func TestCorrelateNewGeneratedCertificatePackAcceptsObservedMultiSANPackAndCertAlias(t *testing.T) {
	preexistingID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	newPackID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	packs := []CertificatePack{
		{ID: preexistingID, Type: "advanced", Status: "active", Hosts: []string{"example.com", "*.example.com"},
			Certificates: []CertificatePackCertificate{{ID: "11111111-1111-4111-8111-111111111111", Hosts: []string{"example.com", "*.example.com"}}}},
		{ID: newPackID, Type: "advanced", Status: "active", Hosts: []string{"example.com", "*.example.com", "edge.example.com"},
			Certificates: []CertificatePackCertificate{
				{ID: "22222222-2222-4222-8222-222222222222", Hosts: []string{"example.com", "*.example.com", "edge.example.com"}},
				{ID: "33333333-3333-4333-8333-333333333333", Hosts: []string{"example.com", "*.example.com", "edge.example.com"}},
			}},
	}
	selected, err := CorrelateNewGeneratedCertificatePack(packs, []string{preexistingID}, "edge.example.com")
	if err != nil || selected.ID != newPackID {
		t.Fatalf("selected pack = %#v, %v", selected, err)
	}
	stored, err := SelectGeneratedCertificatePackByID(packs, newPackID, "edge.example.com")
	if err != nil || stored.ID != newPackID {
		t.Fatalf("stored pack = %#v, %v", stored, err)
	}
	if _, err := SelectGeneratedCertificatePackByID(packs, preexistingID, "edge.example.com"); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("unrelated stored pack error = %v, want ErrResourceConflict", err)
	}
}

func TestCorrelateNewGeneratedCertificatePackRejectsAmbiguousOrNoncoveringChildren(t *testing.T) {
	pack := CertificatePack{
		ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Type: "advanced", Status: "active",
		Hosts:        []string{"example.com", "edge.example.com"},
		Certificates: []CertificatePackCertificate{{ID: testCertificateID, Hosts: []string{"example.com"}}},
	}
	if _, err := CorrelateNewGeneratedCertificatePack([]CertificatePack{pack}, nil, "edge.example.com"); !errors.Is(err, ErrResourceConflict) {
		t.Fatalf("noncovering child error = %v, want ErrResourceConflict", err)
	}
	pack.Certificates[0].Hosts = []string{"example.com", "edge.example.com"}
	duplicate := pack
	duplicate.ID = "cccccccccccccccccccccccccccccccc"
	if _, err := CorrelateNewGeneratedCertificatePack([]CertificatePack{pack, duplicate}, nil, "edge.example.com"); err == nil {
		t.Fatal("ambiguous new packs were accepted")
	}
}

func TestRemoveNamedStoredPackAbsenceNeverSelectsReplacementExactPack(t *testing.T) {
	const replacementPack = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"result":{"bindings":[{"name":"DEPLOYMENT_MARKER","type":"plain_text","text":"` + testOwnershipMarker + `"}]}}`},
		{stdout: `{"result":[]}`},
		{stdout: `{"result":[{"id":"` + replacementPack + `","type":"advanced","hosts":["edge.example.com"],"certificates":[{"id":"` + testCertificateID + `","hosts":["edge.example.com"]}]}]}`},
		{stdout: `{"result":[{"name":"VLESS_CREDENTIALS","type":"secret_text"}]}`},
		{},
		{},
	}}
	client := newTestClient(t, runner)
	result, err := client.RemoveNamed(context.Background(), RemoveOptions{
		DryRun: true,
		Resources: NamedResources{
			Worker: "cf-vless-edge", OwnershipMarker: testOwnershipMarker,
			Hostname: "edge.example.com", ZoneID: testZoneID, ZoneName: "example.com",
			SecretNames: []string{"VLESS_CREDENTIALS"}, ExpectedDomainID: testDomainID, EnforceExpectedDomainID: true,
			ExpectedCertificatePackID: testCertificatePack, EnforceExpectedCertificatePackID: true,
		},
	})
	if err != nil {
		t.Fatalf("RemoveNamed: %v", err)
	}
	if len(result.Plan.CertificatePackIDs) != 0 {
		t.Fatalf("replacement pack entered removal plan: %#v", result.Plan)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(strings.Join(call.args, " "), "ssl certificate-packs delete") {
			t.Fatalf("replacement pack reached delete: %#v", call.args)
		}
	}
	runner.assertDone(t)
}

func TestDoctorReturnsStructuredReadOnlyHealth(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: "cf v0.2.0\n"},
		{stdout: "4.110.0\n"},
		{stdout: `{"loggedIn":true,"email":"discard@example.com","accounts":[{"id":"` + testAccountID + `","name":"Example"}],"tokenPermissions":["workers:read"]}`},
		{stdout: `{"authenticated":true,"tokenValid":true,"email":"discard@example.com"}`},
		{stdout: `{"result":[{"id":"` + testAccountID + `","name":"Example"}]}`},
		{stdout: `{"result":[{"id":"` + testZoneID + `","name":"example.com","status":"active","account":{"id":"` + testAccountID + `","name":"Example"}}]}`},
		{stdout: `{"result":[]}`},
	}}
	client := newTestClient(t, runner)

	result, err := client.Doctor(context.Background(), DoctorOptions{
		AccountID: testAccountID,
		ZoneName:  "example.com",
	})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if !result.Healthy || !result.Auth.Authenticated || !result.Auth.TokenValid ||
		!result.WranglerAuth.LoggedIn || !result.WranglerAuth.AccountAccessible || len(result.Accounts) != 1 || len(result.Zones) != 1 {
		t.Errorf("doctor result = %#v", result)
	}
	if result.CFVersion != "0.2.0" || result.WranglerVersion != "4.110.0" {
		t.Errorf("versions = %q / %q", result.CFVersion, result.WranglerVersion)
	}

	runner.assertDone(t)
	assertCall(t, runner.calls[0], "cf", "", []string{"--version"})
	assertCall(t, runner.calls[1], "npx", testProject, []string{"--no-install", "wrangler", "--version"})
	assertCall(t, runner.calls[2], "npx", testProject, []string{"--no-install", "wrangler", "whoami", "--json"})
	assertCall(t, runner.calls[3], "cf", "", []string{"auth", "whoami"})
	assertCall(t, runner.calls[4], "cf", "", []string{"accounts", "list"})
	assertCall(t, runner.calls[5], "cf", "", []string{"zones", "list", "--name", "example.com", "--account-id", testAccountID})
	assertCall(t, runner.calls[6], "cf", "", []string{"ssl", "certificate-packs", "list", "--status", "all", "--page", "1", "--per-page", "50", "--zone", testZoneID})
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call.args, " "), "delete") || strings.Contains(strings.Join(call.args, " "), "deploy") {
			t.Errorf("doctor issued a mutation command: %#v", call.args)
		}
	}
}

func TestDoctorFailsWhenWranglerCannotAccessConfiguredAccount(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: "cf v0.2.0\n"},
		{stdout: "4.110.0\n"},
		{stdout: `{"loggedIn":true,"email":"discard@example.com","accounts":[{"id":"ffffffffffffffffffffffffffffffff","name":"Other"}]}`},
		{stdout: `{"authenticated":true,"tokenValid":true}`},
		{stdout: `{"result":[{"id":"` + testAccountID + `","name":"Example"}]}`},
	}}
	client := newTestClient(t, runner)

	result, err := client.Doctor(context.Background(), DoctorOptions{AccountID: testAccountID})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if result.Healthy || !result.WranglerAuth.LoggedIn || result.WranglerAuth.AccountAccessible {
		t.Fatalf("doctor result = %#v", result)
	}
	var accountCheck *DoctorCheck
	for i := range result.Checks {
		if result.Checks[i].Name == "wrangler.account_access" {
			accountCheck = &result.Checks[i]
			break
		}
	}
	if accountCheck == nil || accountCheck.Status != CheckFail || !accountCheck.Required {
		t.Fatalf("Wrangler account check = %#v", accountCheck)
	}
	runner.assertDone(t)
}

func TestDoctorFailsWhenCertificateInventoryPermissionIsMissing(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: "cf v0.2.0\n"},
		{stdout: "4.110.0\n"},
		{stdout: `{"loggedIn":true,"accounts":[{"id":"` + testAccountID + `"}]}`},
		{stdout: `{"authenticated":true,"tokenValid":true}`},
		{stdout: `{"result":[{"id":"` + testAccountID + `","name":"Example"}]}`},
		{stdout: `{"result":[{"id":"` + testZoneID + `","name":"example.com","status":"active","account":{"id":"` + testAccountID + `"}}]}`},
		{stderr: "permission denied", exitCode: 1, err: errors.New("exit status 1")},
	}}
	client := newTestClient(t, runner)
	result, err := client.Doctor(context.Background(), DoctorOptions{AccountID: testAccountID, ZoneName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Healthy {
		t.Fatal("doctor accepted missing certificate inventory permission")
	}
	found := false
	for _, check := range result.Checks {
		if check.Name == "cf.certificate_access" {
			found = check.Required && check.Status == CheckFail
		}
	}
	if !found {
		t.Fatalf("certificate access failure missing from %#v", result.Checks)
	}
	runner.assertDone(t)
}
