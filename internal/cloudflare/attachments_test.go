package cloudflare

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const managedScriptInventory = `[{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":false,"has_assets":false}]`

func TestValidateWorkerAttachmentsUsesEveryReadOnlySurface(t *testing.T) {
	runner := &scriptedRunner{t: t, scriptAttachmentChecks: true, steps: []runStep{
		{stdout: `{"schedules":[]}`},
		{stdout: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":{"enabled":false,"head_sampling_rate":0,"logs":{"enabled":false,"head_sampling_rate":0,"invocation_logs":false,"persist":false},"traces":{"enabled":false,"head_sampling_rate":0,"persist":false}}}`},
		{stdout: `{"enabled":false,"previews_enabled":false}`},
	}}
	client := newTestClient(t, runner)

	operations, err := client.validateWorkerAttachments(context.Background(), "cf-vless-edge", managedScriptInventory)
	if err != nil {
		t.Fatalf("validateWorkerAttachments: %v", err)
	}
	if len(operations) != 3 {
		t.Fatalf("operations = %#v", operations)
	}
	runner.assertDone(t)
	wants := [][]string{
		{"workers", "scripts", "schedules", "get", "--worker", "cf-vless-edge"},
		{"workers", "scripts", "settings", "get", "--worker", "cf-vless-edge"},
		{"workers", "scripts", "subdomain", "get", "--worker", "cf-vless-edge"},
	}
	for index, want := range wants {
		if !reflect.DeepEqual(runner.calls[index].args, want) {
			t.Errorf("call %d = %#v, want %#v", index, runner.calls[index].args, want)
		}
		if runner.calls[index].interactive || containsString(runner.calls[index].args, "--dry-run") {
			t.Errorf("read-only attachment call = %#v", runner.calls[index])
		}
	}
}

func TestValidateScriptListAttachmentsFailsClosed(t *testing.T) {
	tests := map[string]string{
		"route":          `[{"id":"cf-vless-edge","routes":[{"pattern":"example.com/*"}],"tail_consumers":null,"logpush":false,"has_assets":false}]`,
		"tail consumer":  `[{"id":"cf-vless-edge","routes":null,"tail_consumers":["sink"],"logpush":false,"has_assets":false}]`,
		"Logpush":        `[{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":true,"has_assets":false}]`,
		"assets":         `[{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":false,"has_assets":true}]`,
		"missing field":  `[{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":false}]`,
		"duplicate item": managedScriptInventory[:len(managedScriptInventory)-1] + `,{"id":"cf-vless-edge","routes":null,"tail_consumers":null,"logpush":false,"has_assets":false}]`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateScriptListAttachments(input, "cf-vless-edge")
			if !errors.Is(err, ErrResourceConflict) {
				t.Fatalf("error = %v, want resource conflict", err)
			}
		})
	}
}

func TestAttachmentResponseValidatorsFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		validate func(string) error
		input    string
	}{
		{name: "Cron", validate: validateEmptySchedules, input: `{"schedules":[{"cron":"* * * * *"}]}`},
		{name: "missing Cron container", validate: validateEmptySchedules, input: `{}`},
		{name: "settings Logpush", validate: validateScriptSettings, input: `{"logpush":true,"tail_consumers":null,"tags":[],"observability":null}`},
		{name: "settings tail", validate: validateScriptSettings, input: `{"logpush":false,"tail_consumers":[{"service":"sink"}],"tags":[],"observability":null}`},
		{name: "settings tags", validate: validateScriptSettings, input: `{"logpush":false,"tail_consumers":null,"tags":["user-added"],"observability":null}`},
		{name: "settings observability", validate: validateScriptSettings, input: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":{"enabled":true}}`},
		{name: "settings sampling", validate: validateScriptSettings, input: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":{"enabled":false,"head_sampling_rate":0.1}}`},
		{name: "settings unknown", validate: validateScriptSettings, input: `{"logpush":false,"tail_consumers":null,"tags":[],"observability":null,"new_attachment":false}`},
		{name: "workers dev", validate: validateDisabledSubdomain, input: `{"enabled":true,"previews_enabled":false}`},
		{name: "preview", validate: validateDisabledSubdomain, input: `{"enabled":false,"previews_enabled":true}`},
		{name: "trailing JSON", validate: validateDisabledSubdomain, input: `{"enabled":false,"previews_enabled":false}{}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate(test.input); err == nil {
				t.Fatal("validator accepted an unsafe or malformed attachment response")
			}
		})
	}

	for _, input := range []string{
		`{"logpush":false,"tail_consumers":null,"tags":[],"observability":null}`,
		`{"logpush":false,"tail_consumers":[],"tags":null,"observability":{"enabled":false,"logs":{"enabled":false,"head_sampling_rate":0,"invocation_logs":false},"traces":{"enabled":false,"persist":false}}}`,
	} {
		if err := validateScriptSettings(input); err != nil {
			t.Errorf("safe settings rejected: %v", err)
		}
	}
	if err := validateEmptySchedules(`{"schedules":[]}`); err != nil {
		t.Errorf("empty schedules rejected: %v", err)
	}
	if err := validateDisabledSubdomain(`{"enabled":false,"previews_enabled":false}`); err != nil {
		t.Errorf("disabled subdomain rejected: %v", err)
	}
}

func TestAttachmentCommandFailureStopsInventory(t *testing.T) {
	runner := &scriptedRunner{t: t, scriptAttachmentChecks: true, steps: []runStep{{stderr: "denied", exitCode: 1, err: errors.New("denied")}}}
	client := newTestClient(t, runner)
	operations, err := client.validateWorkerAttachments(context.Background(), "cf-vless-edge", managedScriptInventory)
	if err == nil || !strings.Contains(err.Error(), "denied") || len(operations) != 1 {
		t.Fatalf("operations/error = %#v / %v", operations, err)
	}
	runner.assertDone(t)
}

func TestWorkerStatusRefusesScriptAttachmentBeforeFurtherReads(t *testing.T) {
	runner := &scriptedRunner{t: t, steps: []runStep{{stdout: `[{"id":"cf-vless-edge","routes":[{"pattern":"edge.example.com/*"}],"tail_consumers":null,"logpush":false,"has_assets":false}]`}}}
	client := newTestClient(t, runner)

	_, err := client.WorkerStatus(context.Background(), "cf-vless-edge")
	if !errors.Is(err, ErrResourceConflict) || !strings.Contains(err.Error(), "routes") {
		t.Fatalf("error = %v, want route-attachment conflict", err)
	}
	runner.assertDone(t)
	if len(runner.calls) != 1 {
		t.Fatalf("status continued after script-list attachment: %#v", runner.calls)
	}
}

func TestRemoveNamedRefusesCronBeforeOwnershipOrMutation(t *testing.T) {
	runner := &scriptedRunner{t: t, scriptAttachmentChecks: true, steps: []runStep{
		{stdout: `{"result":[` + testManagedScriptInventoryItem + `]}`},
		{stdout: `{"schedules":[{"cron":"* * * * *"}]}`},
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
	if !errors.Is(err, ErrResourceConflict) || !strings.Contains(err.Error(), "Cron") {
		t.Fatalf("error = %v, want Cron-attachment conflict", err)
	}
	runner.assertDone(t)
	for _, call := range runner.calls {
		if containsString(call.args, "delete") || call.interactive {
			t.Fatalf("attachment conflict reached a mutation: %#v", call)
		}
	}
}
