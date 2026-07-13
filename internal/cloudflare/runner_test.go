package cloudflare

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestExecRunnerNeverPassesGlobalAPIKeysToChildren(t *testing.T) {
	const first = "global-key-must-not-reach-child"
	const second = "legacy-key-must-not-reach-child"
	t.Setenv("CLOUDFLARE_GLOBAL_TOKEN", first)
	t.Setenv("CLOUDFLARE_API_KEY", second)
	t.Setenv("CF_VLESS_ENV_TEST", "visible")
	program, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env executable is unavailable")
	}
	result, err := (ExecRunner{}).Run(context.Background(), Command{Program: program})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Stdout, first) || strings.Contains(result.Stdout, second) ||
		strings.Contains(result.Stdout, "CLOUDFLARE_GLOBAL_TOKEN=") || strings.Contains(result.Stdout, "CLOUDFLARE_API_KEY=") {
		t.Fatal("Global API Key reached a child process")
	}
	if !strings.Contains(result.Stdout, "CF_VLESS_ENV_TEST=visible") {
		t.Fatal("unrelated environment was removed")
	}
}

func TestCommandOverrideCannotReintroduceGlobalAPIKey(t *testing.T) {
	const key = "command-key-must-not-reach-child"
	program, err := exec.LookPath("env")
	if err != nil {
		t.Skip("env executable is unavailable")
	}
	command := Command{Program: program}.withEnvironment("Cloudflare_Api_Key=" + key)
	result, err := (ExecRunner{}).Run(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Stdout, key) || strings.Contains(strings.ToLower(result.Stdout), "cloudflare_api_key=") {
		t.Fatal("command override reintroduced a Global API Key")
	}
}
