package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validClientConfig() ClientConfig {
	return ClientConfig{
		Endpoint: Endpoint{
			Hostname: "edge.example.com",
			Port:     443,
			UUID:     "00112233-4455-4677-8899-aabbccddeeff",
			Path:     "/abcdefghijklmnop",
		},
		SOCKSHost: "127.0.0.1",
		SOCKSPort: 19080,
	}
}

func TestMarshalClientConfigUsesPinnedCanonicalShape(t *testing.T) {
	t.Parallel()

	encoded, err := MarshalClientConfig(validClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	outbounds := document["outbounds"].([]any)
	outbound := outbounds[0].(map[string]any)
	settings := outbound["settings"].(map[string]any)
	if settings["address"] != "edge.example.com" || settings["encryption"] != "none" {
		t.Fatalf("settings = %#v", settings)
	}
	stream := outbound["streamSettings"].(map[string]any)
	if stream["method"] != "websocket" || stream["security"] != "tls" {
		t.Fatalf("stream = %#v", stream)
	}
	if _, exists := stream["network"]; exists {
		t.Fatal("legacy streamSettings.network must not be generated")
	}
	ws := stream["wsSettings"].(map[string]any)
	if ws["host"] != "edge.example.com" || ws["path"] != "/abcdefghijklmnop" {
		t.Fatalf("ws = %#v", ws)
	}
}

func TestWriteClientConfigIsPrivate(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "private", "config.json")
	if err := WriteClientConfig(path, validClientConfig()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestClientConfigRejectsInvalidCredentialAndListener(t *testing.T) {
	t.Parallel()

	config := validClientConfig()
	config.Endpoint.UUID = "not-a-uuid"
	if _, err := MarshalClientConfig(config); err == nil {
		t.Fatal("invalid UUID was accepted")
	}
	config = validClientConfig()
	config.SOCKSHost = "0.0.0.0"
	if _, err := MarshalClientConfig(config); err == nil {
		t.Fatal("non-loopback SOCKS listener was accepted")
	}
}
