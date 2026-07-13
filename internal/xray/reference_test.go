package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validLocalReferenceOptions() LocalReferenceOptions {
	return LocalReferenceOptions{
		UUID:          "27848739-7e62-4138-9fd3-098a63964b6b",
		WebSocketPath: "/local-reference-01",
		ServerPort:    18081,
		SOCKSPort:     18080,
	}
}

func TestMarshalLocalReferenceConfigsUsesVLESSWebSocketWithoutTLS(t *testing.T) {
	t.Parallel()

	configs, err := MarshalLocalReferenceConfigs(validLocalReferenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{"server": configs.ServerJSON, "client": configs.ClientJSON} {
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatalf("%s config: %v", name, err)
		}
		inbounds := document["inbounds"].([]any)
		outbounds := document["outbounds"].([]any)
		if len(inbounds) != 1 || len(outbounds) != 1 {
			t.Fatalf("%s config has unexpected topology", name)
		}
		if document["log"].(map[string]any)["loglevel"] != "none" {
			t.Fatalf("%s config enables process logging", name)
		}
		if inbounds[0].(map[string]any)["listen"] != "127.0.0.1" {
			t.Fatalf("%s inbound is not loopback-only", name)
		}
	}
	var server map[string]any
	if err := json.Unmarshal(configs.ServerJSON, &server); err != nil {
		t.Fatal(err)
	}
	serverInbound := server["inbounds"].([]any)[0].(map[string]any)
	if serverInbound["protocol"] != "vless" {
		t.Fatalf("server inbound = %#v", serverInbound)
	}
	serverStream := serverInbound["streamSettings"].(map[string]any)
	if serverStream["method"] != "websocket" || serverStream["security"] != "none" {
		t.Fatalf("server stream = %#v", serverStream)
	}
	serverOutbound := server["outbounds"].([]any)[0].(map[string]any)
	serverSettings := serverOutbound["settings"].(map[string]any)
	if serverSettings["targetStrategy"] != "UseIPv4" {
		t.Fatal("server does not resolve its static domain mapping before loopback policy")
	}
	finalRules := serverSettings["finalRules"].([]any)
	if len(finalRules) != 2 {
		t.Fatalf("server final rules = %#v", finalRules)
	}
	allowLoopback := finalRules[0].(map[string]any)
	loopbackIPs := allowLoopback["ip"].([]any)
	if allowLoopback["action"] != "allow" || allowLoopback["network"] != "tcp" ||
		len(loopbackIPs) != 2 || loopbackIPs[0] != "127.0.0.1/32" || loopbackIPs[1] != "::1/128" {
		t.Fatalf("server loopback rule = %#v", allowLoopback)
	}
	terminalRule := finalRules[1].(map[string]any)
	if terminalRule["action"] != "block" || len(terminalRule) != 1 {
		t.Fatalf("server terminal rule = %#v", terminalRule)
	}
	dnsConfig := server["dns"].(map[string]any)
	if dnsConfig["queryStrategy"] != "UseIPv4" {
		t.Fatal("server static DNS mapping is not IPv4-only")
	}
	hosts := dnsConfig["hosts"].(map[string]any)
	if len(hosts) != 1 || hosts["example.com"] != "127.0.0.1" {
		t.Fatal("server domain capture is not pinned to IPv4 loopback")
	}
	var client map[string]any
	if err := json.Unmarshal(configs.ClientJSON, &client); err != nil {
		t.Fatal(err)
	}
	clientOutbound := client["outbounds"].([]any)[0].(map[string]any)
	if clientOutbound["protocol"] != "vless" {
		t.Fatalf("client outbound = %#v", clientOutbound)
	}
	clientStream := clientOutbound["streamSettings"].(map[string]any)
	if clientStream["method"] != "websocket" || clientStream["security"] != "none" {
		t.Fatalf("client stream = %#v", clientStream)
	}
	if _, exists := clientStream["tlsSettings"]; exists {
		t.Fatal("local reference config unexpectedly enables TLS")
	}
	if clientOutbound["settings"].(map[string]any)["address"] != "127.0.0.1" {
		t.Fatal("local reference client does not target loopback")
	}
	if clientOutbound["settings"].(map[string]any)["port"] != float64(validLocalReferenceOptions().ServerPort) {
		t.Fatal("local reference client does not default to the server port")
	}
}

func TestMarshalLocalReferenceConfigsSupportsLoopbackCaptureProxy(t *testing.T) {
	t.Parallel()

	options := validLocalReferenceOptions()
	options.ClientTargetPort = 18082
	configs, err := MarshalLocalReferenceConfigs(options)
	if err != nil {
		t.Fatal(err)
	}
	var client map[string]any
	if err := json.Unmarshal(configs.ClientJSON, &client); err != nil {
		t.Fatal(err)
	}
	clientOutbound := client["outbounds"].([]any)[0].(map[string]any)
	if clientOutbound["settings"].(map[string]any)["port"] != float64(options.ClientTargetPort) {
		t.Fatal("local reference client does not target the capture proxy")
	}
}

func TestWriteLocalReferenceConfigsUsesPrivateFiles(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "reference")
	paths, err := WriteLocalReferenceConfigs(directory, validLocalReferenceOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.ServerPath, paths.ClientPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode for %s = %o", filepath.Base(path), info.Mode().Perm())
		}
	}
}

func TestLocalReferenceOptionsRejectUnsafeOrAmbiguousValues(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*LocalReferenceOptions){
		"uuid":       func(options *LocalReferenceOptions) { options.UUID = "invalid" },
		"path":       func(options *LocalReferenceOptions) { options.WebSocketPath = "/short" },
		"port":       func(options *LocalReferenceOptions) { options.ServerPort = 0 },
		"same ports": func(options *LocalReferenceOptions) { options.SOCKSPort = options.ServerPort },
		"proxy is socks": func(options *LocalReferenceOptions) {
			options.ClientTargetPort = options.SOCKSPort
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			options := validLocalReferenceOptions()
			mutate(&options)
			if _, err := MarshalLocalReferenceConfigs(options); err == nil {
				t.Fatal("invalid reference options were accepted")
			}
		})
	}
}
