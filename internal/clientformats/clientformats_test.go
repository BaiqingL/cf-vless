package clientformats

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/BaiqingL/cf-vless/internal/config"
)

const (
	currentUUID  = "27848739-7e62-4138-9fd3-098a63964b6b"
	previousUUID = "550e8400-e29b-41d4-a716-446655440000"
)

func deployment() config.Deployment {
	return config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		AccountID:       "0123456789abcdef0123456789abcdef",
		ZoneID:          "fedcba9876543210fedcba9876543210",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     `My Edge: "東京" #1`,
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{
			Current: config.Credential{UUID: currentUUID, Path: "/random-path-0001"},
			Previous: &config.PreviousCredential{
				Credential: config.Credential{UUID: previousUUID, Path: "/previous-path-01"},
				ExpiresAt:  time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC),
			},
		},
	}
}

func TestVLESSURIUsesExactComponentEncoding(t *testing.T) {
	cfg := deployment()
	got, err := VLESSURI(cfg)
	if err != nil {
		t.Fatalf("VLESSURI() error = %v", err)
	}
	want := "vless://" + currentUUID + "@edge.example.com:443" +
		"?encryption=none&security=tls&type=ws&host=edge.example.com&path=%2Frandom-path-0001&sni=edge.example.com" +
		"#My%20Edge%3A%20%22%E6%9D%B1%E4%BA%AC%22%20%231"
	if got != want {
		t.Fatalf("VLESSURI() =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "+") {
		t.Fatalf("VLESSURI() uses form-style plus encoding: %s", got)
	}
	if strings.Contains(got, previousUUID) {
		t.Fatal("VLESSURI() exposed the previous credential")
	}

	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if parsed.Scheme != "vless" || parsed.User.Username() != currentUUID || parsed.Hostname() != cfg.Hostname || parsed.Port() != "443" {
		t.Fatalf("parsed URI authority = %#v", parsed)
	}
	query := parsed.Query()
	if len(query) != 6 || query.Get("encryption") != "none" || query.Get("security") != "tls" || query.Get("type") != "ws" || query.Get("host") != cfg.Hostname || query.Get("path") != cfg.Credentials.Current.Path || query.Get("sni") != cfg.Hostname {
		t.Fatalf("parsed query = %#v", query)
	}
	if parsed.Fragment != cfg.DisplayName {
		t.Fatalf("parsed fragment = %q, want %q", parsed.Fragment, cfg.DisplayName)
	}
}

func TestXrayJSONUsesCurrentCanonicalShape(t *testing.T) {
	got, err := XrayJSON(deployment())
	if err != nil {
		t.Fatalf("XrayJSON() error = %v", err)
	}
	want := `{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 1080,
      "protocol": "socks",
      "settings": {
        "udp": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "address": "edge.example.com",
        "port": 443,
        "id": "27848739-7e62-4138-9fd3-098a63964b6b",
        "encryption": "none"
      },
      "streamSettings": {
        "method": "websocket",
        "security": "tls",
        "tlsSettings": {
          "serverName": "edge.example.com"
        },
        "wsSettings": {
          "path": "/random-path-0001",
          "host": "edge.example.com"
        }
      }
    }
  ]
}
`
	if string(got) != want {
		t.Fatalf("XrayJSON() =\n%s\nwant\n%s", got, want)
	}
	assertValidJSON(t, got)
	for _, forbidden := range []string{`"vnext"`, `"allowInsecure"`, `"flow"`, previousUUID} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Fatalf("XrayJSON() contains forbidden value %q", forbidden)
		}
	}
}

func TestSingBoxJSONUsesSystemWideChinaDirectPolicy(t *testing.T) {
	got, err := SingBoxJSON(deployment())
	if err != nil {
		t.Fatalf("SingBoxJSON() error = %v", err)
	}
	assertValidJSON(t, got)
	var document map[string]any
	if err := json.Unmarshal(got, &document); err != nil {
		t.Fatal(err)
	}
	dns := document["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	dnsServer := servers[0].(map[string]any)
	if dns["final"] != "china-dns" || dns["strategy"] != "prefer_ipv4" || len(servers) != 1 || dnsServer["type"] != "https" ||
		dnsServer["server"] != singBoxChinaDNSIP || dnsServer["server_port"] != float64(443) || dnsServer["path"] != "/dns-query" ||
		dnsServer["tls"].(map[string]any)["server_name"] != singBoxChinaDNSName || dnsServer["tls"].(map[string]any)["insecure"] != false {
		t.Fatalf("sing-box DNS policy = %#v", dns)
	}
	inbounds := document["inbounds"].([]any)
	tun := inbounds[0].(map[string]any)
	addresses := tun["address"].([]any)
	if len(inbounds) != 1 || tun["type"] != "tun" || tun["tag"] != "tun-in" || tun["auto_route"] != true || tun["strict_route"] != true ||
		len(addresses) != 2 || addresses[0] != singBoxTUNIPv4CIDR || addresses[1] != singBoxTUNIPv6CIDR {
		t.Fatalf("sing-box TUN inbound = %#v", tun)
	}
	outbounds := document["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	direct := outbounds[1].(map[string]any)
	if len(outbounds) != 2 || proxy["type"] != "vless" || proxy["tag"] != "proxy" || proxy["network"] != "tcp" || proxy["domain_resolver"] != "china-dns" ||
		direct["type"] != "direct" || direct["tag"] != "direct" {
		t.Fatalf("sing-box outbounds = %#v", outbounds)
	}
	proxyTLS := proxy["tls"].(map[string]any)
	proxyTransport := proxy["transport"].(map[string]any)
	if proxyTLS["enabled"] != true || proxyTLS["server_name"] != "edge.example.com" || proxyTLS["insecure"] != false ||
		proxyTransport["type"] != "ws" || proxyTransport["path"] != "/random-path-0001" ||
		proxyTransport["headers"].(map[string]any)["Host"] != "edge.example.com" {
		t.Fatalf("sing-box secure transport = tls:%#v transport:%#v", proxyTLS, proxyTransport)
	}
	route := document["route"].(map[string]any)
	if route["final"] != "proxy" || route["auto_detect_interface"] != true || route["default_domain_resolver"].(map[string]any)["server"] != "china-dns" {
		t.Fatalf("sing-box route defaults = %#v", route)
	}
	rules := route["rules"].([]any)
	if len(rules) != 8 || rules[0].(map[string]any)["action"] != "sniff" ||
		rules[1].(map[string]any)["protocol"] != "dns" || rules[1].(map[string]any)["action"] != "hijack-dns" ||
		rules[2].(map[string]any)["ip_is_private"] != true || rules[2].(map[string]any)["outbound"] != "direct" ||
		rules[3].(map[string]any)["action"] != "resolve" || rules[3].(map[string]any)["server"] != "china-dns" ||
		rules[4].(map[string]any)["ip_is_private"] != true || rules[4].(map[string]any)["outbound"] != "direct" ||
		rules[5].(map[string]any)["rule_set"] != "geoip-cn" || rules[5].(map[string]any)["outbound"] != "direct" ||
		rules[6].(map[string]any)["network"] != "udp" || rules[6].(map[string]any)["action"] != "reject" ||
		rules[7].(map[string]any)["network"] != "icmp" || rules[7].(map[string]any)["action"] != "reject" {
		t.Fatalf("sing-box route rules = %#v", rules)
	}
	ruleSets := route["rule_set"].([]any)
	china := ruleSets[0].(map[string]any)
	if len(ruleSets) != 1 || china["tag"] != "geoip-cn" || china["format"] != "binary" || china["url"] != singBoxGeoIPCNURL || china["download_detour"] != "proxy" {
		t.Fatalf("sing-box China rule set = %#v", china)
	}
	cache := document["experimental"].(map[string]any)["cache_file"].(map[string]any)
	if cache["enabled"] != true {
		t.Fatalf("sing-box cache policy = %#v", cache)
	}
	for _, forbidden := range []string{`"flow"`, `"packet_encoding"`, `"multiplex"`, previousUUID} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Fatalf("SingBoxJSON() contains forbidden value %q", forbidden)
		}
	}
}

func TestSingBoxIntegrationJSONKeepsMixedInboundAndRoutingPolicy(t *testing.T) {
	got, err := SingBoxJSONWithLocalPort(deployment(), 19080)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(got, &document); err != nil {
		t.Fatal(err)
	}
	inbound := document["inbounds"].([]any)[0].(map[string]any)
	if inbound["type"] != "mixed" || inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != float64(19080) {
		t.Fatalf("sing-box integration inbound = %#v", inbound)
	}
	if document["route"].(map[string]any)["final"] != "proxy" || len(document["outbounds"].([]any)) != 2 {
		t.Fatalf("sing-box integration policy = %#v", document["route"])
	}
}

func TestMihomoYAMLEscapesDisplayNameAndDisablesUDP(t *testing.T) {
	got, err := MihomoYAML(deployment())
	if err != nil {
		t.Fatalf("MihomoYAML() error = %v", err)
	}
	want := `mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning

proxies:
  - name: "My Edge: \"東京\" #1"
    type: vless
    server: "edge.example.com"
    port: 443
    uuid: "27848739-7e62-4138-9fd3-098a63964b6b"
    udp: false
    tls: true
    servername: "edge.example.com"
    skip-cert-verify: false
    network: ws
    encryption: ""
    ws-opts:
      path: "/random-path-0001"
      headers:
        Host: "edge.example.com"

proxy-groups:
  - name: "CF-VLESS"
    type: select
    proxies:
      - "My Edge: \"東京\" #1"

rules:
  - "MATCH,CF-VLESS"
`
	if string(got) != want {
		t.Fatalf("MihomoYAML() =\n%s\nwant\n%s", got, want)
	}
	for _, required := range []string{"udp: false", "skip-cert-verify: false", "network: ws", `encryption: ""`} {
		if !bytes.Contains(got, []byte(required)) {
			t.Fatalf("MihomoYAML() missing %q", required)
		}
	}
	if bytes.Contains(got, []byte(previousUUID)) {
		t.Fatal("MihomoYAML() exposed the previous credential")
	}
}

func TestMihomoYAMLAvoidsProxyGroupNameCollision(t *testing.T) {
	cfg := deployment()
	cfg.DisplayName = "CF-VLESS"
	got, err := MihomoYAML(cfg)
	if err != nil {
		t.Fatalf("MihomoYAML() error = %v", err)
	}
	if !bytes.Contains(got, []byte(`name: "CF-VLESS-SELECT"`)) || !bytes.Contains(got, []byte(`"MATCH,CF-VLESS-SELECT"`)) {
		t.Fatalf("MihomoYAML() did not avoid group collision:\n%s", got)
	}
}

func TestGenerateReturnsAllFormatsAndRejectsInvalidConfig(t *testing.T) {
	cfg := deployment()
	outputs, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if outputs.VLESSURI == "" || len(outputs.QRCodePNG) == 0 || len(outputs.XrayJSON) == 0 || len(outputs.SingBoxJSON) == 0 || len(outputs.SingBoxQRCodeGIF) == 0 || len(outputs.MihomoYAML) == 0 {
		t.Fatalf("Generate() returned an empty artifact: %#v", outputs)
	}
	for _, artifact := range [][]byte{[]byte(outputs.VLESSURI), outputs.QRCodePNG, outputs.XrayJSON, outputs.SingBoxJSON, outputs.SingBoxQRCodeGIF, outputs.MihomoYAML} {
		if bytes.Contains(artifact, []byte(previousUUID)) {
			t.Fatal("Generate() exposed previous credential")
		}
		for _, metadata := range []string{cfg.AccountID, cfg.ZoneID, cfg.WorkerName} {
			if bytes.Contains(artifact, []byte(metadata)) {
				t.Fatalf("Generate() exposed deployment metadata %q", metadata)
			}
		}
	}

	cfg.Port = 80
	if _, err := Generate(cfg); err == nil {
		t.Fatal("Generate() accepted invalid canonical config")
	}
}

func assertValidJSON(t *testing.T, data []byte) {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}
