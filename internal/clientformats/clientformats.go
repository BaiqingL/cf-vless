// Package clientformats renders the four supported client configuration
// formats from canonical deployment state.
package clientformats

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/BaiqingL/cf-vless/internal/config"
)

const (
	localSOCKSPort      = 1080
	mihomoPort          = 7890
	singBoxGeoIPCNURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
	singBoxChinaDNSIP   = "223.5.5.5"
	singBoxChinaDNSName = "dns.alidns.com"
	singBoxTUNIPv4CIDR  = "172.19.0.1/30"
	singBoxTUNIPv6CIDR  = "fdfe:dcba:9876::1/126"
)

// Outputs contains every supported client artifact. VLESSURI and every byte
// slice contain the current UUID and must be treated as secrets.
type Outputs struct {
	VLESSURI    string
	QRCodePNG   []byte
	XrayJSON    []byte
	SingBoxJSON []byte
	MihomoYAML  []byte
}

// Generate renders all client artifacts from the current credential only.
func Generate(deployment config.Deployment) (Outputs, error) {
	if err := deployment.Validate(); err != nil {
		return Outputs{}, err
	}
	uri, err := VLESSURI(deployment)
	if err != nil {
		return Outputs{}, err
	}
	qrCode, err := QRCodePNG(deployment)
	if err != nil {
		return Outputs{}, err
	}
	xray, err := XrayJSON(deployment)
	if err != nil {
		return Outputs{}, err
	}
	singBox, err := SingBoxJSON(deployment)
	if err != nil {
		return Outputs{}, err
	}
	mihomo, err := MihomoYAML(deployment)
	if err != nil {
		return Outputs{}, err
	}
	return Outputs{
		VLESSURI:    uri,
		QRCodePNG:   qrCode,
		XrayJSON:    xray,
		SingBoxJSON: singBox,
		MihomoYAML:  mihomo,
	}, nil
}

// VLESSURI returns an Xray-style VLESS share URI suitable for manual
// Shadowrocket import verification. Query and fragment values use strict URI
// component percent encoding, not HTML form encoding.
func VLESSURI(deployment config.Deployment) (string, error) {
	if err := deployment.Validate(); err != nil {
		return "", err
	}
	credential := deployment.Credentials.Current
	var uri strings.Builder
	uri.Grow(160 + len(deployment.DisplayName))
	uri.WriteString("vless://")
	uri.WriteString(credential.UUID)
	uri.WriteByte('@')
	uri.WriteString(deployment.Hostname)
	uri.WriteByte(':')
	uri.WriteString(strconv.Itoa(int(deployment.Port)))
	uri.WriteString("?encryption=none&security=tls&type=ws&host=")
	uri.WriteString(escapeComponent(deployment.Hostname))
	uri.WriteString("&path=")
	uri.WriteString(escapeComponent(credential.Path))
	uri.WriteString("&sni=")
	uri.WriteString(escapeComponent(deployment.Hostname))
	uri.WriteByte('#')
	uri.WriteString(escapeComponent(deployment.DisplayName))
	return uri.String(), nil
}

func escapeComponent(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(len(value))
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'a' && current <= 'z' || current >= 'A' && current <= 'Z' || current >= '0' && current <= '9' || current == '-' || current == '.' || current == '_' || current == '~' {
			escaped.WriteByte(current)
			continue
		}
		escaped.WriteByte('%')
		escaped.WriteByte(hexadecimal[current>>4])
		escaped.WriteByte(hexadecimal[current&0x0f])
	}
	return escaped.String()
}

// XrayJSON renders the current v26.7.11 canonical flat VLESS settings and
// streamSettings.method form.
func XrayJSON(deployment config.Deployment) ([]byte, error) {
	return XrayJSONWithLocalPort(deployment, localSOCKSPort)
}

// XrayJSONWithLocalPort renders the shipped Xray format with a caller-selected
// loopback port for executable integration tests.
func XrayJSONWithLocalPort(deployment config.Deployment, localPort uint16) ([]byte, error) {
	if err := deployment.Validate(); err != nil {
		return nil, err
	}
	if localPort == 0 {
		return nil, errors.New("Xray local port is invalid")
	}
	type logConfig struct {
		LogLevel string `json:"loglevel"`
	}
	type socksSettings struct {
		UDP bool `json:"udp"`
	}
	type inbound struct {
		Tag      string        `json:"tag"`
		Listen   string        `json:"listen"`
		Port     int           `json:"port"`
		Protocol string        `json:"protocol"`
		Settings socksSettings `json:"settings"`
	}
	type vlessSettings struct {
		Address    string `json:"address"`
		Port       uint16 `json:"port"`
		ID         string `json:"id"`
		Encryption string `json:"encryption"`
	}
	type tlsSettings struct {
		ServerName string `json:"serverName"`
	}
	type websocketSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
	}
	type streamSettings struct {
		Method    string            `json:"method"`
		Security  string            `json:"security"`
		TLS       tlsSettings       `json:"tlsSettings"`
		WebSocket websocketSettings `json:"wsSettings"`
	}
	type outbound struct {
		Tag            string         `json:"tag"`
		Protocol       string         `json:"protocol"`
		Settings       vlessSettings  `json:"settings"`
		StreamSettings streamSettings `json:"streamSettings"`
	}
	type document struct {
		Log       logConfig  `json:"log"`
		Inbounds  []inbound  `json:"inbounds"`
		Outbounds []outbound `json:"outbounds"`
	}

	credential := deployment.Credentials.Current
	doc := document{
		Log: logConfig{LogLevel: "warning"},
		Inbounds: []inbound{{
			Tag:      "socks-in",
			Listen:   "127.0.0.1",
			Port:     int(localPort),
			Protocol: "socks",
			Settings: socksSettings{UDP: false},
		}},
		Outbounds: []outbound{{
			Tag:      "proxy",
			Protocol: "vless",
			Settings: vlessSettings{
				Address:    deployment.Hostname,
				Port:       deployment.Port,
				ID:         credential.UUID,
				Encryption: "none",
			},
			StreamSettings: streamSettings{
				Method:   "websocket",
				Security: "tls",
				TLS:      tlsSettings{ServerName: deployment.Hostname},
				WebSocket: websocketSettings{
					Path: credential.Path,
					Host: deployment.Hostname,
				},
			},
		}},
	}
	return marshalJSON(doc)
}

// SingBoxJSON renders a system-wide TUN client. Private and mainland China
// destinations are direct; unmatched public TCP destinations use VLESS.
func SingBoxJSON(deployment config.Deployment) ([]byte, error) {
	return singBoxJSON(deployment, 0, true)
}

// SingBoxJSONWithLocalPort renders the same routing policy with an unprivileged
// mixed inbound for executable integration tests.
func SingBoxJSONWithLocalPort(deployment config.Deployment, localPort uint16) ([]byte, error) {
	return singBoxJSON(deployment, localPort, false)
}

func singBoxJSON(deployment config.Deployment, localPort uint16, systemWide bool) ([]byte, error) {
	if err := deployment.Validate(); err != nil {
		return nil, err
	}
	if !systemWide && localPort == 0 {
		return nil, errors.New("sing-box local port is invalid")
	}
	type logConfig struct {
		Level string `json:"level"`
	}
	type tlsConfig struct {
		Enabled    bool   `json:"enabled"`
		ServerName string `json:"server_name"`
		Insecure   bool   `json:"insecure"`
	}
	type dnsServer struct {
		Type       string    `json:"type"`
		Tag        string    `json:"tag"`
		Server     string    `json:"server"`
		ServerPort uint16    `json:"server_port"`
		Path       string    `json:"path"`
		TLS        tlsConfig `json:"tls"`
	}
	type dnsConfig struct {
		Servers  []dnsServer `json:"servers"`
		Final    string      `json:"final"`
		Strategy string      `json:"strategy"`
	}
	type inbound struct {
		Type        string   `json:"type"`
		Tag         string   `json:"tag"`
		Listen      string   `json:"listen,omitempty"`
		ListenPort  int      `json:"listen_port,omitempty"`
		Address     []string `json:"address,omitempty"`
		AutoRoute   bool     `json:"auto_route,omitempty"`
		StrictRoute bool     `json:"strict_route,omitempty"`
	}
	type transport struct {
		Type    string            `json:"type"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
	}
	type outbound struct {
		Type           string     `json:"type"`
		Tag            string     `json:"tag"`
		Server         string     `json:"server,omitempty"`
		ServerPort     uint16     `json:"server_port,omitempty"`
		UUID           string     `json:"uuid,omitempty"`
		Network        string     `json:"network,omitempty"`
		DomainResolver string     `json:"domain_resolver,omitempty"`
		TLS            *tlsConfig `json:"tls,omitempty"`
		Transport      *transport `json:"transport,omitempty"`
	}
	type routeRule struct {
		IPIsPrivate bool   `json:"ip_is_private,omitempty"`
		RuleSet     string `json:"rule_set,omitempty"`
		Network     string `json:"network,omitempty"`
		Protocol    string `json:"protocol,omitempty"`
		Action      string `json:"action"`
		Outbound    string `json:"outbound,omitempty"`
		Server      string `json:"server,omitempty"`
		Strategy    string `json:"strategy,omitempty"`
	}
	type ruleSet struct {
		Type           string `json:"type"`
		Tag            string `json:"tag"`
		Format         string `json:"format"`
		URL            string `json:"url"`
		DownloadDetour string `json:"download_detour"`
		UpdateInterval string `json:"update_interval"`
	}
	type domainResolver struct {
		Server string `json:"server"`
	}
	type route struct {
		Rules                 []routeRule    `json:"rules"`
		RuleSet               []ruleSet      `json:"rule_set"`
		Final                 string         `json:"final"`
		AutoDetectInterface   bool           `json:"auto_detect_interface"`
		DefaultDomainResolver domainResolver `json:"default_domain_resolver"`
	}
	type cacheFile struct {
		Enabled bool `json:"enabled"`
	}
	type experimental struct {
		CacheFile cacheFile `json:"cache_file"`
	}
	type document struct {
		Log          logConfig    `json:"log"`
		DNS          dnsConfig    `json:"dns"`
		Inbounds     []inbound    `json:"inbounds"`
		Outbounds    []outbound   `json:"outbounds"`
		Route        route        `json:"route"`
		Experimental experimental `json:"experimental"`
	}

	credential := deployment.Credentials.Current
	inboundConfig := inbound{
		Type:       "mixed",
		Tag:        "mixed-in",
		Listen:     "127.0.0.1",
		ListenPort: int(localPort),
	}
	if systemWide {
		inboundConfig = inbound{
			Type:        "tun",
			Tag:         "tun-in",
			Address:     []string{singBoxTUNIPv4CIDR, singBoxTUNIPv6CIDR},
			AutoRoute:   true,
			StrictRoute: true,
		}
	}
	tls := tlsConfig{
		Enabled:    true,
		ServerName: deployment.Hostname,
		Insecure:   false,
	}
	websocket := transport{
		Type: "ws",
		Path: credential.Path,
		Headers: map[string]string{
			"Host": deployment.Hostname,
		},
	}
	doc := document{
		Log: logConfig{Level: "warn"},
		DNS: dnsConfig{
			Servers: []dnsServer{{
				Type:       "https",
				Tag:        "china-dns",
				Server:     singBoxChinaDNSIP,
				ServerPort: 443,
				Path:       "/dns-query",
				TLS: tlsConfig{
					Enabled:    true,
					ServerName: singBoxChinaDNSName,
					Insecure:   false,
				},
			}},
			Final:    "china-dns",
			Strategy: "prefer_ipv4",
		},
		Inbounds: []inbound{inboundConfig},
		Outbounds: []outbound{{
			Type:           "vless",
			Tag:            "proxy",
			Server:         deployment.Hostname,
			ServerPort:     deployment.Port,
			UUID:           credential.UUID,
			Network:        "tcp",
			DomainResolver: "china-dns",
			TLS:            &tls,
			Transport:      &websocket,
		}, {
			Type: "direct",
			Tag:  "direct",
		}},
		Route: route{
			Rules: []routeRule{
				{Action: "sniff"},
				{Protocol: "dns", Action: "hijack-dns"},
				{IPIsPrivate: true, Action: "route", Outbound: "direct"},
				{Action: "resolve", Server: "china-dns", Strategy: "prefer_ipv4"},
				{IPIsPrivate: true, Action: "route", Outbound: "direct"},
				{RuleSet: "geoip-cn", Action: "route", Outbound: "direct"},
				{Network: "udp", Action: "reject"},
				{Network: "icmp", Action: "reject"},
			},
			RuleSet: []ruleSet{{
				Type:           "remote",
				Tag:            "geoip-cn",
				Format:         "binary",
				URL:            singBoxGeoIPCNURL,
				DownloadDetour: "proxy",
				UpdateInterval: "1d",
			}},
			Final:                 "proxy",
			AutoDetectInterface:   true,
			DefaultDomainResolver: domainResolver{Server: "china-dns"},
		},
		Experimental: experimental{CacheFile: cacheFile{Enabled: true}},
	}
	return marshalJSON(doc)
}

// MihomoYAML renders a complete Mihomo configuration without an external YAML
// dependency. User-controlled scalar values are encoded as JSON strings,
// which are valid YAML 1.2 double-quoted scalars.
func MihomoYAML(deployment config.Deployment) ([]byte, error) {
	return MihomoYAMLWithLocalPort(deployment, mihomoPort)
}

// MihomoYAMLWithLocalPort renders the shipped Mihomo format with a
// caller-selected loopback port for executable integration tests.
func MihomoYAMLWithLocalPort(deployment config.Deployment, localPort uint16) ([]byte, error) {
	if err := deployment.Validate(); err != nil {
		return nil, err
	}
	if localPort == 0 {
		return nil, errors.New("Mihomo local port is invalid")
	}
	proxyName := yamlString(deployment.DisplayName)
	groupNameValue := "CF-VLESS"
	if deployment.DisplayName == groupNameValue {
		groupNameValue = "CF-VLESS-SELECT"
	}
	groupName := yamlString(groupNameValue)
	credential := deployment.Credentials.Current

	var yaml strings.Builder
	yaml.Grow(700 + len(deployment.DisplayName))
	yaml.WriteString("mixed-port: ")
	yaml.WriteString(strconv.Itoa(int(localPort)))
	yaml.WriteString("\nallow-lan: false\nmode: rule\nlog-level: warning\n\nproxies:\n  - name: ")
	yaml.WriteString(proxyName)
	yaml.WriteString("\n    type: vless\n    server: ")
	yaml.WriteString(yamlString(deployment.Hostname))
	yaml.WriteString("\n    port: ")
	yaml.WriteString(strconv.Itoa(int(deployment.Port)))
	yaml.WriteString("\n    uuid: ")
	yaml.WriteString(yamlString(credential.UUID))
	yaml.WriteString("\n    udp: false\n    tls: true\n    servername: ")
	yaml.WriteString(yamlString(deployment.Hostname))
	yaml.WriteString("\n    skip-cert-verify: false\n    network: ws\n    encryption: \"\"\n    ws-opts:\n      path: ")
	yaml.WriteString(yamlString(credential.Path))
	yaml.WriteString("\n      headers:\n        Host: ")
	yaml.WriteString(yamlString(deployment.Hostname))
	yaml.WriteString("\n\nproxy-groups:\n  - name: ")
	yaml.WriteString(groupName)
	yaml.WriteString("\n    type: select\n    proxies:\n      - ")
	yaml.WriteString(proxyName)
	yaml.WriteString("\n\nrules:\n  - ")
	yaml.WriteString(yamlString("MATCH," + groupNameValue))
	yaml.WriteByte('\n')
	return []byte(yaml.String()), nil
}

func yamlString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(errors.New("validated string could not be encoded"))
	}
	return string(encoded)
}

func marshalJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, errors.New("encode client JSON")
	}
	return append(encoded, '\n'), nil
}
