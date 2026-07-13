package xray

import (
	"encoding/json"
	"errors"
	"path/filepath"

	projectconfig "github.com/BaiqingL/cf-vless/internal/config"
)

// LocalReferenceOptions describes a loopback-only Xray client/server pair.
// TLS is deliberately absent: this reference gate isolates VLESS-over-
// WebSocket behavior, while deployed Worker tests cover Cloudflare TLS.
type LocalReferenceOptions struct {
	UUID          string
	WebSocketPath string
	ServerPort    uint16
	// ClientTargetPort optionally inserts a loopback-only transparent proxy
	// between the client and ServerPort. Zero targets ServerPort directly.
	ClientTargetPort uint16
	SOCKSPort        uint16
}

type LocalReferenceConfigs struct {
	ServerJSON []byte
	ClientJSON []byte
}

type LocalReferencePaths struct {
	ServerPath string
	ClientPath string
}

func (options LocalReferenceOptions) Validate() error {
	if !validUUID(options.UUID) {
		return errors.New("local reference UUID is invalid")
	}
	if !safeWebSocketPath.MatchString(options.WebSocketPath) {
		return errors.New("local reference WebSocket path is invalid")
	}
	clientTargetPort := options.clientTargetPort()
	if options.ServerPort == 0 || clientTargetPort == 0 || options.SOCKSPort == 0 ||
		options.ServerPort == options.SOCKSPort || clientTargetPort == options.SOCKSPort {
		return errors.New("local reference ports are invalid")
	}
	return nil
}

func (options LocalReferenceOptions) clientTargetPort() uint16 {
	if options.ClientTargetPort != 0 {
		return options.ClientTargetPort
	}
	return options.ServerPort
}

// MarshalLocalReferenceConfigs renders the current pinned Xray flat VLESS
// settings and streamSettings.method form for both sides of a loopback pair.
func MarshalLocalReferenceConfigs(options LocalReferenceOptions) (LocalReferenceConfigs, error) {
	if err := options.Validate(); err != nil {
		return LocalReferenceConfigs{}, err
	}
	type logConfig struct {
		LogLevel string `json:"loglevel"`
	}
	type websocketSettings struct {
		Path string `json:"path"`
		Host string `json:"host,omitempty"`
		ED   uint32 `json:"ed,omitempty"`
	}
	type streamSettings struct {
		Method    string            `json:"method"`
		Security  string            `json:"security"`
		WebSocket websocketSettings `json:"wsSettings"`
	}
	type serverAccount struct {
		ID string `json:"id"`
	}
	type serverSettings struct {
		Clients    []serverAccount `json:"clients"`
		Decryption string          `json:"decryption"`
	}
	type serverInbound struct {
		Tag            string         `json:"tag"`
		Listen         string         `json:"listen"`
		Port           uint16         `json:"port"`
		Protocol       string         `json:"protocol"`
		Settings       serverSettings `json:"settings"`
		StreamSettings streamSettings `json:"streamSettings"`
	}
	type freedomFinalRule struct {
		Action  string   `json:"action"`
		Network string   `json:"network,omitempty"`
		IP      []string `json:"ip,omitempty"`
	}
	type freedomSettings struct {
		TargetStrategy string             `json:"targetStrategy"`
		FinalRules     []freedomFinalRule `json:"finalRules"`
	}
	type freedomOutbound struct {
		Tag      string          `json:"tag"`
		Protocol string          `json:"protocol"`
		Settings freedomSettings `json:"settings"`
	}
	type dnsConfig struct {
		Hosts         map[string]string `json:"hosts"`
		QueryStrategy string            `json:"queryStrategy"`
	}
	serverDocument := struct {
		Log       logConfig         `json:"log"`
		DNS       dnsConfig         `json:"dns"`
		Inbounds  []serverInbound   `json:"inbounds"`
		Outbounds []freedomOutbound `json:"outbounds"`
	}{
		Log: logConfig{LogLevel: "none"},
		// The real domain-header capture uses the canonical documentation
		// hostname, but this static mapping guarantees that Xray neither asks an
		// external resolver nor dials anything outside IPv4 loopback.
		DNS: dnsConfig{
			Hosts:         map[string]string{"example.com": "127.0.0.1"},
			QueryStrategy: "UseIPv4",
		},
		Inbounds: []serverInbound{{
			Tag:      "reference-vless-in",
			Listen:   "127.0.0.1",
			Port:     options.ServerPort,
			Protocol: "vless",
			Settings: serverSettings{
				Clients:    []serverAccount{{ID: options.UUID}},
				Decryption: "none",
			},
			StreamSettings: streamSettings{
				Method:   "websocket",
				Security: "none",
				WebSocket: websocketSettings{
					Path: options.WebSocketPath,
				},
			},
		}},
		Outbounds: []freedomOutbound{{
			Tag:      "loopback-only",
			Protocol: "freedom",
			// Pinned Xray blocks private destinations from VLESS by default.
			// Resolve the one static test domain and permit only this test's IPv4
			// and IPv6 loopback targets, then fail closed.
			Settings: freedomSettings{TargetStrategy: "UseIPv4", FinalRules: []freedomFinalRule{
				{Action: "allow", Network: "tcp", IP: []string{"127.0.0.1/32", "::1/128"}},
				{Action: "block"},
			}},
		}},
	}

	type socksSettings struct {
		Auth string `json:"auth"`
		UDP  bool   `json:"udp"`
	}
	type clientInbound struct {
		Tag      string        `json:"tag"`
		Listen   string        `json:"listen"`
		Port     uint16        `json:"port"`
		Protocol string        `json:"protocol"`
		Settings socksSettings `json:"settings"`
	}
	type clientSettings struct {
		Address    string `json:"address"`
		Port       uint16 `json:"port"`
		ID         string `json:"id"`
		Encryption string `json:"encryption"`
	}
	type clientOutbound struct {
		Tag            string         `json:"tag"`
		Protocol       string         `json:"protocol"`
		Settings       clientSettings `json:"settings"`
		StreamSettings streamSettings `json:"streamSettings"`
	}
	clientDocument := struct {
		Log       logConfig        `json:"log"`
		Inbounds  []clientInbound  `json:"inbounds"`
		Outbounds []clientOutbound `json:"outbounds"`
	}{
		Log: logConfig{LogLevel: "none"},
		Inbounds: []clientInbound{{
			Tag:      "reference-socks-in",
			Listen:   "127.0.0.1",
			Port:     options.SOCKSPort,
			Protocol: "socks",
			Settings: socksSettings{Auth: "noauth", UDP: false},
		}},
		Outbounds: []clientOutbound{{
			Tag:      "reference-vless-out",
			Protocol: "vless",
			Settings: clientSettings{
				Address:    "127.0.0.1",
				Port:       options.clientTargetPort(),
				ID:         options.UUID,
				Encryption: "none",
			},
			StreamSettings: streamSettings{
				Method:   "websocket",
				Security: "none",
				WebSocket: websocketSettings{
					Path: options.WebSocketPath,
					Host: "127.0.0.1",
				},
			},
		}},
	}
	serverJSON, err := json.MarshalIndent(serverDocument, "", "  ")
	if err != nil {
		return LocalReferenceConfigs{}, errors.New("encode local Xray server config")
	}
	clientJSON, err := json.MarshalIndent(clientDocument, "", "  ")
	if err != nil {
		return LocalReferenceConfigs{}, errors.New("encode local Xray client config")
	}
	return LocalReferenceConfigs{
		ServerJSON: append(serverJSON, '\n'),
		ClientJSON: append(clientJSON, '\n'),
	}, nil
}

func WriteLocalReferenceConfigs(directory string, options LocalReferenceOptions) (LocalReferencePaths, error) {
	configs, err := MarshalLocalReferenceConfigs(options)
	if err != nil {
		return LocalReferencePaths{}, err
	}
	if err := projectconfig.EnsureSecretDirectory(directory); err != nil {
		return LocalReferencePaths{}, errors.New("create private local reference directory")
	}
	paths := LocalReferencePaths{
		ServerPath: filepath.Join(directory, "server.json"),
		ClientPath: filepath.Join(directory, "client.json"),
	}
	if err := projectconfig.WriteSecretFile(paths.ServerPath, configs.ServerJSON, false); err != nil {
		return LocalReferencePaths{}, errors.New("write local Xray server config")
	}
	if err := projectconfig.WriteSecretFile(paths.ClientPath, configs.ClientJSON, false); err != nil {
		return LocalReferencePaths{}, errors.New("write local Xray client config")
	}
	return paths, nil
}
