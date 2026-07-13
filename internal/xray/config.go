package xray

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var safeWebSocketPath = regexp.MustCompile(`^/[A-Za-z0-9_-]{16,128}$`)

type Endpoint struct {
	Hostname string
	Port     uint16
	UUID     string
	Path     string
}

type ClientConfig struct {
	Endpoint  Endpoint
	SOCKSHost string
	SOCKSPort uint16
	LogLevel  string
}

func (config ClientConfig) Validate() error {
	if err := config.Endpoint.Validate(); err != nil {
		return err
	}
	if config.SOCKSHost != "127.0.0.1" && config.SOCKSHost != "::1" {
		return errors.New("Xray SOCKS listener must use loopback")
	}
	if config.SOCKSPort == 0 {
		return errors.New("Xray SOCKS port is required")
	}
	if config.LogLevel != "" && config.LogLevel != "none" && config.LogLevel != "error" && config.LogLevel != "warning" {
		return errors.New("unsupported Xray log level")
	}
	return nil
}

func (endpoint Endpoint) Validate() error {
	if endpoint.Hostname == "" || len(endpoint.Hostname) > 253 || endpoint.Hostname != strings.ToLower(endpoint.Hostname) || net.ParseIP(endpoint.Hostname) != nil {
		return errors.New("endpoint hostname is invalid")
	}
	labels := strings.Split(endpoint.Hostname, ".")
	if len(labels) < 2 {
		return errors.New("endpoint hostname is invalid")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("endpoint hostname is invalid")
		}
		for index := range len(label) {
			value := label[index]
			if !(value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-') {
				return errors.New("endpoint hostname is invalid")
			}
		}
	}
	if endpoint.Port == 0 {
		return errors.New("endpoint port is required")
	}
	if !validUUID(endpoint.UUID) {
		return errors.New("endpoint UUID is invalid")
	}
	if !safeWebSocketPath.MatchString(endpoint.Path) {
		return errors.New("endpoint WebSocket path is invalid")
	}
	return nil
}

func (config ClientConfig) SOCKSAddress() string {
	return net.JoinHostPort(config.SOCKSHost, fmt.Sprintf("%d", config.SOCKSPort))
}

// MarshalClientConfig emits the flat VLESS settings and streamSettings.method
// shape used by the pinned Xray release.
func MarshalClientConfig(config ClientConfig) ([]byte, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	logLevel := config.LogLevel
	if logLevel == "" {
		logLevel = "warning"
	}
	type logConfig struct {
		LogLevel string `json:"loglevel"`
	}
	type socksSettings struct {
		Auth string `json:"auth"`
		UDP  bool   `json:"udp"`
	}
	type inbound struct {
		Tag      string        `json:"tag"`
		Listen   string        `json:"listen"`
		Port     uint16        `json:"port"`
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
		ServerName    string `json:"serverName"`
		AllowInsecure bool   `json:"allowInsecure"`
	}
	type websocketSettings struct {
		Path string `json:"path"`
		Host string `json:"host"`
		ED   uint32 `json:"ed"`
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
	document := struct {
		Log       logConfig  `json:"log"`
		Inbounds  []inbound  `json:"inbounds"`
		Outbounds []outbound `json:"outbounds"`
	}{
		Log: logConfig{LogLevel: logLevel},
		Inbounds: []inbound{{
			Tag:      "integration-socks",
			Listen:   config.SOCKSHost,
			Port:     config.SOCKSPort,
			Protocol: "socks",
			Settings: socksSettings{Auth: "noauth", UDP: false},
		}},
		Outbounds: []outbound{{
			Tag:      "worker-vless",
			Protocol: "vless",
			Settings: vlessSettings{
				Address:    config.Endpoint.Hostname,
				Port:       config.Endpoint.Port,
				ID:         config.Endpoint.UUID,
				Encryption: "none",
			},
			StreamSettings: streamSettings{
				Method:   "websocket",
				Security: "tls",
				TLS: tlsSettings{
					ServerName:    config.Endpoint.Hostname,
					AllowInsecure: false,
				},
				WebSocket: websocketSettings{
					Path: config.Endpoint.Path,
					Host: config.Endpoint.Hostname,
					ED:   0,
				},
			},
		}},
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, errors.New("encode Xray client config")
	}
	return append(encoded, '\n'), nil
}

func WriteClientConfig(path string, config ClientConfig) (returnErr error) {
	encoded, err := MarshalClientConfig(config)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("Xray config path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create Xray config directory")
	}
	temporary, err := os.CreateTemp(directory, ".xray-config-*")
	if err != nil {
		return errors.New("create temporary Xray config")
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			if err := temporary.Close(); err != nil {
				returnErr = errors.Join(returnErr, errors.New("close temporary Xray config"))
			}
		}
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, errors.New("remove temporary Xray config"))
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return errors.New("protect Xray config")
	}
	if _, err := temporary.Write(encoded); err != nil {
		return errors.New("write Xray config")
	}
	if err := temporary.Sync(); err != nil {
		return errors.New("sync Xray config")
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return errors.New("close Xray config")
	}
	closed = true
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("install Xray config")
	}
	return nil
}

func ReserveLoopbackPort() (uint16, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, errors.New("reserve loopback port")
	}
	defer func() {
		_ = listener.Close()
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	if port <= 0 || port > 65535 {
		return 0, errors.New("invalid reserved loopback port")
	}
	return uint16(port), nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && decoded[6]>>4 == 4 && decoded[8]&0xc0 == 0x80
}
