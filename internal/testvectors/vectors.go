// Package testvectors generates deterministic, non-secret VLESS v0 TCP wire
// fixtures. They are independently encoded from the pinned Xray source layout,
// rather than emitted from a capture file. The opt-in local reference gate
// captures the pinned, unmodified Xray client's real IPv4, domain, and IPv6
// WebSocket requests, sanitizes credential and destination fields in memory,
// and byte-compares every observed header with its corresponding oracle here.
// The encoding is independent of production Worker code.
package testvectors

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

const (
	// XrayCommit is the exact Xray-core gitlink recorded by this repository.
	XrayCommit = "50231eaff98ccc31b5cbd247a721c16e97fe5ec1"
	XrayTag    = "v26.7.11"

	sanitizedUUID  = "00112233-4455-6677-8899-aabbccddeeff"
	initialPayload = "01020304"
)

// Suite is the stable JSON fixture document emitted by cmd/test-vector-gen.
type Suite struct {
	SchemaVersion     int      `json:"schema_version"`
	Protocol          string   `json:"protocol"`
	Upstream          string   `json:"upstream"`
	UpstreamCommit    string   `json:"upstream_commit"`
	UpstreamTag       string   `json:"upstream_tag"`
	SanitizedUUID     string   `json:"sanitized_uuid"`
	ResponseHeaderHex string   `json:"response_header_hex"`
	Cases             []Vector `json:"cases"`
}

// Vector describes one canonical request header and representative ways its
// byte stream can be divided into WebSocket messages.
type Vector struct {
	Name              string          `json:"name"`
	AddressType       string          `json:"address_type"`
	Host              string          `json:"host"`
	Port              uint16          `json:"port"`
	RequestHeaderHex  string          `json:"request_header_hex"`
	HeaderBytes       int             `json:"header_bytes"`
	InitialPayloadHex string          `json:"initial_payload_hex"`
	WireHex           string          `json:"wire_hex"`
	Fragmentations    []Fragmentation `json:"fragmentations"`
}

// Fragmentation contains message payload sizes in wire order. Sizes always
// cover the complete WireHex value exactly.
type Fragmentation struct {
	Name       string `json:"name"`
	ChunkSizes []int  `json:"chunk_sizes"`
}

// Generate returns the deterministic VLESS v0 TCP fixture suite.
func Generate() (Suite, error) {
	uuid, err := decodeUUID(sanitizedUUID)
	if err != nil {
		return Suite{}, err
	}
	payload, err := hex.DecodeString(initialPayload)
	if err != nil {
		return Suite{}, err
	}
	specifications := []struct {
		name        string
		addressType string
		host        string
		port        uint16
	}{
		{name: "domain", addressType: "domain", host: "example.com", port: 443},
		{name: "ipv4", addressType: "ipv4", host: "203.0.113.7", port: 80},
		{name: "ipv6", addressType: "ipv6", host: "2001:db8::1", port: 8443},
	}

	suite := Suite{
		SchemaVersion:     1,
		Protocol:          "VLESS v0 TCP",
		Upstream:          "https://github.com/XTLS/Xray-core.git",
		UpstreamCommit:    XrayCommit,
		UpstreamTag:       XrayTag,
		SanitizedUUID:     sanitizedUUID,
		ResponseHeaderHex: "0000",
		Cases:             make([]Vector, 0, len(specifications)),
	}
	for _, specification := range specifications {
		header, fieldSizes, err := encodeRequest(uuid, specification.addressType, specification.host, specification.port)
		if err != nil {
			return Suite{}, fmt.Errorf("encode %s fixture: %w", specification.name, err)
		}
		wire := append(append([]byte(nil), header...), payload...)
		fieldChunks := append(append([]int(nil), fieldSizes...), len(payload))
		bytewise := make([]int, 0, len(header)+1)
		for range header {
			bytewise = append(bytewise, 1)
		}
		bytewise = append(bytewise, len(payload))
		suite.Cases = append(suite.Cases, Vector{
			Name:              specification.name,
			AddressType:       specification.addressType,
			Host:              specification.host,
			Port:              specification.port,
			RequestHeaderHex:  hex.EncodeToString(header),
			HeaderBytes:       len(header),
			InitialPayloadHex: initialPayload,
			WireHex:           hex.EncodeToString(wire),
			Fragmentations: []Fragmentation{
				{Name: "single_message", ChunkSizes: []int{len(wire)}},
				{Name: "header_then_payload", ChunkSizes: []int{len(header), len(payload)}},
				{Name: "version_then_remainder", ChunkSizes: []int{1, len(wire) - 1}},
				{Name: "field_boundaries", ChunkSizes: fieldChunks},
				{Name: "bytewise_header", ChunkSizes: bytewise},
			},
		})
	}
	return suite, nil
}

// Marshal encodes Generate's output with stable indentation and a final
// newline so it can be checked into any consumer's fixture directory.
func Marshal() ([]byte, error) {
	suite, err := Generate()
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal VLESS fixtures: %w", err)
	}
	return append(encoded, '\n'), nil
}

func encodeRequest(uuid []byte, addressType, host string, port uint16) ([]byte, []int, error) {
	if len(uuid) != 16 {
		return nil, nil, errors.New("UUID must be 16 bytes")
	}
	if port == 0 {
		return nil, nil, errors.New("port must be nonzero")
	}
	header := make([]byte, 0, 64)
	header = append(header, 0) // version
	header = append(header, uuid...)
	header = append(header, 0) // empty add-ons
	header = append(header, 1) // TCP
	header = append(header, byte(port>>8), byte(port))
	fieldSizes := []int{1, 16, 1, 1, 2, 1}

	switch addressType {
	case "ipv4":
		address := net.ParseIP(host).To4()
		if address == nil {
			return nil, nil, errors.New("invalid IPv4 address")
		}
		header = append(header, 1)
		header = append(header, address...)
		fieldSizes = append(fieldSizes, 4)
	case "domain":
		if len(host) == 0 || len(host) > 255 {
			return nil, nil, errors.New("invalid domain length")
		}
		for index := range len(host) {
			value := host[index]
			if !isXrayDomainByte(value) {
				return nil, nil, errors.New("invalid domain byte")
			}
		}
		header = append(header, 2, byte(len(host)))
		header = append(header, host...)
		fieldSizes = append(fieldSizes, 1, len(host))
	case "ipv6":
		parsed := net.ParseIP(host)
		if parsed == nil || parsed.To4() != nil {
			return nil, nil, errors.New("invalid IPv6 address")
		}
		header = append(header, 3)
		header = append(header, parsed.To16()...)
		fieldSizes = append(fieldSizes, 16)
	default:
		return nil, nil, errors.New("unsupported address type")
	}
	return header, fieldSizes, nil
}

func decodeUUID(value string) ([]byte, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return nil, errors.New("invalid UUID")
	}
	compact := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != 16 {
		return nil, errors.New("invalid UUID")
	}
	return decoded, nil
}

func isXrayDomainByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value == '-' || value == '.' || value == '_'
}
