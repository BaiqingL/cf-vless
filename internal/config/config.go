// Package config defines the canonical local deployment state.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// CurrentVersion is the only local deployment schema version understood by
	// this build.
	CurrentVersion = 1
	// TLSPort is fixed because the public endpoint is always Cloudflare-managed
	// HTTPS/WebSocket.
	TLSPort uint16 = 443
	// DefaultWorkerName is used by the standalone initializer unless the user
	// selects another safe Cloudflare Worker resource name.
	DefaultWorkerName = "cf-vless"
	// WorkerSecretName is the only secret binding consumed by the Worker.
	WorkerSecretName = "VLESS_CREDENTIALS"
	// OwnershipMarkerBinding identifies a non-secret, random deployment marker.
	OwnershipMarkerBinding = "DEPLOYMENT_MARKER"

	webSocketPathRandomBytes   = 24
	ownershipMarkerRandomBytes = 24
	maxDisplayNameBytes        = 256
)

var (
	webSocketPathPattern              = regexp.MustCompile(`^/[A-Za-z0-9_-]{16,128}$`)
	workerNamePattern                 = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	cloudflareIDPattern               = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	canonicalWorkerDomainIDPattern    = regexp.MustCompile(`^[0-9a-f]{32}([0-9a-f]{8})?$`)
	canonicalCertificatePackIDPattern = regexp.MustCompile(`^([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	ownershipMarkerPattern            = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)

	// ErrRotationInProgress prevents a second rotation from silently dropping
	// a credential that is still inside its promised overlap window.
	ErrRotationInProgress = errors.New("credential rotation is already in progress")
	// ErrRotationOverlapActive prevents finalization before the promised overlap expires.
	ErrRotationOverlapActive = errors.New("credential rotation overlap is still active")
)

// Credential is the inseparable VLESS UUID and WebSocket path used by the
// Worker. The path is an additional routing control; the UUID is the VLESS
// authentication credential.
type Credential struct {
	UUID string `json:"uuid"`
	Path string `json:"path"`
}

// PreviousCredential is accepted only until ExpiresAt during a credential
// rotation overlap.
type PreviousCredential struct {
	Credential
	ExpiresAt time.Time `json:"expires_at"`
}

// CredentialSet contains the active credential and, during rotation, the
// outgoing credential with an explicit expiration.
type CredentialSet struct {
	Current  Credential          `json:"current"`
	Previous *PreviousCredential `json:"previous,omitempty"`
}

// ManagedDomain is the creation-time ownership proof for the one Custom
// Domain managed by this deployment. CertificatePackID is empty only while
// Cloudflare is asynchronously exposing the generated Advanced Certificate
// pack after a successful bind.
type ManagedDomain struct {
	DomainID                        string   `json:"domain_id"`
	InitialCertificateID            string   `json:"initial_certificate_id"`
	CertificatePackID               string   `json:"certificate_pack_id,omitempty"`
	CertificatePackBaselineIDs      []string `json:"certificate_pack_baseline_ids,omitempty"`
	CertificatePackBaselineRecorded bool     `json:"certificate_pack_baseline_recorded,omitempty"`
}

// Deployment is the canonical local state needed to deploy the Worker and
// render clients. Protocol, transport, TLS name, and WebSocket Host are not
// configurable: they are VLESS/TCP, WebSocket, and the deployment hostname.
type Deployment struct {
	Version         int            `json:"version"`
	WorkerName      string         `json:"worker_name"`
	AccountID       string         `json:"account_id,omitempty"`
	ZoneID          string         `json:"zone_id,omitempty"`
	ZoneName        string         `json:"zone_name"`
	Hostname        string         `json:"hostname"`
	Port            uint16         `json:"port"`
	DisplayName     string         `json:"display_name"`
	AllowedPorts    []uint16       `json:"allowed_ports"`
	OwnershipMarker string         `json:"deployment_marker"`
	Credentials     CredentialSet  `json:"credentials"`
	ManagedDomain   *ManagedDomain `json:"managed_domain,omitempty"`
}

// InitOptions supplies deployment and Cloudflare resource identifiers. The
// account and zone IDs may remain empty until doctor/init resolves them.
type InitOptions struct {
	WorkerName   string
	AccountID    string
	ZoneID       string
	ZoneName     string
	Hostname     string
	DisplayName  string
	AllowedPorts []uint16
}

// DefaultAllowedPorts returns a fresh copy of the conservative TCP policy.
func DefaultAllowedPorts() []uint16 {
	return []uint16{22, 80, 443}
}

// Generate creates a new deployment using cryptographically secure random
// values. It never persists the result.
func Generate(hostname, displayName string) (Deployment, error) {
	zoneName := ""
	if separator := strings.IndexByte(hostname, '.'); separator >= 0 && separator+1 < len(hostname) {
		zoneName = hostname[separator+1:]
	}
	return New(InitOptions{
		WorkerName:  DefaultWorkerName,
		ZoneName:    zoneName,
		Hostname:    hostname,
		DisplayName: displayName,
	})
}

// New creates deployment state from explicit operational targets and fresh
// cryptographic credentials.
func New(options InitOptions) (Deployment, error) {
	credential, err := generateCredential(rand.Reader)
	if err != nil {
		return Deployment{}, fmt.Errorf("generate credential: %w", err)
	}
	marker, err := generateOwnershipMarker(rand.Reader)
	if err != nil {
		return Deployment{}, fmt.Errorf("generate ownership marker: %w", err)
	}
	workerName := options.WorkerName
	if workerName == "" {
		workerName = DefaultWorkerName
	}
	allowedPorts := options.AllowedPorts
	if allowedPorts == nil {
		allowedPorts = DefaultAllowedPorts()
	} else {
		allowedPorts = append([]uint16(nil), allowedPorts...)
	}
	cfg := Deployment{
		Version:         CurrentVersion,
		WorkerName:      workerName,
		AccountID:       options.AccountID,
		ZoneID:          options.ZoneID,
		ZoneName:        options.ZoneName,
		Hostname:        options.Hostname,
		Port:            TLSPort,
		DisplayName:     options.DisplayName,
		AllowedPorts:    allowedPorts,
		OwnershipMarker: marker,
		Credentials:     CredentialSet{Current: credential},
	}
	if err := cfg.Validate(); err != nil {
		return Deployment{}, err
	}
	return cfg, nil
}

// GenerateCredential creates a new UUIDv4 and randomized Worker-compatible
// WebSocket path.
func GenerateCredential() (Credential, error) {
	return generateCredential(rand.Reader)
}

func generateCredential(random io.Reader) (Credential, error) {
	uuid, err := generateUUID(random)
	if err != nil {
		return Credential{}, err
	}
	path, err := generateWebSocketPath(random)
	if err != nil {
		return Credential{}, err
	}
	return Credential{UUID: uuid, Path: path}, nil
}

func generateUUID(random io.Reader) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(random, value[:]); err != nil {
		return "", fmt.Errorf("read UUID randomness: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], value[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], value[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], value[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], value[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], value[10:16])
	return string(encoded), nil
}

func generateWebSocketPath(random io.Reader) (string, error) {
	value := make([]byte, webSocketPathRandomBytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("read WebSocket path randomness: %w", err)
	}
	return "/" + base64.RawURLEncoding.EncodeToString(value), nil
}

func generateOwnershipMarker(random io.Reader) (string, error) {
	value := make([]byte, ownershipMarkerRandomBytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("read ownership marker randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// Validate rejects noncanonical or unsupported deployment state. Errors name
// fields but never include credential or path values.
func (d Deployment) Validate() error {
	if d.Version != CurrentVersion {
		return fmt.Errorf("deployment version must be %d", CurrentVersion)
	}
	if !workerNamePattern.MatchString(d.WorkerName) {
		return errors.New("Worker name is invalid")
	}
	if d.AccountID != "" && !cloudflareIDPattern.MatchString(d.AccountID) {
		return errors.New("Cloudflare account ID is invalid")
	}
	if d.ZoneID != "" && !cloudflareIDPattern.MatchString(d.ZoneID) {
		return errors.New("Cloudflare zone ID is invalid")
	}
	if err := validateHostname(d.ZoneName); err != nil {
		return errors.New("zone name is invalid")
	}
	if err := validateHostname(d.Hostname); err != nil {
		return err
	}
	if d.Hostname == d.ZoneName || !strings.HasSuffix(d.Hostname, "."+d.ZoneName) {
		return errors.New("hostname must be a dedicated subdomain of the zone")
	}
	if d.Port != TLSPort {
		return fmt.Errorf("deployment port must be %d", TLSPort)
	}
	if err := validateAllowedPorts(d.AllowedPorts); err != nil {
		return err
	}
	if !ownershipMarkerPattern.MatchString(d.OwnershipMarker) {
		return errors.New("deployment ownership marker is invalid")
	}
	if err := validateDisplayName(d.DisplayName); err != nil {
		return err
	}
	if err := validateCredential("current credential", d.Credentials.Current); err != nil {
		return err
	}
	if previous := d.Credentials.Previous; previous != nil {
		if err := validateCredential("previous credential", previous.Credential); err != nil {
			return err
		}
		if previous.ExpiresAt.IsZero() {
			return errors.New("previous credential expiration is required")
		}
		if previous.UUID == d.Credentials.Current.UUID {
			return errors.New("current and previous credential UUIDs must differ")
		}
		if previous.Path == d.Credentials.Current.Path {
			return errors.New("current and previous credential paths must differ")
		}
	}
	if managed := d.ManagedDomain; managed != nil {
		if !canonicalWorkerDomainIDPattern.MatchString(managed.DomainID) {
			return errors.New("managed Custom Domain ID is invalid")
		}
		if !validCanonicalUUID(managed.InitialCertificateID) {
			return errors.New("managed initial certificate ID is invalid")
		}
		if managed.CertificatePackID != "" && !canonicalCertificatePackIDPattern.MatchString(managed.CertificatePackID) {
			return errors.New("managed certificate pack ID is invalid")
		}
		if managed.CertificatePackID != "" && (managed.CertificatePackBaselineRecorded || len(managed.CertificatePackBaselineIDs) != 0) {
			return errors.New("managed certificate pack baseline must be cleared after provenance is established")
		}
		if !managed.CertificatePackBaselineRecorded && len(managed.CertificatePackBaselineIDs) != 0 {
			return errors.New("managed certificate pack baseline is not marked as recorded")
		}
		if len(managed.CertificatePackBaselineIDs) > 100 {
			return errors.New("managed certificate pack baseline exceeds the safe bound")
		}
		for index, id := range managed.CertificatePackBaselineIDs {
			if !canonicalCertificatePackIDPattern.MatchString(id) {
				return errors.New("managed certificate pack baseline ID is invalid")
			}
			if index > 0 && managed.CertificatePackBaselineIDs[index-1] >= id {
				return errors.New("managed certificate pack baseline IDs must be unique and sorted")
			}
		}
	}
	return nil
}

func validateAllowedPorts(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 64 {
		return errors.New("allowed ports are invalid")
	}
	var previous uint16
	for index, port := range ports {
		if port == 0 || port == 25 {
			return errors.New("allowed ports contain a prohibited port")
		}
		if index > 0 && port <= previous {
			return errors.New("allowed ports must be sorted and unique")
		}
		previous = port
	}
	return nil
}

func validateHostname(hostname string) error {
	if hostname == "" || len(hostname) > 253 || !utf8.ValidString(hostname) {
		return errors.New("hostname is invalid")
	}
	if hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") || net.ParseIP(hostname) != nil {
		return errors.New("hostname must be a canonical lowercase DNS name")
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return errors.New("hostname must contain at least two DNS labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return errors.New("hostname contains an invalid DNS label")
		}
		for index := 1; index < len(label)-1; index++ {
			if !isASCIIAlphaNumeric(label[index]) && label[index] != '-' {
				return errors.New("hostname contains an invalid DNS label")
			}
		}
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func validateDisplayName(displayName string) error {
	if !utf8.ValidString(displayName) || strings.TrimSpace(displayName) == "" || len(displayName) > maxDisplayNameBytes {
		return errors.New("display name is invalid")
	}
	for _, value := range displayName {
		if unicode.IsControl(value) {
			return errors.New("display name contains a control character")
		}
	}
	return nil
}

func validateCredential(field string, credential Credential) error {
	if !validUUIDv4(credential.UUID) {
		return fmt.Errorf("%s UUID is invalid", field)
	}
	if !webSocketPathPattern.MatchString(credential.Path) {
		return fmt.Errorf("%s path is invalid", field)
	}
	return nil
}

func validUUIDv4(value string) bool {
	if !validCanonicalUUID(value) {
		return false
	}
	hexValue := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	decoded, err := hex.DecodeString(hexValue)
	if err != nil || len(decoded) != 16 {
		return false
	}
	return decoded[6]>>4 == 4 && decoded[8]&0xc0 == 0x80
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	hexValue := value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36]
	decoded, err := hex.DecodeString(hexValue)
	return err == nil && len(decoded) == 16
}

// ActiveUUIDs returns the current UUID and the previous UUID only while its
// overlap is active. Callers must treat the returned strings as secrets.
func (c CredentialSet) ActiveUUIDs(now time.Time) []string {
	active := []string{c.Current.UUID}
	if c.Previous != nil && now.Before(c.Previous.ExpiresAt) {
		active = append(active, c.Previous.UUID)
	}
	return active
}

// RotateCredential replaces the UUID and path together and retains the
// outgoing pair for overlap. An unexpired prior overlap must finish first.
func (d *Deployment) RotateCredential(now time.Time, overlap time.Duration) error {
	return d.rotateCredential(now, overlap, rand.Reader)
}

// EmergencyRotateCredential replaces the current pair and immediately drops
// every previous pair. It is the incident-response path for a compromised
// credential and deliberately provides no overlap.
func (d *Deployment) EmergencyRotateCredential() error {
	return d.emergencyRotateCredential(rand.Reader)
}

func (d *Deployment) emergencyRotateCredential(random io.Reader) error {
	if d == nil {
		return errors.New("deployment is required")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	next, err := generateCredential(random)
	if err != nil {
		return fmt.Errorf("generate emergency credential: %w", err)
	}
	if next.UUID == d.Credentials.Current.UUID || next.Path == d.Credentials.Current.Path {
		return errors.New("generated credential collides with current credential")
	}
	candidate := *d
	candidate.Credentials = CredentialSet{Current: next}
	if err := candidate.Validate(); err != nil {
		return err
	}
	*d = candidate
	return nil
}

// FinalizeCredential removes an expired previous credential without changing
// the current client credential.
func (d *Deployment) FinalizeCredential(now time.Time) error {
	if d == nil {
		return errors.New("deployment is required")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("finalization time is required")
	}
	if d.Credentials.Previous == nil {
		return nil
	}
	if now.Before(d.Credentials.Previous.ExpiresAt) {
		return ErrRotationOverlapActive
	}
	candidate := *d
	candidate.Credentials = CredentialSet{Current: d.Credentials.Current}
	*d = candidate
	return nil
}

func (d *Deployment) rotateCredential(now time.Time, overlap time.Duration, random io.Reader) error {
	if d == nil {
		return errors.New("deployment is required")
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return errors.New("rotation time is required")
	}
	if overlap <= 0 {
		return errors.New("rotation overlap must be positive")
	}
	if d.Credentials.Previous != nil && now.Before(d.Credentials.Previous.ExpiresAt) {
		return ErrRotationInProgress
	}

	next, err := generateCredential(random)
	if err != nil {
		return fmt.Errorf("generate rotated credential: %w", err)
	}
	if next.UUID == d.Credentials.Current.UUID || next.Path == d.Credentials.Current.Path {
		return errors.New("generated credential collides with current credential")
	}

	expiresAt := now.UTC().Add(overlap)
	if !expiresAt.After(now.UTC()) {
		return errors.New("rotation expiration is invalid")
	}
	candidate := *d
	candidate.Credentials = CredentialSet{
		Current: next,
		Previous: &PreviousCredential{
			Credential: d.Credentials.Current,
			ExpiresAt:  expiresAt,
		},
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	*d = candidate
	return nil
}

// WorkerSecretJSON renders the exact VLESS_CREDENTIALS secret consumed by
// worker/src/auth.ts. It intentionally excludes all Cloudflare metadata and
// client display information.
func (d Deployment) WorkerSecretJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	type workerCredential struct {
		UUID string `json:"uuid"`
		Path string `json:"path"`
	}
	type workerPrevious struct {
		UUID      string `json:"uuid"`
		Path      string `json:"path"`
		ExpiresAt string `json:"expiresAt"`
	}
	type workerCredentialSet struct {
		Current  workerCredential `json:"current"`
		Previous *workerPrevious  `json:"previous,omitempty"`
	}

	secret := workerCredentialSet{
		Current: workerCredential{UUID: d.Credentials.Current.UUID, Path: d.Credentials.Current.Path},
	}
	if previous := d.Credentials.Previous; previous != nil {
		secret.Previous = &workerPrevious{
			UUID:      previous.UUID,
			Path:      previous.Path,
			ExpiresAt: previous.ExpiresAt.UTC().Format(time.RFC3339Nano),
		}
	}
	encoded, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		return nil, errors.New("encode Worker credential secret")
	}
	return append(encoded, '\n'), nil
}
