package cloudflare

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	// SupportedCFVersion is the technical-preview version whose command surface
	// this adapter has verified.
	SupportedCFVersion = "0.2.0"
)

// Provider identifies the executable responsible for an operation.
type Provider string

const (
	ProviderCF            Provider = "cf"
	ProviderWrangler      Provider = "wrangler"
	ProviderCloudflareAPI Provider = "cloudflare-api"
)

// CertificatePackAPI is the deliberately narrow REST surface used only when
// cf 0.2.0's OAuth session is denied access to certificate-pack operations.
// Implementations must keep credentials out of URLs, diagnostics, and child
// process environments.
type CertificatePackAPI interface {
	ListCertificatePacksPage(context.Context, string, int, int) ([]CertificatePack, error)
	DeleteCertificatePack(context.Context, string, string) error
}

// Options configures command locations without changing command semantics.
type Options struct {
	// ProjectDir is the explicit working directory for project-scoped cf and
	// project-local Wrangler commands. Callers may point it at an isolated
	// generated workspace such as .cf-vless/worker.
	ProjectDir string
	AccountID  string

	CFProgram         string
	WranglerProgram   string
	WranglerArgs      []string
	ExpectedCFVersion string

	// GlobalAPIKey is copied on construction and is used only for the narrowly
	// scoped certificate-pack fallback. CertificateAPI is an injectable test
	// seam; production callers should leave it nil.
	GlobalAPIKey   []byte
	CertificateAPI CertificatePackAPI
	// CertificateHTTPClient is an HTTP transport seam for tests. Production
	// callers should leave it nil so the bounded no-redirect client is used.
	CertificateHTTPClient *http.Client
}

// OperationResult is safe to log. Command is always the redacted diagnostic
// representation and command output is scrubbed of any supplied secret.
type OperationResult struct {
	Provider       Provider
	Command        string
	Stdout         string
	Stderr         string
	ExitCode       int
	DryRun         bool
	FallbackReason string
}

// CommandError contains only sanitized process information.
type CommandError struct {
	Provider Provider
	Command  string
	ExitCode int
	Stderr   string
	Cause    string
	unwrap   error
}

func (e *CommandError) Error() string {
	message := string(e.Provider) + " command failed: " + e.Command
	if e.ExitCode >= 0 {
		message += " (exit " + strconv.Itoa(e.ExitCode) + ")"
	}
	if e.Stderr != "" {
		message += ": " + e.Stderr
	} else if e.Cause != "" {
		message += ": " + e.Cause
	}
	return message
}

// Unwrap preserves only known, non-sensitive adapter sentinel errors. Raw
// process errors are represented by the sanitized Cause string instead.
func (e *CommandError) Unwrap() error {
	return e.unwrap
}

// AuthInfo deliberately excludes email and raw token metadata.
type AuthInfo struct {
	Authenticated bool
	TokenValid    bool
}

// WranglerAuthInfo contains only the minimum state needed to decide whether
// Wrangler can serve as the live-tail fallback. In particular, it deliberately
// excludes the email address, account names, authentication type, and token
// permissions returned by `wrangler whoami --json`.
type WranglerAuthInfo struct {
	LoggedIn          bool
	AccountAccessible bool
}

type Account struct {
	ID   string
	Name string
}

type AccountFilter struct {
	Name string
}

type Zone struct {
	ID          string
	Name        string
	Status      string
	AccountID   string
	AccountName string
}

type ZoneFilter struct {
	Name      string
	Status    string
	AccountID string
}

type DomainBinding struct {
	ID          string
	CertID      string
	Hostname    string
	Service     string
	Environment string
	ZoneID      string
	ZoneName    string
}

type CertificatePackCertificate struct {
	ID    string
	Hosts []string
}

type CertificatePack struct {
	ID           string
	Type         string
	Status       string
	Hosts        []string
	Certificates []CertificatePackCertificate
}

type DomainFilter struct {
	Hostname    string
	Service     string
	Environment string
	ZoneID      string
	ZoneName    string
}

type DNSRecord struct {
	ID      string
	Type    string
	Name    string
	Content string
}

type WorkerRoute struct {
	ID      string
	Pattern string
	Script  string
}

type HostnameCheckOptions struct {
	Hostname        string
	ZoneID          string
	ZoneName        string
	Worker          string
	OwnershipMarker string
}

type HostnameCheck struct {
	Available bool
	Owned     bool
	Message   string
	Domains   []DomainBinding
	Records   []DNSRecord
	Routes    []WorkerRoute
}

type SecretBinding struct {
	Name string
	Type string
}

type BuildOptions struct {
	Mode string
}

type DeployOptions struct {
	Mode     string
	Prebuilt bool
	Tag      string
	Message  string
	DryRun   bool
}

type WorkerStatus struct {
	Name            string
	Exists          bool
	OwnershipMarker string
	DeploymentCount int
	Domains         []DomainBinding
	Secrets         []SecretBinding
	Operations      []OperationResult
}

type SecretRequest struct {
	Worker          string
	OwnershipMarker string
	Name            string
	Value           []byte
}

type CustomDomainRequest struct {
	Hostname    string
	Worker      string
	Environment string
	ZoneID      string
	ZoneName    string
	DryRun      bool
}

type DomainBindResult struct {
	Existing   bool
	Changed    bool
	DryRun     bool
	Binding    DomainBinding
	Operations []OperationResult
}

type LogsOptions struct {
	Worker       string
	Statuses     []string
	Search       string
	SamplingRate *float64
	Stdout       io.Writer
	Stderr       io.Writer
}

type NamedResources struct {
	Worker                           string
	OwnershipMarker                  string
	Hostname                         string
	Environment                      string
	ZoneID                           string
	ZoneName                         string
	SecretNames                      []string
	ExpectedDomainID                 string
	EnforceExpectedDomainID          bool
	ExpectedCertificatePackID        string
	EnforceExpectedCertificatePackID bool
}

type RemoveOptions struct {
	Resources NamedResources
	Confirm   bool
	DryRun    bool
}

// RemovalPlan is the complete, non-secret set of remote resources selected by
// RemoveNamed after its ownership preflight. SecretNames contains binding names
// only; secret values are never read or returned.
type RemovalPlan struct {
	Worker             string   `json:"worker"`
	DeleteWorker       bool     `json:"delete_worker"`
	Hostname           string   `json:"hostname"`
	DomainIDs          []string `json:"domain_ids"`
	CertificatePackIDs []string `json:"certificate_pack_ids"`
	SecretNames        []string `json:"secret_names"`
}

type RemovalResult struct {
	DryRun                    bool
	Plan                      RemovalPlan
	RemovedDomainIDs          []string
	RemovedCertificatePackIDs []string
	RemovedSecrets            []string
	WorkerRemoved             bool
	Operations                []OperationResult
}

// Capability identifies one operational surface used by cf-vless.
type Capability string

const (
	CapabilityAuth            Capability = "auth"
	CapabilityAccounts        Capability = "accounts"
	CapabilityZones           Capability = "zones"
	CapabilityWorkerBuild     Capability = "worker_build"
	CapabilityWorkerDeploy    Capability = "worker_deploy"
	CapabilityWorkerStatus    Capability = "worker_status"
	CapabilitySingleSecret    Capability = "single_secret"
	CapabilityCustomDomain    Capability = "custom_domain"
	CapabilityStoredLogs      Capability = "stored_logs"
	CapabilityLiveLogs        Capability = "live_logs"
	CapabilityNamedRemoval    Capability = "named_removal"
	CapabilityTypeGeneration  Capability = "type_generation"
	CapabilityStartupProfile  Capability = "startup_profile"
	CapabilityBulkSecrets     Capability = "bulk_secrets"
	CapabilityTrafficRollback Capability = "traffic_rollback"
)

type CapabilityStatus struct {
	Capability Capability
	Provider   Provider
	Supported  bool
	Available  bool
	Required   bool
	Fallback   bool
	Reason     string
}

type CapabilityReport struct {
	CFVersion       string
	WranglerVersion string
	CFCompatible    bool
	Items           []CapabilityStatus
}

type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarning CheckStatus = "warning"
	CheckSkipped CheckStatus = "skipped"
)

type DoctorCheck struct {
	Name     string
	Status   CheckStatus
	Required bool
	Provider Provider
	Message  string
}

type DoctorOptions struct {
	AccountID       string
	ZoneName        string
	Hostname        string
	Worker          string
	OwnershipMarker string
}

type DoctorResult struct {
	CheckedAt       time.Time
	Healthy         bool
	CFVersion       string
	WranglerVersion string
	Auth            AuthInfo
	WranglerAuth    WranglerAuthInfo
	Accounts        []Account
	Zones           []Zone
	Capabilities    CapabilityReport
	Checks          []DoctorCheck
}

var (
	ErrConfirmationRequired        = errors.New("explicit confirmation is required")
	ErrInteractiveTerminalRequired = errors.New("an interactive terminal is required for safe Worker deletion")
	ErrResourceConflict            = errors.New("named resource belongs to a different deployment")
	ErrCertificatePackPending      = errors.New("generated certificate pack is not yet visible")
	ErrWorkerNotFound              = errors.New("named Worker does not exist")
)
