package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	liveLogsFallbackReason = "cf 0.2.0 can create a tail session but does not attach to and stream its WebSocket"
	secretCFReason         = "cf 0.2.0 consumes an omitted --text value from protected non-TTY stdin, keeping the secret out of argv"
	namedRemovalReason     = "exact domain, generated certificate pack, and secret deletion is noninteractive; safe Worker deletion requires a real terminal because cf 0.2.0 --force also permits deletion of associated bindings and Durable Objects"
)

var semanticVersionPattern = regexp.MustCompile(`(?m)(?:^|[^0-9])v?([0-9]+\.[0-9]+\.[0-9]+)(?:$|[^0-9])`)

// Client constructs and executes the exact command surface verified for cf
// 0.2.0, with narrowly-scoped Wrangler fallbacks.
type Client struct {
	runner Runner

	projectDir string
	accountID  string

	cfProgram         string
	wranglerProgram   string
	wranglerArgs      []string
	expectedCFVersion string
	globalAPIKey      []byte
	certificateAPI    CertificatePackAPI
	certificateHTTP   *http.Client
}

// NewClient creates a command adapter. A nil Runner is rejected because all
// execution must remain injectable and testable.
func NewClient(runner Runner, options Options) (*Client, error) {
	if runner == nil {
		return nil, fmt.Errorf("cloudflare runner is required")
	}

	if options.ProjectDir == "" {
		options.ProjectDir = "."
	}
	if options.CFProgram == "" {
		options.CFProgram = "cf"
	}
	if options.ExpectedCFVersion == "" {
		options.ExpectedCFVersion = SupportedCFVersion
	}
	if options.WranglerProgram == "" {
		options.WranglerProgram = "npx"
		if options.WranglerArgs == nil {
			options.WranglerArgs = []string{"--no-install", "wrangler"}
		}
	}
	if options.AccountID != "" {
		if err := validateCloudflareID("account ID", options.AccountID); err != nil {
			return nil, err
		}
	}
	if len(options.GlobalAPIKey) > 0 && !globalAPIKeyPattern.Match(options.GlobalAPIKey) {
		return nil, errors.New("Cloudflare Global API Key does not match a supported Cloudflare key format")
	}

	return &Client{
		runner:            runner,
		projectDir:        options.ProjectDir,
		accountID:         options.AccountID,
		cfProgram:         options.CFProgram,
		wranglerProgram:   options.WranglerProgram,
		wranglerArgs:      append([]string(nil), options.WranglerArgs...),
		expectedCFVersion: options.ExpectedCFVersion,
		globalAPIKey:      append([]byte(nil), options.GlobalAPIKey...),
		certificateAPI:    options.CertificateAPI,
		certificateHTTP:   options.CertificateHTTPClient,
	}, nil
}

func (c *Client) cfGlobalCommand(args ...string) Command {
	return Command{Program: c.cfProgram, Args: append([]string(nil), args...)}
}

func (c *Client) cfWorkerCommand(args ...string) Command {
	command := Command{
		Program: c.cfProgram,
		Args:    append([]string(nil), args...),
		Dir:     c.projectDir,
	}
	if c.accountID != "" {
		command = command.withEnvironment("CLOUDFLARE_ACCOUNT_ID=" + c.accountID)
	}
	return command
}

func (c *Client) wranglerCommand(args ...string) Command {
	allArgs := make([]string, 0, len(c.wranglerArgs)+len(args))
	allArgs = append(allArgs, c.wranglerArgs...)
	allArgs = append(allArgs, args...)
	command := Command{Program: c.wranglerProgram, Args: allArgs, Dir: c.projectDir}
	if c.accountID != "" {
		command = command.withEnvironment("CLOUDFLARE_ACCOUNT_ID=" + c.accountID)
	}
	return command
}

func (c *Client) execute(
	ctx context.Context,
	provider Provider,
	command Command,
	dryRun bool,
	redactions ...[]byte,
) (OperationResult, error) {
	runResult, runErr := c.runner.Run(ctx, command)
	operation := OperationResult{
		Provider: provider,
		Command:  command.String(),
		Stdout:   redactText(runResult.Stdout, redactions...),
		Stderr:   redactText(runResult.Stderr, redactions...),
		ExitCode: runResult.ExitCode,
		DryRun:   dryRun,
	}
	if runErr == nil {
		return operation, nil
	}
	if ctx.Err() != nil {
		return operation, ctx.Err()
	}

	commandError := &CommandError{
		Provider: provider,
		Command:  operation.Command,
		ExitCode: operation.ExitCode,
		Stderr:   compactDiagnostic(operation.Stderr),
		Cause:    compactDiagnostic(redactText(runErr.Error(), redactions...)),
	}
	if errors.Is(runErr, ErrInteractiveTerminalRequired) {
		commandError.unwrap = ErrInteractiveTerminalRequired
	}
	return operation, commandError
}

func redactText(value string, redactions ...[]byte) string {
	redacted := []byte(value)
	for _, secret := range redactions {
		if len(secret) == 0 {
			continue
		}
		redacted = bytes.ReplaceAll(redacted, secret, []byte("[REDACTED]"))
		quoted := strconv.Quote(string(secret))
		if len(quoted) >= 2 {
			escaped := []byte(quoted[1 : len(quoted)-1])
			if !bytes.Equal(escaped, secret) {
				redacted = bytes.ReplaceAll(redacted, escaped, []byte("[REDACTED]"))
			}
		}
	}
	return string(redacted)
}

func compactDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	const maximum = 4096
	if len(value) <= maximum {
		return value
	}
	return value[:maximum] + "...[truncated]"
}

// CFVersion returns the installed cf version.
func (c *Client) CFVersion(ctx context.Context) (string, error) {
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand("--version"), false)
	if err != nil {
		return "", err
	}
	return extractVersion(operation.Stdout + "\n" + operation.Stderr)
}

// RequireSupportedCFVersion verifies the exact technical-preview cf command
// schema before a command performs any provider mutation. Callers should run
// this once at command-level preflight rather than repeating it inside each
// low-level operation in a multi-step transaction.
func (c *Client) RequireSupportedCFVersion(ctx context.Context) error {
	version, err := c.CFVersion(ctx)
	if err != nil {
		return fmt.Errorf("verify cf version: %w", err)
	}
	if version != SupportedCFVersion {
		return fmt.Errorf("installed cf %s does not match required version %s", version, SupportedCFVersion)
	}
	return nil
}

// WranglerVersion returns the project-local Wrangler fallback version without
// allowing npx to install a missing package.
func (c *Client) WranglerVersion(ctx context.Context) (string, error) {
	operation, err := c.execute(ctx, ProviderWrangler, c.wranglerCommand("--version"), false)
	if err != nil {
		return "", err
	}
	return extractVersion(operation.Stdout + "\n" + operation.Stderr)
}

// WranglerAuthentication verifies the separate Wrangler credential store used
// by the live-tail fallback. Wrangler's JSON response also contains an email
// address, account names, authentication details, and token permissions; those
// fields are intentionally ignored and never included in the returned value.
func (c *Client) WranglerAuthentication(ctx context.Context, accountID string) (WranglerAuthInfo, error) {
	if accountID == "" {
		accountID = c.accountID
	}
	if accountID != "" {
		if err := validateCloudflareID("account ID", accountID); err != nil {
			return WranglerAuthInfo{}, err
		}
	}

	operation, commandErr := c.execute(ctx, ProviderWrangler, c.wranglerCommand("whoami", "--json"), false)
	var response struct {
		LoggedIn *bool `json:"loggedIn"`
		Accounts []struct {
			ID string `json:"id"`
		} `json:"accounts"`
	}
	decodeErr := json.Unmarshal([]byte(operation.Stdout), &response)
	if commandErr != nil {
		// Wrangler emits {"loggedIn":false} as its structured unauthenticated
		// result while still exiting unsuccessfully. Treat that explicit state as
		// a valid health result, but preserve every other command failure.
		if decodeErr == nil && response.LoggedIn != nil && !*response.LoggedIn {
			return WranglerAuthInfo{}, nil
		}
		return WranglerAuthInfo{}, commandErr
	}
	if decodeErr != nil {
		return WranglerAuthInfo{}, fmt.Errorf("decode Wrangler authentication status: %w", decodeErr)
	}
	if response.LoggedIn == nil {
		return WranglerAuthInfo{}, fmt.Errorf("decode Wrangler authentication status: loggedIn is missing")
	}

	info := WranglerAuthInfo{LoggedIn: *response.LoggedIn}
	if !info.LoggedIn {
		return info, nil
	}
	if accountID == "" {
		info.AccountAccessible = len(response.Accounts) > 0
		return info, nil
	}
	for _, account := range response.Accounts {
		if account.ID == accountID {
			info.AccountAccessible = true
			break
		}
	}
	return info, nil
}

func extractVersion(output string) (string, error) {
	match := semanticVersionPattern.FindStringSubmatch(output)
	if len(match) != 2 {
		return "", fmt.Errorf("could not parse semantic version from command output")
	}
	return match[1], nil
}

// Authentication checks cf's OAuth/token status while discarding PII and
// detailed token scopes from the returned structure.
func (c *Client) Authentication(ctx context.Context) (AuthInfo, error) {
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand("auth", "whoami"), false)
	if err != nil {
		return AuthInfo{}, err
	}
	var response struct {
		Authenticated bool `json:"authenticated"`
		TokenValid    bool `json:"tokenValid"`
	}
	if err := json.Unmarshal([]byte(operation.Stdout), &response); err != nil {
		return AuthInfo{}, fmt.Errorf("decode cf authentication status: %w", err)
	}
	return AuthInfo{
		Authenticated: response.Authenticated,
		TokenValid:    response.TokenValid,
	}, nil
}

// ListAccounts reads accessible accounts.
func (c *Client) ListAccounts(ctx context.Context, filter AccountFilter) ([]Account, error) {
	if filter.Name != "" {
		if err := validateArgument("account name", filter.Name); err != nil {
			return nil, err
		}
	}
	args := []string{"accounts", "list"}
	if filter.Name != "" {
		args = append(args, "--name", filter.Name)
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(args...), false)
	if err != nil {
		return nil, err
	}
	objects, err := decodeObjectList(operation.Stdout)
	if err != nil {
		return nil, fmt.Errorf("decode cf accounts: %w", err)
	}
	accounts := make([]Account, 0, len(objects))
	for _, object := range objects {
		accounts = append(accounts, Account{
			ID:   firstString(object, "id", "account_id"),
			Name: firstString(object, "name"),
		})
	}
	return accounts, nil
}

// ListZones reads zones with exact argv filters.
func (c *Client) ListZones(ctx context.Context, filter ZoneFilter) ([]Zone, error) {
	if filter.Name != "" {
		normalized, err := normalizeHostname("zone name", filter.Name)
		if err != nil {
			return nil, err
		}
		filter.Name = normalized
	}
	if filter.AccountID != "" {
		if err := validateCloudflareID("account ID", filter.AccountID); err != nil {
			return nil, err
		}
	}
	if filter.Status != "" && !oneOf(filter.Status, "initializing", "pending", "active", "moved") {
		return nil, fmt.Errorf("unsupported zone status %q", filter.Status)
	}

	args := []string{"zones", "list"}
	if filter.Name != "" {
		args = append(args, "--name", filter.Name)
	}
	if filter.Status != "" {
		args = append(args, "--status", filter.Status)
	}
	if filter.AccountID != "" {
		args = append(args, "--account-id", filter.AccountID)
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(args...), false)
	if err != nil {
		return nil, err
	}
	objects, err := decodeObjectList(operation.Stdout)
	if err != nil {
		return nil, fmt.Errorf("decode cf zones: %w", err)
	}
	zones := make([]Zone, 0, len(objects))
	for _, object := range objects {
		account := nestedObject(object, "account")
		zones = append(zones, Zone{
			ID:          firstString(object, "id", "zone_id"),
			Name:        firstString(object, "name"),
			Status:      firstString(object, "status"),
			AccountID:   firstString(account, "id", "account_id"),
			AccountName: firstString(account, "name"),
		})
	}
	return zones, nil
}

// Capabilities reports which verified cf operations and Wrangler fallbacks are
// usable for the supplied discovered versions.
func (c *Client) Capabilities(cfVersion, wranglerVersion string) CapabilityReport {
	cfAvailable := cfVersion == c.expectedCFVersion
	wranglerAvailable := versionMajorAtLeast(wranglerVersion, 4)

	cfItem := func(capability Capability, required bool) CapabilityStatus {
		reason := "supported by the verified cf " + c.expectedCFVersion + " command surface"
		if !cfAvailable {
			reason = "installed cf version is not the verified technical-preview version " + c.expectedCFVersion
		}
		return CapabilityStatus{
			Capability: capability,
			Provider:   ProviderCF,
			Supported:  true,
			Available:  cfAvailable,
			Required:   required,
			Reason:     reason,
		}
	}
	wranglerItem := func(capability Capability, required bool, reason string) CapabilityStatus {
		return CapabilityStatus{
			Capability: capability,
			Provider:   ProviderWrangler,
			Supported:  true,
			Available:  wranglerAvailable,
			Required:   required,
			Fallback:   true,
			Reason:     reason,
		}
	}
	namedRemoval := cfItem(CapabilityNamedRemoval, true)
	if cfAvailable {
		namedRemoval.Reason = namedRemovalReason
	}
	singleSecret := cfItem(CapabilitySingleSecret, true)
	if cfAvailable {
		singleSecret.Reason = secretCFReason
	}

	items := []CapabilityStatus{
		cfItem(CapabilityAuth, true),
		cfItem(CapabilityAccounts, true),
		cfItem(CapabilityZones, true),
		cfItem(CapabilityWorkerBuild, true),
		cfItem(CapabilityWorkerDeploy, true),
		cfItem(CapabilityWorkerStatus, true),
		singleSecret,
		cfItem(CapabilityCustomDomain, true),
		cfItem(CapabilityStoredLogs, false),
		namedRemoval,
		wranglerItem(CapabilityLiveLogs, true, liveLogsFallbackReason),
		wranglerItem(CapabilityTypeGeneration, false, "cf 0.2.0 has no binding type-generation command"),
		wranglerItem(CapabilityStartupProfile, false, "cf 0.2.0 has no startup profiling command"),
		wranglerItem(CapabilityBulkSecrets, false, "cf 0.2.0 has no high-level Worker secret bulk command"),
		wranglerItem(CapabilityTrafficRollback, false, "cf 0.2.0 has no high-level rollback workflow"),
	}

	return CapabilityReport{
		CFVersion:       cfVersion,
		WranglerVersion: wranglerVersion,
		CFCompatible:    cfAvailable,
		Items:           items,
	}
}

func versionMajorAtLeast(version string, minimum int) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	major, err := strconv.Atoi(parts[0])
	return err == nil && major >= minimum
}

// Doctor performs read-only checks and returns failures as structured checks.
func (c *Client) Doctor(ctx context.Context, options DoctorOptions) (DoctorResult, error) {
	result := DoctorResult{CheckedAt: time.Now().UTC()}

	cfVersion, cfErr := c.CFVersion(ctx)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if cfErr != nil {
		result.Checks = append(result.Checks, failedCheck("cf.version", ProviderCF, cfErr))
	} else {
		result.CFVersion = cfVersion
		if cfVersion == c.expectedCFVersion {
			result.Checks = append(result.Checks, passedCheck("cf.version", ProviderCF, "verified cf "+cfVersion+" is installed"))
		} else {
			result.Checks = append(result.Checks, DoctorCheck{
				Name:     "cf.version",
				Status:   CheckFail,
				Required: true,
				Provider: ProviderCF,
				Message:  "installed cf " + cfVersion + " does not match verified preview " + c.expectedCFVersion,
			})
		}
	}

	wranglerVersion, wranglerErr := c.WranglerVersion(ctx)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if wranglerErr != nil {
		result.Checks = append(result.Checks, failedCheck("wrangler.version", ProviderWrangler, wranglerErr))
	} else {
		result.WranglerVersion = wranglerVersion
		if versionMajorAtLeast(wranglerVersion, 4) {
			result.Checks = append(result.Checks, passedCheck("wrangler.version", ProviderWrangler, "project Wrangler "+wranglerVersion+" is available for explicit fallbacks"))
		} else {
			result.Checks = append(result.Checks, DoctorCheck{
				Name:     "wrangler.version",
				Status:   CheckFail,
				Required: true,
				Provider: ProviderWrangler,
				Message:  "Wrangler v4 or newer is required for fallback operations",
			})
		}
	}

	wranglerReady := wranglerErr == nil && versionMajorAtLeast(wranglerVersion, 4)
	if wranglerReady {
		accountID := options.AccountID
		if accountID == "" {
			accountID = c.accountID
		}
		auth, err := c.WranglerAuthentication(ctx, accountID)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Checks = append(result.Checks,
				failedCheck("wrangler.authentication", ProviderWrangler, err),
				DoctorCheck{
					Name:     "wrangler.account_access",
					Status:   CheckSkipped,
					Required: true,
					Provider: ProviderWrangler,
					Message:  "account access was not checked because Wrangler authentication could not be read",
				},
			)
		} else {
			result.WranglerAuth = auth
			if auth.LoggedIn {
				result.Checks = append(result.Checks, passedCheck("wrangler.authentication", ProviderWrangler, "Wrangler authentication is available for the live-tail fallback"))
			} else {
				result.Checks = append(result.Checks, DoctorCheck{
					Name:     "wrangler.authentication",
					Status:   CheckFail,
					Required: true,
					Provider: ProviderWrangler,
					Message:  "Wrangler is not authenticated; the live-tail fallback cannot run",
				})
			}
			if !auth.LoggedIn {
				result.Checks = append(result.Checks, DoctorCheck{
					Name:     "wrangler.account_access",
					Status:   CheckSkipped,
					Required: true,
					Provider: ProviderWrangler,
					Message:  "account access was not checked because Wrangler is not authenticated",
				})
			} else if auth.AccountAccessible {
				result.Checks = append(result.Checks, passedCheck("wrangler.account_access", ProviderWrangler, "the configured Cloudflare account is accessible to Wrangler"))
			} else {
				result.Checks = append(result.Checks, DoctorCheck{
					Name:     "wrangler.account_access",
					Status:   CheckFail,
					Required: true,
					Provider: ProviderWrangler,
					Message:  "the configured Cloudflare account is not accessible to Wrangler",
				})
			}
		}
	} else {
		result.Checks = append(result.Checks,
			DoctorCheck{
				Name:     "wrangler.authentication",
				Status:   CheckSkipped,
				Required: true,
				Provider: ProviderWrangler,
				Message:  "authentication was not checked because a supported Wrangler is unavailable",
			},
			DoctorCheck{
				Name:     "wrangler.account_access",
				Status:   CheckSkipped,
				Required: true,
				Provider: ProviderWrangler,
				Message:  "account access was not checked because a supported Wrangler is unavailable",
			},
		)
	}

	result.Capabilities = c.Capabilities(result.CFVersion, result.WranglerVersion)

	if cfErr == nil {
		auth, err := c.Authentication(ctx)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Checks = append(result.Checks, failedCheck("cf.authentication", ProviderCF, err))
		} else {
			result.Auth = auth
			if auth.Authenticated && auth.TokenValid {
				result.Checks = append(result.Checks, passedCheck("cf.authentication", ProviderCF, "Cloudflare authentication is valid"))
			} else {
				result.Checks = append(result.Checks, DoctorCheck{
					Name:     "cf.authentication",
					Status:   CheckFail,
					Required: true,
					Provider: ProviderCF,
					Message:  "Cloudflare authentication is missing or expired",
				})
			}
		}

		if result.Auth.Authenticated && result.Auth.TokenValid {
			accounts, err := c.ListAccounts(ctx, AccountFilter{})
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			if err != nil {
				result.Checks = append(result.Checks, failedCheck("cf.account_access", ProviderCF, err))
			} else {
				result.Accounts = accounts
				accountOK := len(accounts) > 0
				if options.AccountID != "" {
					accountOK = containsAccount(accounts, options.AccountID)
				}
				if accountOK {
					result.Checks = append(result.Checks, passedCheck("cf.account_access", ProviderCF, "Cloudflare account access is available"))
				} else {
					result.Checks = append(result.Checks, DoctorCheck{
						Name:     "cf.account_access",
						Status:   CheckFail,
						Required: true,
						Provider: ProviderCF,
						Message:  "requested Cloudflare account is not accessible",
					})
				}
			}
		} else {
			result.Checks = append(result.Checks, DoctorCheck{
				Name:     "cf.account_access",
				Status:   CheckSkipped,
				Required: true,
				Provider: ProviderCF,
				Message:  "account access was not checked because Cloudflare authentication is unavailable",
			})
		}
	} else {
		result.Checks = append(result.Checks,
			DoctorCheck{
				Name:     "cf.authentication",
				Status:   CheckSkipped,
				Required: true,
				Provider: ProviderCF,
				Message:  "authentication was not checked because cf is unavailable",
			},
			DoctorCheck{
				Name:     "cf.account_access",
				Status:   CheckSkipped,
				Required: true,
				Provider: ProviderCF,
				Message:  "account access was not checked because cf is unavailable",
			},
		)
	}

	if options.ZoneName == "" {
		result.Checks = append(result.Checks, DoctorCheck{
			Name:     "cf.zone_access",
			Status:   CheckSkipped,
			Required: false,
			Provider: ProviderCF,
			Message:  "no zone name supplied",
		})
	} else if result.Auth.Authenticated && result.Auth.TokenValid {
		accountID := options.AccountID
		if accountID == "" {
			accountID = c.accountID
		}
		zones, err := c.ListZones(ctx, ZoneFilter{Name: options.ZoneName, AccountID: accountID})
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Checks = append(result.Checks, failedCheck("cf.zone_access", ProviderCF, err))
		} else {
			result.Zones = zones
			zoneOK := false
			for _, zone := range zones {
				if strings.EqualFold(zone.Name, options.ZoneName) && zone.Status == "active" {
					zoneOK = true
					break
				}
			}
			if zoneOK {
				result.Checks = append(result.Checks, passedCheck("cf.zone_access", ProviderCF, "requested Cloudflare zone is active and accessible"))
			} else {
				result.Checks = append(result.Checks, DoctorCheck{
					Name:     "cf.zone_access",
					Status:   CheckFail,
					Required: true,
					Provider: ProviderCF,
					Message:  "requested Cloudflare zone is not active and accessible",
				})
			}
		}
	} else {
		result.Checks = append(result.Checks, DoctorCheck{
			Name:     "cf.zone_access",
			Status:   CheckSkipped,
			Required: true,
			Provider: ProviderCF,
			Message:  "zone access was not checked because Cloudflare authentication is unavailable",
		})
	}

	activeZone := exactlyOneActiveZone(result.Zones, options.ZoneName)
	if options.ZoneName == "" {
		result.Checks = append(result.Checks, DoctorCheck{
			Name: "cf.certificate_access", Status: CheckSkipped, Required: false, Provider: ProviderCF,
			Message: "no zone name supplied",
		})
	} else if activeZone == nil {
		result.Checks = append(result.Checks, DoctorCheck{
			Name: "cf.certificate_access", Status: CheckSkipped, Required: true, Provider: ProviderCF,
			Message: "certificate inventory was not checked because exactly one active zone was not resolved",
		})
	} else {
		_, _, err := c.ListCertificatePacks(ctx, activeZone.ID)
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err != nil {
			result.Checks = append(result.Checks, failedCheck("cf.certificate_access", ProviderCF, err))
		} else {
			result.Checks = append(result.Checks, passedCheck("cf.certificate_access", ProviderCF,
				"Advanced Certificate inventory is accessible for reproducible Custom Domain removal"))
		}
	}

	if options.Hostname == "" {
		result.Checks = append(result.Checks, DoctorCheck{
			Name:     "cf.hostname_availability",
			Status:   CheckSkipped,
			Required: false,
			Provider: ProviderCF,
			Message:  "no dedicated hostname supplied",
		})
	} else if result.Auth.Authenticated && result.Auth.TokenValid {
		if activeZone == nil {
			result.Checks = append(result.Checks, DoctorCheck{
				Name: "cf.hostname_availability", Status: CheckFail, Required: true, Provider: ProviderCF,
				Message: "hostname was not checked because exactly one active zone was not resolved",
			})
		} else {
			check, err := c.CheckHostnameAvailability(ctx, HostnameCheckOptions{
				Hostname: options.Hostname, ZoneID: activeZone.ID, ZoneName: activeZone.Name,
				Worker: options.Worker, OwnershipMarker: options.OwnershipMarker,
			})
			if err != nil {
				result.Checks = append(result.Checks, failedCheck("cf.hostname_availability", ProviderCF, err))
			} else if check.Available {
				result.Checks = append(result.Checks, passedCheck("cf.hostname_availability", ProviderCF, check.Message))
			} else {
				result.Checks = append(result.Checks, DoctorCheck{
					Name: "cf.hostname_availability", Status: CheckFail, Required: true, Provider: ProviderCF, Message: check.Message,
				})
			}
		}
	} else {
		result.Checks = append(result.Checks, DoctorCheck{
			Name: "cf.hostname_availability", Status: CheckSkipped, Required: true, Provider: ProviderCF,
			Message: "hostname was not checked because Cloudflare authentication is unavailable",
		})
	}

	capabilitiesOK := true
	for _, capability := range result.Capabilities.Items {
		if capability.Required && !capability.Available {
			capabilitiesOK = false
			break
		}
	}
	if capabilitiesOK {
		result.Checks = append(result.Checks, passedCheck("cli.capabilities", ProviderCF, "all required cf and Wrangler fallback capabilities are available"))
	} else {
		result.Checks = append(result.Checks, DoctorCheck{
			Name:     "cli.capabilities",
			Status:   CheckFail,
			Required: true,
			Provider: ProviderCF,
			Message:  "one or more required command capabilities are unavailable",
		})
	}

	result.Healthy = true
	for _, check := range result.Checks {
		if check.Required && check.Status != CheckPass {
			result.Healthy = false
			break
		}
	}
	return result, nil
}

func exactlyOneActiveZone(zones []Zone, name string) *Zone {
	var active *Zone
	for index := range zones {
		if !strings.EqualFold(zones[index].Name, name) || zones[index].Status != "active" {
			continue
		}
		if active != nil {
			return nil
		}
		active = &zones[index]
	}
	return active
}

func containsAccount(accounts []Account, id string) bool {
	for _, account := range accounts {
		if account.ID == id {
			return true
		}
	}
	return false
}

func passedCheck(name string, provider Provider, message string) DoctorCheck {
	return DoctorCheck{Name: name, Status: CheckPass, Required: true, Provider: provider, Message: message}
}

func failedCheck(name string, provider Provider, err error) DoctorCheck {
	return DoctorCheck{Name: name, Status: CheckFail, Required: true, Provider: provider, Message: compactDiagnostic(err.Error())}
}
