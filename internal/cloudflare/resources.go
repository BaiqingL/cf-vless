package cloudflare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const vlessCredentialSecretName = "VLESS_CREDENTIALS"

var managedWorkerBindingTypes = map[string]string{
	"EXPECTED_HOST":           "plain_text",
	"DEPLOYMENT_MARKER":       "plain_text",
	"ALLOWED_PORTS":           "plain_text",
	"HANDSHAKE_TIMEOUT_MS":    "plain_text",
	"CONNECT_TIMEOUT_MS":      "plain_text",
	"IDLE_TIMEOUT_MS":         "plain_text",
	"SESSION_TIMEOUT_MS":      "plain_text",
	vlessCredentialSecretName: "secret_text",
}

// Build builds the project rooted at Options.ProjectDir with cf.
func (c *Client) Build(ctx context.Context, options BuildOptions) (OperationResult, error) {
	args := []string{"build"}
	if options.Mode != "" {
		if err := validateArgument("build mode", options.Mode); err != nil {
			return OperationResult{}, err
		}
		args = append(args, "--mode", options.Mode)
	}
	return c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), false)
}

// Deploy builds and deploys the project rooted at Options.ProjectDir with cf.
func (c *Client) Deploy(ctx context.Context, options DeployOptions) (OperationResult, error) {
	args := []string{"deploy"}
	if options.Mode != "" {
		if err := validateArgument("deploy mode", options.Mode); err != nil {
			return OperationResult{}, err
		}
		args = append(args, "--mode", options.Mode)
	}
	if options.Prebuilt {
		args = append(args, "--prebuilt")
	}
	if options.Tag != "" {
		if err := validateArgument("deployment tag", options.Tag); err != nil {
			return OperationResult{}, err
		}
		args = append(args, "--tag", options.Tag)
	}
	if options.Message != "" {
		if err := validateArgument("deployment message", options.Message); err != nil {
			return OperationResult{}, err
		}
		args = append(args, "--message", options.Message)
	}
	if options.DryRun {
		args = append(args, "--dry-run")
	}
	return c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), options.DryRun)
}

func (c *Client) listScripts(ctx context.Context) ([]string, OperationResult, error) {
	operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand("workers", "scripts", "list"), false)
	if err != nil {
		return nil, operation, err
	}
	names, err := parseScriptNames(operation.Stdout)
	if err != nil {
		return nil, operation, fmt.Errorf("decode cf Worker scripts: %w", err)
	}
	return names, operation, nil
}

func (c *Client) listDeployments(ctx context.Context, worker string) (int, OperationResult, error) {
	operation, err := c.execute(
		ctx,
		ProviderCF,
		c.cfWorkerCommand("workers", "deployments", "list", "--worker", worker),
		false,
	)
	if err != nil {
		return 0, operation, err
	}
	objects, err := decodeObjectList(operation.Stdout)
	if err != nil {
		return 0, operation, fmt.Errorf("decode cf Worker deployments: %w", err)
	}
	return len(objects), operation, nil
}

func (c *Client) workerOwnershipMarker(ctx context.Context, worker string) (string, OperationResult, error) {
	if err := validateWorkerName(worker); err != nil {
		return "", OperationResult{}, err
	}
	operation, err := c.execute(
		ctx,
		ProviderCF,
		c.cfWorkerCommand("workers", "scripts", "script-and-version-settings", "get", "--worker", worker),
		false,
	)
	if err != nil {
		return "", operation, err
	}
	marker, err := parseOwnershipMarker(operation.Stdout, "DEPLOYMENT_MARKER")
	if err != nil {
		return "", operation, fmt.Errorf("decode Worker ownership marker: %w", err)
	}
	return marker, operation, nil
}

func validateManagedWorkerBindings(output string) error {
	bindings, err := parseWorkerBindings(output)
	if err != nil {
		return fmt.Errorf("decode Worker binding inventory: %w", err)
	}
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		expectedType, managed := managedWorkerBindingTypes[binding.Name]
		if !managed || binding.Type != expectedType {
			return fmt.Errorf("%w: Worker has an unplanned binding", ErrResourceConflict)
		}
		if _, duplicate := seen[binding.Name]; duplicate {
			return fmt.Errorf("%w: Worker has duplicate bindings", ErrResourceConflict)
		}
		seen[binding.Name] = struct{}{}
	}
	return nil
}

// ListDomains reads exact custom-domain bindings. Every non-empty filter is
// represented as its own argv entry.
func (c *Client) ListDomains(ctx context.Context, filter DomainFilter) ([]DomainBinding, OperationResult, error) {
	var err error
	if filter.Hostname != "" {
		filter.Hostname, err = normalizeHostname("domain hostname", filter.Hostname)
		if err != nil {
			return nil, OperationResult{}, err
		}
	}
	if filter.Service != "" {
		if err := validateWorkerName(filter.Service); err != nil {
			return nil, OperationResult{}, err
		}
	}
	if filter.Environment != "" {
		if err := validateArgument("Worker environment", filter.Environment); err != nil {
			return nil, OperationResult{}, err
		}
	}
	if filter.ZoneID != "" {
		if err := validateCloudflareID("zone ID", filter.ZoneID); err != nil {
			return nil, OperationResult{}, err
		}
	}
	if filter.ZoneName != "" {
		filter.ZoneName, err = normalizeHostname("zone name", filter.ZoneName)
		if err != nil {
			return nil, OperationResult{}, err
		}
	}

	args := []string{"workers", "domains", "list"}
	if filter.ZoneID != "" {
		args = append(args, "--zone-id", filter.ZoneID)
	}
	if filter.ZoneName != "" {
		args = append(args, "--zone-name", filter.ZoneName)
	}
	if filter.Service != "" {
		args = append(args, "--service", filter.Service)
	}
	if filter.Hostname != "" {
		args = append(args, "--hostname", filter.Hostname)
	}
	if filter.Environment != "" {
		args = append(args, "--environment", filter.Environment)
	}

	operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), false)
	if err != nil {
		return nil, operation, err
	}
	domains, err := parseDomains(operation.Stdout)
	if err != nil {
		return nil, operation, fmt.Errorf("decode cf Worker domains: %w", err)
	}
	return domains, operation, nil
}

// ListCertificatePacks returns every certificate-pack status so removal can
// identify the exact Advanced pack generated for a Worker Custom Domain.
func (c *Client) ListCertificatePacks(ctx context.Context, zoneID string) ([]CertificatePack, OperationResult, error) {
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return nil, OperationResult{}, err
	}
	const pageSize = 50 // Cloudflare API maximum.
	const maximumPages = 100
	all := make([]CertificatePack, 0, pageSize)
	var last OperationResult
	for page := 1; page <= maximumPages; page++ {
		operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(
			"ssl", "certificate-packs", "list",
			"--status", "all", "--page", strconv.Itoa(page), "--per-page", strconv.Itoa(pageSize), "--zone", zoneID,
		), false)
		last = operation
		if err != nil {
			if page == 1 && certificateAuthorizationDenied(err) {
				api, apiErr := c.certificateAPIForFallback(ctx)
				if apiErr != nil {
					return nil, operation, apiErr
				}
				if api != nil {
					return listCertificatePacksWithAPI(ctx, api, zoneID)
				}
			}
			return nil, operation, err
		}
		packs, err := parseCertificatePacks(operation.Stdout)
		if err != nil {
			return nil, operation, fmt.Errorf("decode cf certificate packs: %w", err)
		}
		if len(packs) > pageSize {
			return nil, operation, errors.New("cf certificate pack page exceeded the requested bound")
		}
		all = append(all, packs...)
		if len(packs) < pageSize {
			return all, operation, nil
		}
	}
	return nil, last, errors.New("certificate pack inventory exceeds the safe pagination bound")
}

func listCertificatePacksWithAPI(
	ctx context.Context,
	api CertificatePackAPI,
	zoneID string,
) ([]CertificatePack, OperationResult, error) {
	const pageSize = 50
	const maximumPages = 100
	operation := OperationResult{
		Provider:       ProviderCloudflareAPI,
		Command:        certificateAPIListDiagnostic,
		ExitCode:       0,
		FallbackReason: certificateAPIFallbackReason,
	}
	all := make([]CertificatePack, 0, pageSize)
	for page := 1; page <= maximumPages; page++ {
		packs, err := api.ListCertificatePacksPage(ctx, zoneID, page, pageSize)
		if err != nil {
			operation.ExitCode = -1
			return nil, operation, err
		}
		if len(packs) > pageSize {
			operation.ExitCode = -1
			return nil, operation, errors.New("Cloudflare certificate API page exceeded the requested bound")
		}
		all = append(all, packs...)
		if len(packs) < pageSize {
			return all, operation, nil
		}
	}
	operation.ExitCode = -1
	return nil, operation, errors.New("certificate pack inventory exceeds the safe pagination bound")
}

func (c *Client) deleteCertificatePack(
	ctx context.Context,
	zoneID string,
	packID string,
	dryRun bool,
) (OperationResult, error) {
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return OperationResult{}, err
	}
	if err := validateCertificatePackID("certificate pack ID", packID); err != nil {
		return OperationResult{}, err
	}
	args := []string{"ssl", "certificate-packs", "delete", packID, "--zone", zoneID, "--force"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(args...), dryRun)
	if err == nil || dryRun || !certificateAuthorizationDenied(err) {
		return operation, err
	}
	api, apiErr := c.certificateAPIForFallback(ctx)
	if apiErr != nil {
		return operation, apiErr
	}
	if api == nil {
		return operation, err
	}
	apiOperation := OperationResult{
		Provider:       ProviderCloudflareAPI,
		Command:        certificateAPIDeleteDiagnostic,
		FallbackReason: certificateAPIFallbackReason,
	}
	if apiErr := api.DeleteCertificatePack(ctx, zoneID, packID); apiErr != nil {
		apiOperation.ExitCode = -1
		return apiOperation, apiErr
	}
	return apiOperation, nil
}

func (c *Client) ListDNSRecords(ctx context.Context, hostname, zoneID string) ([]DNSRecord, OperationResult, error) {
	hostname, err := normalizeHostname("DNS record hostname", hostname)
	if err != nil {
		return nil, OperationResult{}, err
	}
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return nil, OperationResult{}, err
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(
		"dns", "records", "list", "--name", hostname, "--zone", zoneID,
	), false)
	if err != nil {
		return nil, operation, err
	}
	records, err := parseDNSRecords(operation.Stdout)
	if err != nil {
		return nil, operation, fmt.Errorf("decode cf DNS records: %w", err)
	}
	return records, operation, nil
}

func (c *Client) ListWorkerRoutes(ctx context.Context, zoneID string) ([]WorkerRoute, OperationResult, error) {
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return nil, OperationResult{}, err
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand(
		"workers", "routes", "list", "--zone", zoneID,
	), false)
	if err != nil {
		return nil, operation, err
	}
	routes, err := parseWorkerRoutes(operation.Stdout)
	if err != nil {
		return nil, operation, fmt.Errorf("decode cf Worker routes: %w", err)
	}
	return routes, operation, nil
}

func routesMatchingHostname(routes []WorkerRoute, hostname string) []WorkerRoute {
	matches := make([]WorkerRoute, 0)
	for _, route := range routes {
		pattern := route.Pattern
		lowerPattern := strings.ToLower(pattern)
		if strings.HasPrefix(lowerPattern, "https://") {
			pattern = pattern[len("https://"):]
		} else if strings.HasPrefix(lowerPattern, "http://") {
			pattern = pattern[len("http://"):]
		}
		hostPattern, _, _ := strings.Cut(pattern, "/")
		hostPattern = strings.ToLower(hostPattern)
		matched := false
		switch {
		case strings.HasPrefix(hostPattern, "*."):
			suffix := strings.TrimPrefix(hostPattern, "*.")
			matched = hostname != suffix && strings.HasSuffix(hostname, "."+suffix)
		case strings.HasPrefix(hostPattern, "*"):
			matched = strings.HasSuffix(hostname, strings.TrimPrefix(hostPattern, "*"))
		case strings.Contains(hostPattern, "*"):
			// Cloudflare currently rejects infix host wildcards. Treat any
			// unexpected stored shape as a conflict rather than guessing.
			matched = true
		default:
			matched = strings.EqualFold(hostPattern, hostname)
		}
		if matched {
			matches = append(matches, route)
		}
	}
	return matches
}

// CheckHostnameAvailability detects Custom Domain and exact DNS conflicts
// without modifying them. An existing hostname is accepted only when its
// Worker carries the canonical ownership marker.
func (c *Client) CheckHostnameAvailability(ctx context.Context, options HostnameCheckOptions) (HostnameCheck, error) {
	hostname, err := normalizeHostname("domain hostname", options.Hostname)
	if err != nil {
		return HostnameCheck{}, err
	}
	zoneName, err := normalizeHostname("zone name", options.ZoneName)
	if err != nil {
		return HostnameCheck{}, err
	}
	if hostname == zoneName || !strings.HasSuffix(hostname, "."+zoneName) {
		return HostnameCheck{}, fmt.Errorf("domain hostname must be a dedicated subdomain of the zone")
	}
	domains, _, err := c.ListDomains(ctx, DomainFilter{Hostname: hostname, ZoneID: options.ZoneID, ZoneName: zoneName})
	if err != nil {
		return HostnameCheck{}, err
	}
	records, _, err := c.ListDNSRecords(ctx, hostname, options.ZoneID)
	if err != nil {
		return HostnameCheck{}, err
	}
	routes, _, err := c.ListWorkerRoutes(ctx, options.ZoneID)
	if err != nil {
		return HostnameCheck{}, err
	}
	matchingRoutes := routesMatchingHostname(routes, hostname)
	result := HostnameCheck{Domains: domains, Records: records, Routes: matchingRoutes}
	if len(matchingRoutes) != 0 {
		result.Message = "hostname is covered by an existing Worker route"
		return result, nil
	}
	if len(domains) > 1 {
		result.Message = "multiple Custom Domain bindings use the hostname"
		return result, nil
	}
	if len(domains) == 1 {
		domain := domains[0]
		if options.Worker == "" || options.OwnershipMarker == "" || domain.Service != options.Worker || !productionEnvironment(domain.Environment) {
			result.Message = "hostname is already bound to another or unowned Worker"
			return result, nil
		}
		marker, _, markerErr := c.workerOwnershipMarker(ctx, options.Worker)
		if markerErr != nil {
			return result, markerErr
		}
		if marker != options.OwnershipMarker {
			result.Message = "hostname Worker ownership marker does not match"
			return result, nil
		}
		result.Available = true
		result.Owned = true
		result.Message = "hostname is already owned by this deployment"
		return result, nil
	}
	if len(records) != 0 {
		result.Message = "hostname already has an exact DNS record"
		return result, nil
	}
	result.Available = true
	result.Message = "hostname has no conflicting Custom Domain, DNS record, or Worker Route"
	return result, nil
}

// ListSecrets reads secret binding names and types; the Cloudflare API never
// returns secret values.
func (c *Client) ListSecrets(ctx context.Context, worker string) ([]SecretBinding, OperationResult, error) {
	if err := validateWorkerName(worker); err != nil {
		return nil, OperationResult{}, err
	}
	operation, err := c.execute(
		ctx,
		ProviderCF,
		c.cfWorkerCommand("workers", "secrets", "list", "--worker", worker),
		false,
	)
	if err != nil {
		return nil, operation, err
	}
	secrets, err := parseSecrets(operation.Stdout)
	if err != nil {
		return nil, operation, fmt.Errorf("decode cf Worker secrets: %w", err)
	}
	return secrets, operation, nil
}

// WorkerStatus assembles a read-only status from the verified cf list
// commands. It stops after the script list when the exact Worker does not
// exist.
func (c *Client) WorkerStatus(ctx context.Context, worker string) (WorkerStatus, error) {
	status := WorkerStatus{Name: worker}
	if err := validateWorkerName(worker); err != nil {
		return status, err
	}

	scripts, operation, err := c.listScripts(ctx)
	status.Operations = append(status.Operations, operation)
	if err != nil {
		return status, err
	}
	status.Exists = containsString(scripts, worker)
	if !status.Exists {
		return status, nil
	}
	attachmentOperations, err := c.validateWorkerAttachments(ctx, worker, operation.Stdout)
	status.Operations = append(status.Operations, attachmentOperations...)
	if err != nil {
		return status, err
	}
	status.OwnershipMarker, operation, err = c.workerOwnershipMarker(ctx, worker)
	status.Operations = append(status.Operations, operation)
	if err != nil {
		return status, err
	}
	if err := validateManagedWorkerBindings(operation.Stdout); err != nil {
		return status, err
	}

	status.DeploymentCount, operation, err = c.listDeployments(ctx, worker)
	status.Operations = append(status.Operations, operation)
	if err != nil {
		return status, err
	}

	status.Domains, operation, err = c.ListDomains(ctx, DomainFilter{Service: worker})
	status.Operations = append(status.Operations, operation)
	if err != nil {
		return status, err
	}

	status.Secrets, operation, err = c.ListSecrets(ctx, worker)
	status.Operations = append(status.Operations, operation)
	if err != nil {
		return status, err
	}
	return status, nil
}

// SetSecret securely writes one secret with cf. Omitting --text activates cf's
// secret prompt, which consumes non-TTY stdin without placing the value in argv.
func (c *Client) SetSecret(ctx context.Context, request SecretRequest) (OperationResult, error) {
	if err := validateWorkerName(request.Worker); err != nil {
		return OperationResult{}, err
	}
	if err := validateSecretName(request.Name); err != nil {
		return OperationResult{}, err
	}
	if request.OwnershipMarker == "" {
		return OperationResult{}, fmt.Errorf("ownership marker is required")
	}
	if len(request.Value) == 0 {
		return OperationResult{}, fmt.Errorf("secret value is required")
	}
	if !utf8.Valid(request.Value) {
		return OperationResult{}, fmt.Errorf("secret value must be valid UTF-8")
	}
	if bytes.IndexByte(request.Value, 0) >= 0 {
		return OperationResult{}, fmt.Errorf("secret value contains a NUL byte")
	}

	// Wrangler can offer to create a draft Worker when secret put targets a
	// missing script. Refuse that broader mutation by preflighting the exact
	// Worker name with cf first.
	scripts, preflight, err := c.listScripts(ctx)
	if err != nil {
		return preflight, err
	}
	if !containsString(scripts, request.Worker) {
		return preflight, fmt.Errorf("%w: %s", ErrWorkerNotFound, request.Worker)
	}
	marker, markerOperation, err := c.workerOwnershipMarker(ctx, request.Worker)
	if err != nil {
		return markerOperation, err
	}
	if marker != request.OwnershipMarker {
		return markerOperation, fmt.Errorf("%w: Worker ownership marker does not match", ErrResourceConflict)
	}

	input := make([]byte, 0, len(request.Value)+1)
	input = append(input, request.Value...)
	input = append(input, '\n')
	defer zeroBytes(input)
	command := c.cfWorkerCommand(
		"workers", "secrets", "update", request.Name,
		"--worker", request.Worker,
		"--type", "secret_text",
	).withStdin(input, true)
	return c.execute(ctx, ProviderCF, command, false, request.Value)
}

// BindCustomDomain binds exactly one hostname. cf 0.2.0 incorrectly prompts
// for omitted optional fields, so update always supplies environment, zone ID,
// and zone name explicitly.
func (c *Client) BindCustomDomain(ctx context.Context, request CustomDomainRequest) (DomainBindResult, error) {
	normalized, err := normalizeCustomDomainRequest(request)
	if err != nil {
		return DomainBindResult{}, err
	}
	request = normalized

	filter := DomainFilter{
		Hostname: request.Hostname,
		ZoneID:   request.ZoneID,
		ZoneName: request.ZoneName,
	}
	domains, preflight, err := c.ListDomains(ctx, filter)
	result := DomainBindResult{Operations: []OperationResult{preflight}}
	if err != nil {
		return result, err
	}
	var existing *DomainBinding
	for _, domain := range domains {
		if !strings.EqualFold(domain.Hostname, request.Hostname) {
			continue
		}
		if domain.Service != request.Worker || !equivalentWorkerEnvironment(domain.Environment, request.Environment) ||
			(domain.ZoneID != "" && domain.ZoneID != request.ZoneID) ||
			(domain.ZoneName != "" && !strings.EqualFold(domain.ZoneName, request.ZoneName)) {
			return result, fmt.Errorf("%w: hostname %s is bound to %s/%s", ErrResourceConflict, request.Hostname, domain.Service, domain.Environment)
		}
		if existing != nil {
			return result, fmt.Errorf("refusing to reuse duplicate bindings for hostname %s", request.Hostname)
		}
		domainCopy := domain
		existing = &domainCopy
	}
	if existing != nil {
		routes, routePreflight, routeErr := c.ListWorkerRoutes(ctx, request.ZoneID)
		result.Operations = append(result.Operations, routePreflight)
		if routeErr != nil {
			return result, routeErr
		}
		if len(routesMatchingHostname(routes, request.Hostname)) != 0 {
			return result, fmt.Errorf("%w: hostname %s is covered by a Worker route", ErrResourceConflict, request.Hostname)
		}
		result.Existing = true
		result.Binding = *existing
		return result, nil
	}
	records, dnsPreflight, err := c.ListDNSRecords(ctx, request.Hostname, request.ZoneID)
	result.Operations = append(result.Operations, dnsPreflight)
	if err != nil {
		return result, err
	}
	if len(records) != 0 {
		return result, fmt.Errorf("%w: hostname %s acquired an exact DNS record before the Custom Domain bind", ErrResourceConflict, request.Hostname)
	}
	routes, routePreflight, err := c.ListWorkerRoutes(ctx, request.ZoneID)
	result.Operations = append(result.Operations, routePreflight)
	if err != nil {
		return result, err
	}
	if len(routesMatchingHostname(routes, request.Hostname)) != 0 {
		return result, fmt.Errorf("%w: hostname %s is covered by a Worker route", ErrResourceConflict, request.Hostname)
	}

	args := []string{
		"workers", "domains", "update",
		"--hostname", request.Hostname,
		"--service", request.Worker,
		"--environment", request.Environment,
		"--zone-id", request.ZoneID,
		"--zone-name", request.ZoneName,
	}
	if request.DryRun {
		args = append(args, "--dry-run")
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), request.DryRun)
	result.Existing = false
	result.Changed = !request.DryRun && err == nil
	result.DryRun = request.DryRun
	result.Binding = DomainBinding{
		Hostname:    request.Hostname,
		Service:     request.Worker,
		Environment: request.Environment,
		ZoneID:      request.ZoneID,
		ZoneName:    request.ZoneName,
	}
	result.Operations = append(result.Operations, operation)
	if err != nil {
		return result, err
	}
	if domains, decodeErr := parseDomains(operation.Stdout); decodeErr == nil && len(domains) == 1 {
		result.Binding = domains[0]
	}
	return result, nil
}

func normalizeCustomDomainRequest(request CustomDomainRequest) (CustomDomainRequest, error) {
	var err error
	request.Hostname, err = normalizeHostname("domain hostname", request.Hostname)
	if err != nil {
		return request, err
	}
	if err := validateWorkerName(request.Worker); err != nil {
		return request, err
	}
	if request.Environment == "" {
		request.Environment = "production"
	}
	if err := validateArgument("Worker environment", request.Environment); err != nil {
		return request, err
	}
	if err := validateCloudflareID("zone ID", request.ZoneID); err != nil {
		return request, err
	}
	request.ZoneName, err = normalizeHostname("zone name", request.ZoneName)
	if err != nil {
		return request, err
	}
	if request.Hostname != request.ZoneName && !strings.HasSuffix(request.Hostname, "."+request.ZoneName) {
		return request, fmt.Errorf("domain hostname must be within zone %s", request.ZoneName)
	}
	return request, nil
}

// TailLogs streams a live JSON tail with project-local Wrangler because cf
// 0.2.0 does not attach to the WebSocket returned by its tail-session API.
func (c *Client) TailLogs(ctx context.Context, options LogsOptions) (OperationResult, error) {
	if err := validateWorkerName(options.Worker); err != nil {
		return OperationResult{}, err
	}
	if options.Stdout == nil {
		return OperationResult{}, fmt.Errorf("log stdout writer is required")
	}

	args := []string{"tail", options.Worker, "--format", "json"}
	for _, status := range uniqueStrings(options.Statuses) {
		if !oneOf(status, "ok", "error", "canceled") {
			return OperationResult{}, fmt.Errorf("unsupported tail status %q", status)
		}
		args = append(args, "--status", status)
	}
	if options.Search != "" {
		if err := validateArgument("tail search", options.Search); err != nil {
			return OperationResult{}, err
		}
		args = append(args, "--search", options.Search)
	}
	if options.SamplingRate != nil {
		rate := *options.SamplingRate
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 || rate > 1 {
			return OperationResult{}, fmt.Errorf("tail sampling rate must be greater than 0 and at most 1")
		}
		args = append(args, "--sampling-rate", strconv.FormatFloat(rate, 'f', -1, 64))
	}

	command := c.wranglerCommand(args...).withWriters(options.Stdout, options.Stderr)
	operation, err := c.execute(ctx, ProviderWrangler, command, false)
	operation.FallbackReason = liveLogsFallbackReason
	return operation, err
}

// RemoveNamed removes only the exact hostname, secret names, and Worker name
// in options. It performs all read-only ownership checks before any deletion.
func (c *Client) RemoveNamed(ctx context.Context, options RemoveOptions) (RemovalResult, error) {
	result := RemovalResult{DryRun: options.DryRun}
	if !options.DryRun && !options.Confirm {
		return result, ErrConfirmationRequired
	}
	resources, err := normalizeNamedResources(options.Resources)
	if err != nil {
		return result, err
	}

	scripts, operation, err := c.listScripts(ctx)
	result.Operations = append(result.Operations, operation)
	if err != nil {
		return result, err
	}
	workerExists := containsString(scripts, resources.Worker)
	if workerExists {
		attachmentOperations, attachmentErr := c.validateWorkerAttachments(ctx, resources.Worker, operation.Stdout)
		result.Operations = append(result.Operations, attachmentOperations...)
		if attachmentErr != nil {
			return result, attachmentErr
		}
		marker, markerOperation, markerErr := c.workerOwnershipMarker(ctx, resources.Worker)
		result.Operations = append(result.Operations, markerOperation)
		if markerErr != nil {
			return result, markerErr
		}
		if bindingErr := validateManagedWorkerBindings(markerOperation.Stdout); bindingErr != nil {
			return result, bindingErr
		}
		if marker != resources.OwnershipMarker {
			return result, fmt.Errorf("%w: Worker ownership marker does not match", ErrResourceConflict)
		}
	}

	// Query every domain attached to the service, not merely the canonical
	// hostname. Deleting the Worker is refused if any additional domain would be
	// swept up or orphaned.
	var domain *DomainBinding
	domains, listOperation, listErr := c.ListDomains(ctx, DomainFilter{Service: resources.Worker})
	result.Operations = append(result.Operations, listOperation)
	if listErr != nil {
		return result, listErr
	}
	for i := range domains {
		candidate := domains[i]
		if candidate.Service != resources.Worker {
			return result, fmt.Errorf("%w: service-wide domain query returned a binding for a different Worker", ErrResourceConflict)
		}
		if resources.Hostname == "" || !strings.EqualFold(candidate.Hostname, resources.Hostname) {
			return result, fmt.Errorf("%w: Worker has an unplanned Custom Domain binding", ErrResourceConflict)
		}
		if !equivalentWorkerEnvironment(candidate.Environment, resources.Environment) ||
			(candidate.ZoneID != "" && candidate.ZoneID != resources.ZoneID) ||
			(candidate.ZoneName != "" && !strings.EqualFold(candidate.ZoneName, resources.ZoneName)) {
			return result, fmt.Errorf("%w: hostname %s has unexpected domain metadata", ErrResourceConflict, resources.Hostname)
		}
		if domain != nil {
			return result, fmt.Errorf("refusing to remove duplicate bindings for hostname %s", resources.Hostname)
		}
		if err := validateWorkerDomainID("domain ID", candidate.ID); err != nil {
			return result, fmt.Errorf("refusing to remove domain without an exact ID: %w", err)
		}
		if (resources.EnforceExpectedDomainID || resources.ExpectedDomainID != "") && candidate.ID != resources.ExpectedDomainID {
			return result, fmt.Errorf("%w: Custom Domain does not match the removal checkpoint", ErrResourceConflict)
		}
		if err := validateUUID("domain certificate ID", candidate.CertID); err != nil {
			return result, fmt.Errorf("refusing to remove domain without an exact certificate ID: %w", err)
		}
		if !workerExists {
			return result, fmt.Errorf("%w: Custom Domain exists but the ownership-marked Worker does not", ErrResourceConflict)
		}
		domain = &candidate
	}

	var certificatePack *CertificatePack
	if domain != nil || resources.ExpectedCertificatePackID != "" {
		packs, packOperation, packErr := c.ListCertificatePacks(ctx, resources.ZoneID)
		result.Operations = append(result.Operations, packOperation)
		if packErr != nil {
			return result, packErr
		}
		if resources.ExpectedCertificatePackID != "" {
			certificatePack, err = selectExpectedCertificatePack(packs, resources.ExpectedCertificatePackID, resources.Hostname)
			if err != nil {
				return result, err
			}
			if domain != nil {
				if certificatePack == nil {
					return result, fmt.Errorf("%w: stored generated certificate pack is absent while its Custom Domain still exists", ErrResourceConflict)
				}
				if err := validateDomainCertificateInPack(*certificatePack, *domain); err != nil {
					return result, err
				}
			}
		} else if resources.EnforceExpectedCertificatePackID {
			return result, fmt.Errorf("%w: generated certificate pack provenance is required", ErrResourceConflict)
		} else if domain != nil {
			certificatePack, err = selectGeneratedCertificatePack(packs, *domain)
			if err != nil {
				return result, err
			}
		}
		if certificatePack != nil && certificatePackDeletionPending(certificatePack.Status) {
			return result, errors.New("generated certificate pack deletion is still pending; retry after Cloudflare finishes it")
		}
	}

	existingSecrets := make([]string, 0, len(resources.SecretNames))
	if workerExists {
		secrets, listOperation, listErr := c.ListSecrets(ctx, resources.Worker)
		result.Operations = append(result.Operations, listOperation)
		if listErr != nil {
			return result, listErr
		}
		seen := make(map[string]struct{}, len(secrets))
		for _, secret := range secrets {
			if secret.Name != vlessCredentialSecretName || (secret.Type != "" && secret.Type != "secret_text") {
				return result, fmt.Errorf("%w: Worker has an unplanned secret binding", ErrResourceConflict)
			}
			if _, duplicate := seen[secret.Name]; duplicate {
				return result, fmt.Errorf("refusing to remove duplicate secret bindings named %s", secret.Name)
			}
			seen[secret.Name] = struct{}{}
			existingSecrets = append(existingSecrets, secret.Name)
		}
	}

	result.Plan = RemovalPlan{
		Worker:             resources.Worker,
		DeleteWorker:       workerExists,
		Hostname:           resources.Hostname,
		DomainIDs:          make([]string, 0, 1),
		CertificatePackIDs: make([]string, 0, 1),
		SecretNames:        append([]string{}, existingSecrets...),
	}
	if domain != nil {
		result.Plan.DomainIDs = append(result.Plan.DomainIDs, domain.ID)
	}
	if certificatePack != nil && certificatePack.Status != "deleted" {
		result.Plan.CertificatePackIDs = append(result.Plan.CertificatePackIDs, certificatePack.ID)
	}

	if workerExists && !options.DryRun {
		if readiness, ok := c.runner.(InteractiveReadiness); ok && !readiness.InteractiveReady() {
			return result, ErrInteractiveTerminalRequired
		}
	}

	if domain != nil {
		args := []string{"workers", "domains", "delete", domain.ID, "--force"}
		if options.DryRun {
			args = append(args, "--dry-run")
		}
		operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), options.DryRun)
		result.Operations = append(result.Operations, operation)
		if err != nil {
			return result, err
		}
		if !options.DryRun {
			result.RemovedDomainIDs = append(result.RemovedDomainIDs, domain.ID)
		}
	}

	if certificatePack != nil {
		operation, err := c.deleteCertificatePack(ctx, resources.ZoneID, certificatePack.ID, options.DryRun)
		result.Operations = append(result.Operations, operation)
		if err != nil {
			return result, err
		}
		if !options.DryRun {
			result.RemovedCertificatePackIDs = append(result.RemovedCertificatePackIDs, certificatePack.ID)
		}
	}

	for _, name := range existingSecrets {
		args := []string{"workers", "secrets", "delete", name, "--worker", resources.Worker, "--force"}
		if options.DryRun {
			args = append(args, "--dry-run")
		}
		operation, err := c.execute(ctx, ProviderCF, c.cfWorkerCommand(args...), options.DryRun)
		result.Operations = append(result.Operations, operation)
		if err != nil {
			return result, err
		}
		if !options.DryRun {
			result.RemovedSecrets = append(result.RemovedSecrets, name)
		}
	}

	if workerExists {
		args := []string{"workers", "scripts", "delete", "--worker", resources.Worker}
		command := c.cfWorkerCommand(args...)
		if options.DryRun {
			command.Args = append(command.Args, "--dry-run")
		} else {
			// Deliberately do not use cf's --force: for scripts it broadens the
			// deletion to associated bindings and Durable Objects. cf 0.2.0
			// refuses piped confirmation, so a real terminal is required.
			command = command.withInteractive()
		}
		operation, err := c.execute(ctx, ProviderCF, command, options.DryRun)
		result.Operations = append(result.Operations, operation)
		if err != nil {
			return result, err
		}
		if strings.Contains(operation.Stderr, "Aborted.") {
			return result, ErrConfirmationRequired
		}
		result.WorkerRemoved = !options.DryRun
	}
	return result, nil
}

func normalizeNamedResources(resources NamedResources) (NamedResources, error) {
	if err := validateWorkerName(resources.Worker); err != nil {
		return resources, err
	}
	if resources.OwnershipMarker == "" {
		return resources, fmt.Errorf("ownership marker is required")
	}
	resources.SecretNames = uniqueStrings(resources.SecretNames)
	if len(resources.SecretNames) != 1 || resources.SecretNames[0] != vlessCredentialSecretName {
		return resources, fmt.Errorf("the exact %s secret binding must be selected", vlessCredentialSecretName)
	}
	for _, name := range resources.SecretNames {
		if err := validateSecretName(name); err != nil {
			return resources, err
		}
	}
	if resources.ExpectedDomainID != "" {
		if err := validateWorkerDomainID("expected domain ID", resources.ExpectedDomainID); err != nil {
			return resources, err
		}
	}
	if resources.ExpectedCertificatePackID != "" {
		if err := validateCertificatePackID("expected certificate pack ID", resources.ExpectedCertificatePackID); err != nil {
			return resources, err
		}
	}
	if resources.EnforceExpectedCertificatePackID && resources.ExpectedCertificatePackID == "" {
		return resources, fmt.Errorf("expected certificate pack ID is required")
	}
	if resources.Hostname == "" {
		if resources.Environment != "" || resources.ZoneID != "" || resources.ZoneName != "" {
			return resources, fmt.Errorf("hostname is required when domain metadata is supplied")
		}
		return resources, nil
	}

	request, err := normalizeCustomDomainRequest(CustomDomainRequest{
		Hostname:    resources.Hostname,
		Worker:      resources.Worker,
		Environment: resources.Environment,
		ZoneID:      resources.ZoneID,
		ZoneName:    resources.ZoneName,
	})
	if err != nil {
		return resources, err
	}
	resources.Hostname = request.Hostname
	resources.Environment = request.Environment
	resources.ZoneID = request.ZoneID
	resources.ZoneName = request.ZoneName
	return resources, nil
}

func selectGeneratedCertificatePack(packs []CertificatePack, domain DomainBinding) (*CertificatePack, error) {
	selected, err := CorrelateGeneratedCertificatePack(packs, domain.CertID, domain.Hostname)
	if errors.Is(err, ErrCertificatePackPending) {
		return nil, fmt.Errorf("refusing to remove Custom Domain %s because its generated Advanced certificate pack was not found", domain.Hostname)
	}
	return selected, err
}

// CorrelateGeneratedCertificatePack maps the certificate ID returned by the
// Custom Domain attach API to exactly one one-host Advanced Certificate pack.
// Cloudflare has returned certificate IDs in both canonical UUID and the same
// 32 hexadecimal digits without hyphens, so no other coercion is accepted.
func CorrelateGeneratedCertificatePack(packs []CertificatePack, certificateID, hostname string) (*CertificatePack, error) {
	if err := validateUUID("Custom Domain certificate ID", certificateID); err != nil {
		return nil, err
	}
	normalizedHostname, err := normalizeHostname("Custom Domain hostname", hostname)
	if err != nil {
		return nil, err
	}
	var selected *CertificatePack
	for i := range packs {
		pack := &packs[i]
		if pack.Status == "deleted" {
			continue
		}
		var matchingCertificate *CertificatePackCertificate
		for certificateIndex := range pack.Certificates {
			certificate := &pack.Certificates[certificateIndex]
			if !CertificateIDsEquivalent(certificate.ID, certificateID) {
				continue
			}
			if matchingCertificate != nil {
				return nil, fmt.Errorf("refusing an ambiguous certificate pack for hostname %s", normalizedHostname)
			}
			matchingCertificate = certificate
		}
		if matchingCertificate == nil {
			continue
		}
		if pack.Type != "advanced" || !exactCertificateHosts(pack.Hosts, normalizedHostname) ||
			!exactCertificateHosts(matchingCertificate.Hosts, normalizedHostname) {
			return nil, fmt.Errorf("%w: certificate ID matches a pack with unexpected type or hostnames", ErrResourceConflict)
		}
		if err := validateCertificatePackID("certificate pack ID", pack.ID); err != nil {
			return nil, fmt.Errorf("refusing to remove certificate pack without an exact ID: %w", err)
		}
		if selected != nil {
			return nil, fmt.Errorf("refusing ambiguous certificate packs for hostname %s", normalizedHostname)
		}
		selected = pack
	}
	if selected == nil {
		return nil, ErrCertificatePackPending
	}
	copy := *selected
	return &copy, nil
}

// CorrelateNewGeneratedCertificatePack identifies the one Advanced pack that
// appeared after the pre-bind inventory and explicitly covers the Custom
// Domain hostname. Current Cloudflare Custom Domains can create a multi-SAN
// pack and return a Domain cert_id that is not a certificate child ID, so the
// before/after pack-ID boundary is the immutable creation proof.
func CorrelateNewGeneratedCertificatePack(
	packs []CertificatePack,
	preexistingIDs []string,
	hostname string,
) (*CertificatePack, error) {
	normalizedHostname, err := normalizeHostname("Custom Domain hostname", hostname)
	if err != nil {
		return nil, err
	}
	preexisting := make(map[string]struct{}, len(preexistingIDs))
	for _, id := range preexistingIDs {
		if err := validateCertificatePackID("pre-bind certificate pack ID", id); err != nil {
			return nil, err
		}
		preexisting[id] = struct{}{}
	}
	var selected *CertificatePack
	for index := range packs {
		pack := &packs[index]
		if pack.Status == "deleted" {
			continue
		}
		if _, existed := preexisting[pack.ID]; existed {
			continue
		}
		if !certificateHostsContain(pack.Hosts, normalizedHostname) {
			continue
		}
		if err := validateGeneratedCertificatePackShape(*pack, normalizedHostname); err != nil {
			return nil, err
		}
		if selected != nil {
			return nil, fmt.Errorf("refusing ambiguous newly generated certificate packs for hostname %s", normalizedHostname)
		}
		selected = pack
	}
	if selected == nil {
		return nil, ErrCertificatePackPending
	}
	copy := *selected
	return &copy, nil
}

// SelectGeneratedCertificatePackByID validates the exact creation-provenance
// pack without requiring Cloudflare's Domain cert_id to equal a child ID.
func SelectGeneratedCertificatePackByID(
	packs []CertificatePack,
	expectedID string,
	hostname string,
) (*CertificatePack, error) {
	if err := validateCertificatePackID("expected certificate pack ID", expectedID); err != nil {
		return nil, err
	}
	normalizedHostname, err := normalizeHostname("Custom Domain hostname", hostname)
	if err != nil {
		return nil, err
	}
	var selected *CertificatePack
	for index := range packs {
		pack := &packs[index]
		if pack.ID != expectedID || pack.Status == "deleted" {
			continue
		}
		if selected != nil {
			return nil, errors.New("duplicate certificate packs returned for the stored ID")
		}
		selected = pack
	}
	if selected == nil {
		return nil, ErrCertificatePackPending
	}
	if err := validateGeneratedCertificatePackShape(*selected, normalizedHostname); err != nil {
		return nil, err
	}
	copy := *selected
	return &copy, nil
}

func validateGeneratedCertificatePackShape(pack CertificatePack, hostname string) error {
	if pack.Type != "advanced" || !certificateHostsContain(pack.Hosts, hostname) {
		return fmt.Errorf("%w: generated certificate pack has unexpected type or hostnames", ErrResourceConflict)
	}
	if err := validateCertificatePackID("certificate pack ID", pack.ID); err != nil {
		return fmt.Errorf("generated certificate pack has an invalid ID: %w", err)
	}
	if pack.Status == "active" && len(pack.Certificates) == 0 {
		return fmt.Errorf("%w: active generated certificate pack has no certificates", ErrResourceConflict)
	}
	for _, certificate := range pack.Certificates {
		if !certificateHostsContain(certificate.Hosts, hostname) {
			return fmt.Errorf("%w: generated certificate pack contains a certificate that does not cover the hostname", ErrResourceConflict)
		}
	}
	return nil
}

func certificateHostsContain(hosts []string, hostname string) bool {
	for _, host := range hosts {
		if strings.EqualFold(strings.TrimSuffix(host, "."), hostname) {
			return true
		}
	}
	return false
}

func validateDomainCertificateInPack(pack CertificatePack, domain DomainBinding) error {
	return validateGeneratedCertificatePackShape(pack, domain.Hostname)
}

// CertificateIDsEquivalent compares only canonical UUIDs and their equivalent
// 32 hexadecimal form. Arbitrary opaque strings are never coerced.
func CertificateIDsEquivalent(left, right string) bool {
	leftNormalized, leftOK := normalizeCertificateID(left)
	rightNormalized, rightOK := normalizeCertificateID(right)
	return leftOK && rightOK && leftNormalized == rightNormalized
}

func normalizeCertificateID(value string) (string, bool) {
	if uuidPattern.MatchString(value) {
		return strings.ToLower(strings.ReplaceAll(value, "-", "")), true
	}
	if cloudflareIDPattern.MatchString(value) {
		return strings.ToLower(value), true
	}
	return "", false
}

func selectExpectedCertificatePack(packs []CertificatePack, expectedID, hostname string) (*CertificatePack, error) {
	var selected *CertificatePack
	for i := range packs {
		pack := &packs[i]
		if pack.ID != expectedID {
			continue
		}
		if pack.Status == "deleted" {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("refusing to remove duplicate certificate packs with checkpoint ID %s", expectedID)
		}
		selected = pack
	}
	if selected == nil {
		// A retry may arrive after the exact pack deletion succeeded but a later
		// secret or Worker deletion failed. Its absence is therefore an
		// already-completed step, not permission to select a different pack.
		return nil, nil
	}
	if err := validateGeneratedCertificatePackShape(*selected, hostname); err != nil {
		return nil, err
	}
	copy := *selected
	return &copy, nil
}

func exactCertificateHosts(hosts []string, hostname string) bool {
	return len(hosts) == 1 && strings.EqualFold(strings.TrimSuffix(hosts[0], "."), hostname)
}

func certificatePackDeletionPending(status string) bool {
	switch status {
	case "pending_deletion", "pending_cleanup", "deactivating":
		return true
	default:
		return false
	}
}

func productionEnvironment(value string) bool {
	return value == "" || value == "production"
}

func equivalentWorkerEnvironment(actual, expected string) bool {
	if expected == "production" {
		return productionEnvironment(actual)
	}
	return actual == expected
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
