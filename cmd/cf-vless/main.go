// Command cf-vless manages one self-hosted VLESS-over-WebSocket Worker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BaiqingL/cf-vless/internal/clientformats"
	"github.com/BaiqingL/cf-vless/internal/cloudflare"
	"github.com/BaiqingL/cf-vless/internal/config"
	"github.com/BaiqingL/cf-vless/internal/testvectors"
	"github.com/BaiqingL/cf-vless/internal/workerproject"
)

const defaultConfigPath = ".cf-vless/deployment.json"

type localCommandRunner func(context.Context, string, string, []string, io.Writer, io.Writer) error
type publicHTTPSReadinessProbe func(context.Context, string) error

type dependencies struct {
	cloudflareRunner   cloudflare.Runner
	runLocal           localCommandRunner
	now                func() time.Time
	loadGlobalAPIKey   func(string) ([]byte, error)
	certificatePackAPI cloudflare.CertificatePackAPI
	probePublicHTTPS   publicHTTPSReadinessProbe
}

type commonFlags struct {
	projectRoot string
	configPath  string
}

type resolvedPaths struct {
	root      string
	config    string
	stateDir  string
	workspace string
	template  string
	pending   string
	removal   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultDependencies()))
}

func defaultDependencies() dependencies {
	return dependencies{
		cloudflareRunner: cloudflare.ExecRunner{},
		runLocal:         executeLocal,
		now:              time.Now,
		loadGlobalAPIKey: loadGlobalAPIKey,
		probePublicHTTPS: cloudflare.ProbePublicHTTPSReadiness,
	}
}

func executeLocal(ctx context.Context, directory, program string, args []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = directory
	command.Env = localCommandEnvironment(os.Environ())
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func localCommandEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, globalAPIKeyVariable) || strings.EqualFold(name, "CLOUDFLARE_API_KEY") {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr, deps)
	case "init":
		return runInit(ctx, args[1:], stdout, stderr, deps)
	case "deploy":
		return runDeploy(ctx, args[1:], stdout, stderr, deps)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr, deps)
	case "test":
		return runIntegration(ctx, args[1:], stdout, stderr, deps)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "rotate":
		return runRotate(ctx, args[1:], stdout, stderr, deps)
	case "logs":
		return runLogs(ctx, args[1:], stdout, stderr, deps)
	case "remove":
		return runRemove(ctx, args[1:], stdout, stderr, deps)
	default:
		fmt.Fprintf(stderr, "cf-vless: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprint(writer, `usage: cf-vless <command> [options]

commands:
  doctor   verify local tools and Cloudflare access
  init     create private deployment state and Worker workspace
  deploy   preflight or publish the managed Worker
  status   verify owned resources and public HTTPS readiness
  test     run executable-client integration gates
  config   generate private client configurations and QR code
  rotate   replace or finalize VLESS credentials
  logs     stream sanitized live Worker events
  remove   plan or delete only marker-owned resources

run cf-vless <command> --help for command-specific options.
exit status: 0 success; 1 operational failure; 2 invalid usage.
`)
}

func (common *commonFlags) bind(flags *flag.FlagSet) {
	flags.StringVar(&common.projectRoot, "project-root", ".", "repository root containing worker and third_party")
	flags.StringVar(&common.configPath, "config", defaultConfigPath, "canonical owner-only deployment file")
}

func (common commonFlags) resolve() (resolvedPaths, error) {
	root, err := filepath.Abs(common.projectRoot)
	if err != nil {
		return resolvedPaths{}, fmt.Errorf("resolve project root: %w", err)
	}
	configPath := common.configPath
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(root, configPath)
	}
	configPath = filepath.Clean(configPath)
	stateDirectory := filepath.Dir(configPath)
	return resolvedPaths{
		root:      root,
		config:    configPath,
		stateDir:  stateDirectory,
		workspace: filepath.Join(stateDirectory, "worker"),
		template:  filepath.Join(root, "worker"),
		pending:   filepath.Join(stateDirectory, "deployment.pending.json"),
		removal:   filepath.Join(stateDirectory, "removal.pending.json"),
	}, nil
}

func newCloudflareClient(deps dependencies, paths resolvedPaths, accountID string, initialized bool) (*cloudflare.Client, error) {
	projectDirectory := paths.template
	if initialized {
		projectDirectory = paths.workspace
	}
	var globalAPIKey []byte
	if deps.loadGlobalAPIKey != nil {
		var err error
		globalAPIKey, err = deps.loadGlobalAPIKey(paths.root)
		if err != nil {
			return nil, err
		}
		defer zeroBytes(globalAPIKey)
	}
	return cloudflare.NewClient(deps.cloudflareRunner, cloudflare.Options{
		ProjectDir:     projectDirectory,
		AccountID:      accountID,
		GlobalAPIKey:   globalAPIKey,
		CertificateAPI: deps.certificatePackAPI,
	})
}

func parseFlagSet(flags *flag.FlagSet, args []string) (int, bool) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(flags.Output(), "unexpected positional arguments")
		flags.Usage()
		return 2, false
	}
	return 0, true
}

func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	zoneName := flags.String("zone", "", "Cloudflare zone to verify")
	hostname := flags.String("hostname", "", "dedicated hostname to verify for conflicts")
	workerName := flags.String("worker", config.DefaultWorkerName, "Worker name associated with an initialized hostname")
	accountID := flags.String("account-id", "", "Cloudflare account ID to verify")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, err := common.resolve()
	if err != nil {
		return printError(stderr, "doctor", err)
	}
	initialized := false
	if deployment, loadErr := config.Load(paths.config); loadErr == nil {
		initialized = true
		if *zoneName == "" {
			*zoneName = deployment.ZoneName
		}
		if *accountID == "" {
			*accountID = deployment.AccountID
		}
		if *hostname == "" {
			*hostname = deployment.Hostname
		}
		*workerName = deployment.WorkerName
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		fmt.Fprintf(stderr, "warning: local deployment state is not usable: %v\n", loadErr)
	}
	if !initialized && (*zoneName == "" || *hostname == "") {
		fmt.Fprintln(stderr, "doctor requires --zone and --hostname before init")
		return 2
	}
	client, err := newCloudflareClient(deps, paths, *accountID, initialized)
	if err != nil {
		return printError(stderr, "doctor", err)
	}
	marker := ""
	if deployment, loadErr := config.Load(paths.config); loadErr == nil {
		marker = deployment.OwnershipMarker
	}
	report, err := client.Doctor(ctx, cloudflare.DoctorOptions{
		AccountID: *accountID, ZoneName: *zoneName, Hostname: *hostname,
		Worker: *workerName, OwnershipMarker: marker,
	})
	if err != nil {
		return printError(stderr, "doctor", err)
	}
	for _, check := range report.Checks {
		fmt.Fprintf(stdout, "[%s] %s: %s\n", check.Status, check.Name, check.Message)
	}
	localHealthy := runLocalDoctor(ctx, paths, stdout)
	if !report.Healthy || !localHealthy {
		return 1
	}
	return 0
}

type localDoctorCheck struct {
	name             string
	program          string
	args             []string
	minimum          string
	unsupportedMajor int
	requirement      string
}

func localDoctorChecks() []localDoctorCheck {
	return []localDoctorCheck{
		{name: "go", program: "go", args: []string{"version"}, minimum: "1.26"},
		{name: "node", program: "node", args: []string{"--version"}, minimum: "22.18", unsupportedMajor: 23, requirement: "22.18+ within major 22, or 24+"},
		{name: "npm", program: "npm", args: []string{"--version"}, minimum: "11.0", requirement: "11 or newer"},
		{name: "git", program: "git", args: []string{"--version"}},
		{name: "rg", program: "rg", args: []string{"--version"}},
		{name: "sing-box", program: "sing-box", args: []string{"version"}},
		{name: "mihomo", program: "mihomo", args: []string{"-v"}},
	}
}

func runLocalDoctor(ctx context.Context, paths resolvedPaths, stdout io.Writer) bool {
	healthy := true
	for _, check := range localDoctorChecks() {
		command := exec.CommandContext(ctx, check.program, check.args...)
		command.Env = localCommandEnvironment(os.Environ())
		output, err := command.CombinedOutput()
		if err != nil {
			healthy = false
			fmt.Fprintf(stdout, "[fail] tool.%s: unavailable\n", check.name)
		} else if check.minimum != "" && !localVersionSupported(string(output), check.minimum, check.unsupportedMajor) {
			healthy = false
			requirement := check.requirement
			if requirement == "" {
				requirement = check.minimum + " or newer"
			}
			fmt.Fprintf(stdout, "[fail] tool.%s: version %s is required\n", check.name, requirement)
		} else {
			fmt.Fprintf(stdout, "[pass] tool.%s: available\n", check.name)
		}
	}
	commitCommand := exec.CommandContext(ctx, "git", "-C", filepath.Join(paths.root, "third_party", "xray-core"), "rev-parse", "HEAD")
	commitCommand.Env = localCommandEnvironment(os.Environ())
	commitBytes, err := commitCommand.Output()
	if err != nil || strings.TrimSpace(string(commitBytes)) != testvectors.XrayCommit {
		fmt.Fprintln(stdout, "[fail] xray.submodule: missing or not pinned")
		healthy = false
	} else {
		fmt.Fprintln(stdout, "[pass] xray.submodule: pinned upstream is available")
	}
	return healthy
}

var localVersionPattern = regexp.MustCompile(`(?i)(?:go|v)?([0-9]+)\.([0-9]+)`) // tool output, not user input

func versionAtLeast(output, minimum string) bool {
	actual := localVersionPattern.FindStringSubmatch(output)
	wanted := localVersionPattern.FindStringSubmatch(minimum)
	if len(actual) != 3 || len(wanted) != 3 {
		return false
	}
	actualMajor, _ := strconv.Atoi(actual[1])
	actualMinor, _ := strconv.Atoi(actual[2])
	wantedMajor, _ := strconv.Atoi(wanted[1])
	wantedMinor, _ := strconv.Atoi(wanted[2])
	return actualMajor > wantedMajor || actualMajor == wantedMajor && actualMinor >= wantedMinor
}

func localVersionSupported(output, minimum string, unsupportedMajor int) bool {
	if !versionAtLeast(output, minimum) {
		return false
	}
	actual := localVersionPattern.FindStringSubmatch(output)
	if len(actual) != 3 {
		return false
	}
	actualMajor, _ := strconv.Atoi(actual[1])
	return unsupportedMajor == 0 || actualMajor != unsupportedMajor
}

func runInit(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	hostname := flags.String("hostname", "", "dedicated Worker hostname")
	zoneName := flags.String("zone", "", "active Cloudflare zone")
	displayName := flags.String("name", "", "client display name")
	workerName := flags.String("worker", config.DefaultWorkerName, "Cloudflare Worker name")
	accountID := flags.String("account-id", "", "Cloudflare account ID")
	zoneID := flags.String("zone-id", "", "Cloudflare zone ID")
	allowedPortsText := flags.String("allowed-ports", "22,80,443", "comma-separated TCP destination ports")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	if *hostname == "" || *zoneName == "" || *displayName == "" {
		fmt.Fprintln(stderr, "init requires --hostname, --zone, and --name")
		return 2
	}
	paths, err := common.resolve()
	if err != nil {
		return printError(stderr, "init", err)
	}
	allowedPorts, err := parsePorts(*allowedPortsText)
	if err != nil {
		return printError(stderr, "init", err)
	}
	bootstrapClient, err := newCloudflareClient(deps, paths, *accountID, false)
	if err != nil {
		return printError(stderr, "init", err)
	}
	zone, err := resolveZone(ctx, bootstrapClient, *zoneName, *accountID, *zoneID)
	if err != nil {
		return printError(stderr, "init", err)
	}
	accountClient, err := newCloudflareClient(deps, paths, zone.AccountID, false)
	if err != nil {
		return printError(stderr, "init", err)
	}
	deployment, err := config.New(config.InitOptions{
		WorkerName:   *workerName,
		AccountID:    zone.AccountID,
		ZoneID:       zone.ID,
		ZoneName:     strings.ToLower(*zoneName),
		Hostname:     strings.ToLower(*hostname),
		DisplayName:  *displayName,
		AllowedPorts: allowedPorts,
	})
	if err != nil {
		return printError(stderr, "init", err)
	}
	workerStatus, err := accountClient.WorkerStatus(ctx, deployment.WorkerName)
	if err != nil {
		return printError(stderr, "init", err)
	}
	if workerStatus.Exists {
		return printError(stderr, "init", errors.New("same-named Worker already exists; choose a new --worker name or remove it explicitly"))
	}
	certificatePacks, _, err := accountClient.ListCertificatePacks(ctx, deployment.ZoneID)
	if err != nil {
		return printError(stderr, "init", err)
	}
	if hasExactAdvancedCertificate(certificatePacks, deployment.Hostname) {
		return printError(stderr, "init", errors.New("dedicated hostname already has an exact Advanced Certificate pack"))
	}
	hostnameCheck, err := accountClient.CheckHostnameAvailability(ctx, cloudflare.HostnameCheckOptions{
		Hostname: deployment.Hostname, ZoneID: deployment.ZoneID, ZoneName: deployment.ZoneName,
		Worker: deployment.WorkerName, OwnershipMarker: deployment.OwnershipMarker,
	})
	if err != nil {
		return printError(stderr, "init", err)
	}
	if !hostnameCheck.Available || hostnameCheck.Owned {
		return printError(stderr, "init", errors.New("dedicated hostname is not available for a new deployment"))
	}
	if err := config.SaveNew(paths.config, &deployment); err != nil {
		return printError(stderr, "init", err)
	}
	if err := workerproject.Prepare(paths.template, paths.workspace, deployment); err != nil {
		if cleanupErr := config.RemoveSecretFile(paths.config); cleanupErr != nil {
			return printError(stderr, "init", errors.Join(err, fmt.Errorf("clean up private deployment state: %w", cleanupErr)))
		}
		return printError(stderr, "init", err)
	}
	fmt.Fprintf(stdout, "initialized %s for %s\n", deployment.WorkerName, deployment.Hostname)
	fmt.Fprintf(stdout, "private state: %s\n", paths.config)
	fmt.Fprintf(stdout, "generated Worker: %s\n", paths.workspace)
	return 0
}

func resolveZone(ctx context.Context, client *cloudflare.Client, zoneName, accountID, zoneID string) (cloudflare.Zone, error) {
	zones, err := client.ListZones(ctx, cloudflare.ZoneFilter{Name: zoneName, AccountID: accountID, Status: "active"})
	if err != nil {
		return cloudflare.Zone{}, err
	}
	matches := make([]cloudflare.Zone, 0, len(zones))
	for _, zone := range zones {
		if !strings.EqualFold(zone.Name, zoneName) || zone.Status != "active" {
			continue
		}
		if zoneID != "" && zone.ID != zoneID {
			continue
		}
		if accountID != "" && zone.AccountID != accountID {
			continue
		}
		matches = append(matches, zone)
	}
	if len(matches) != 1 || matches[0].ID == "" || matches[0].AccountID == "" {
		return cloudflare.Zone{}, errors.New("expected exactly one active accessible zone with account and zone IDs")
	}
	return matches[0], nil
}

func parsePorts(value string) ([]uint16, error) {
	seen := make(map[uint16]struct{})
	ports := make([]uint16, 0)
	for _, part := range strings.Split(value, ",") {
		parsed, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err != nil || parsed == 0 || parsed == 25 {
			return nil, errors.New("allowed ports must be unique nonzero numbers and must not include 25")
		}
		port := uint16(parsed)
		if _, duplicate := seen[port]; duplicate {
			return nil, errors.New("allowed ports must be unique")
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Slice(ports, func(left, right int) bool { return ports[left] < ports[right] })
	if len(ports) == 0 {
		return nil, errors.New("at least one allowed port is required")
	}
	return ports, nil
}

func runDeploy(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	dryRun := flags.Bool("dry-run", false, "build and preflight without account mutations")
	recoverDomainID := flags.String("recover-domain-id", "", "explicit immutable Domain ID from an interrupted bind")
	recoverCertificatePackID := flags.String("recover-certificate-pack-id", "", "explicit generated pack ID from an interrupted bind")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	if *dryRun && (*recoverDomainID != "" || *recoverCertificatePackID != "") {
		return printError(stderr, "deploy", errors.New("resource recovery cannot be combined with dry-run"))
	}
	paths, deployment, operationLock, err := loadSettledDeploymentLocked(common)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	defer releaseOperationLock(operationLock, stderr)
	client, err := newCloudflareClient(deps, paths, deployment.AccountID, true)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	if err := client.RequireSupportedCFVersion(ctx); err != nil {
		return printError(stderr, "deploy", err)
	}
	if err := workerproject.Prepare(paths.template, paths.workspace, *deployment); err != nil {
		return printError(stderr, "deploy", err)
	}
	if err := deps.runLocal(ctx, paths.workspace, "npm", []string{"ci"}, stdout, stderr); err != nil {
		return printError(stderr, "deploy", errors.New("install pinned Worker dependencies failed"))
	}
	statusBefore, err := client.WorkerStatus(ctx, deployment.WorkerName)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	if statusBefore.Exists && statusBefore.OwnershipMarker != deployment.OwnershipMarker {
		return printError(stderr, "deploy", errors.New("same-named Worker is not owned by this deployment"))
	}
	if *recoverDomainID != "" {
		if deployment.ManagedDomain != nil {
			return printError(stderr, "deploy", errors.New("Custom Domain provenance is already recorded"))
		}
		managed, recoverErr := recoverInterruptedDomain(statusBefore, *deployment, *recoverDomainID)
		if recoverErr != nil {
			return printError(stderr, "deploy", recoverErr)
		}
		candidate := *deployment
		candidate.ManagedDomain = managed
		if err := config.Save(paths.config, &candidate); err != nil {
			return printError(stderr, "deploy", fmt.Errorf("persist recovered Custom Domain provenance: %w", err))
		}
		deployment = &candidate
		// The initial workspace was generated from the pre-recovery state and
		// therefore has no declarative Custom Domain. Refresh it immediately
		// after provenance is durable so every later preflight and deployment
		// uses the protected, routed configuration.
		if err := workerproject.Prepare(paths.template, paths.workspace, *deployment); err != nil {
			return printError(stderr, "deploy", err)
		}
	}
	if err := validateServiceDomainInventory(statusBefore.Domains, *deployment); err != nil {
		return printError(stderr, "deploy", err)
	}
	certificatePacks, _, err := client.ListCertificatePacks(ctx, deployment.ZoneID)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	hostnameCheck, err := client.CheckHostnameAvailability(ctx, cloudflare.HostnameCheckOptions{
		Hostname: deployment.Hostname, ZoneID: deployment.ZoneID, ZoneName: deployment.ZoneName,
		Worker: deployment.WorkerName, OwnershipMarker: deployment.OwnershipMarker,
	})
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	if !hostnameCheck.Available {
		return printError(stderr, "deploy", errors.New("dedicated hostname became unavailable before deployment"))
	}
	managedBinding, err := validateManagedDomainState(hostnameCheck, *deployment)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	if !hostnameCheck.Owned && hasExactAdvancedCertificate(certificatePacks, deployment.Hostname) {
		return printError(stderr, "deploy", errors.New("dedicated hostname gained an unplanned exact Advanced Certificate pack"))
	}
	if *recoverCertificatePackID != "" {
		if deployment.ManagedDomain == nil || deployment.ManagedDomain.CertificatePackID != "" {
			return printError(stderr, "deploy", errors.New("generated certificate pack recovery is not applicable"))
		}
		pack, recoverErr := cloudflare.SelectGeneratedCertificatePackByID(
			certificatePacks, *recoverCertificatePackID, deployment.Hostname,
		)
		if recoverErr != nil || pack.Status != "active" {
			return printError(stderr, "deploy", errors.New("explicit generated certificate pack is not active and valid for this hostname"))
		}
		candidate := *deployment
		managed := *deployment.ManagedDomain
		managed.CertificatePackID = pack.ID
		managed.CertificatePackBaselineIDs = nil
		managed.CertificatePackBaselineRecorded = false
		candidate.ManagedDomain = &managed
		if err := config.Save(paths.config, &candidate); err != nil {
			return printError(stderr, "deploy", fmt.Errorf("persist recovered certificate pack provenance: %w", err))
		}
		deployment = &candidate
	}
	if managedBinding != nil {
		var pack *cloudflare.CertificatePack
		var correlateErr error
		if deployment.ManagedDomain.CertificatePackID != "" {
			pack, correlateErr = cloudflare.SelectGeneratedCertificatePackByID(
				certificatePacks, deployment.ManagedDomain.CertificatePackID, deployment.Hostname,
			)
		} else if deployment.ManagedDomain.CertificatePackBaselineRecorded {
			pack, correlateErr = cloudflare.CorrelateNewGeneratedCertificatePack(
				certificatePacks, deployment.ManagedDomain.CertificatePackBaselineIDs, deployment.Hostname,
			)
		} else {
			return printError(stderr, "deploy", errors.New("certificate pack baseline is absent; use explicit interrupted-bind recovery"))
		}
		if correlateErr != nil {
			if errors.Is(correlateErr, cloudflare.ErrCertificatePackPending) && deployment.ManagedDomain.CertificatePackID == "" {
				return printError(stderr, "deploy", errors.New("generated certificate pack is still pending; rerun deploy after Cloudflare exposes it"))
			}
			return printError(stderr, "deploy", correlateErr)
		}
		if deployment.ManagedDomain.CertificatePackID != "" && pack.ID != deployment.ManagedDomain.CertificatePackID {
			return printError(stderr, "deploy", errors.New("current Custom Domain certificate is not in the stored generated certificate pack"))
		}
		if deployment.ManagedDomain.CertificatePackID == "" && !*dryRun {
			candidate := *deployment
			managed := *deployment.ManagedDomain
			managed.CertificatePackID = pack.ID
			managed.CertificatePackBaselineIDs = nil
			managed.CertificatePackBaselineRecorded = false
			candidate.ManagedDomain = &managed
			if err := config.Save(paths.config, &candidate); err != nil {
				return printError(stderr, "deploy", fmt.Errorf("persist generated certificate pack provenance: %w", err))
			}
			deployment = &candidate
		}
	}
	secretMissing := !hasSecret(statusBefore, config.WorkerSecretName)
	if secretMissing {
		if err := workerproject.PrepareBootstrap(paths.template, paths.workspace, *deployment); err != nil {
			return printError(stderr, "deploy", err)
		}
	}
	if _, err := client.Deploy(ctx, cloudflare.DeployOptions{Message: "cf-vless deployment preflight", DryRun: true}); err != nil {
		return printError(stderr, "deploy", err)
	}
	if *dryRun {
		fmt.Fprintln(stdout, "deployment dry-run passed for the exact bootstrap/update branch; no Cloudflare resources changed")
		return 0
	}
	secret, err := deployment.WorkerSecretJSON()
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	defer zero(secret)
	if !secretMissing {
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{Message: "cf-vless deployment"}); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.SetSecret(ctx, cloudflare.SecretRequest{
			Worker:          deployment.WorkerName,
			OwnershipMarker: deployment.OwnershipMarker,
			Name:            config.WorkerSecretName,
			Value:           secret,
		}); err != nil {
			return printError(stderr, "deploy", err)
		}
	} else {
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{Message: "cf-vless unroutable bootstrap"}); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.SetSecret(ctx, cloudflare.SecretRequest{
			Worker:          deployment.WorkerName,
			OwnershipMarker: deployment.OwnershipMarker,
			Name:            config.WorkerSecretName,
			Value:           secret,
		}); err != nil {
			return printError(stderr, "deploy", err)
		}
		if err := workerproject.Prepare(paths.template, paths.workspace, *deployment); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{Message: "cf-vless protected deployment preflight", DryRun: true}); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{Message: "cf-vless protected deployment"}); err != nil {
			return printError(stderr, "deploy", err)
		}
	}
	if deployment.ManagedDomain == nil {
		request := cloudflare.CustomDomainRequest{
			Hostname: deployment.Hostname, Worker: deployment.WorkerName, Environment: "production",
			ZoneID: deployment.ZoneID, ZoneName: deployment.ZoneName,
		}
		dryRequest := request
		dryRequest.DryRun = true
		if _, err := client.BindCustomDomain(ctx, dryRequest); err != nil {
			return printError(stderr, "deploy", err)
		}
		// Certificate inventory is re-read immediately before the only live bind.
		// A pack discovered here cannot be attributed to this deployment.
		beforeBind, _, err := client.ListCertificatePacks(ctx, deployment.ZoneID)
		if err != nil {
			return printError(stderr, "deploy", err)
		}
		if hasExactAdvancedCertificate(beforeBind, deployment.Hostname) {
			return printError(stderr, "deploy", errors.New("dedicated hostname gained an unplanned exact Advanced Certificate pack before binding"))
		}
		baselineIDs, err := certificatePackBaseline(beforeBind)
		if err != nil {
			return printError(stderr, "deploy", err)
		}
		bindResult, err := client.BindCustomDomain(ctx, request)
		if err != nil {
			return printError(stderr, "deploy", err)
		}
		managed, err := managedDomainFromChangedBind(bindResult, *deployment)
		if err != nil {
			return printError(stderr, "deploy", err)
		}
		managed.CertificatePackBaselineIDs = baselineIDs
		managed.CertificatePackBaselineRecorded = true
		candidate := *deployment
		candidate.ManagedDomain = managed
		// Persist the API-returned immutable Domain and initial certificate IDs
		// before waiting for the asynchronously-created certificate pack.
		if err := config.Save(paths.config, &candidate); err != nil {
			return printError(stderr, "deploy", fmt.Errorf("persist Custom Domain provenance: %w", err))
		}
		deployment = &candidate

		packs, _, err := client.ListCertificatePacks(ctx, deployment.ZoneID)
		if err != nil {
			return printError(stderr, "deploy", err)
		}
		pack, err := cloudflare.CorrelateNewGeneratedCertificatePack(
			packs, managed.CertificatePackBaselineIDs, deployment.Hostname,
		)
		if err != nil {
			if errors.Is(err, cloudflare.ErrCertificatePackPending) {
				return printError(stderr, "deploy", errors.New("Custom Domain was bound and recorded, but its generated certificate pack is still pending; rerun deploy"))
			}
			return printError(stderr, "deploy", err)
		}
		candidate = *deployment
		managedWithPack := *managed
		managedWithPack.CertificatePackID = pack.ID
		managedWithPack.CertificatePackBaselineIDs = nil
		managedWithPack.CertificatePackBaselineRecorded = false
		candidate.ManagedDomain = &managedWithPack
		if err := config.Save(paths.config, &candidate); err != nil {
			return printError(stderr, "deploy", fmt.Errorf("persist generated certificate pack provenance: %w", err))
		}
		deployment = &candidate

		// The workspace used before the first bind intentionally had no route.
		// Regenerate it from the now-provenanced state, validate the exact
		// protected configuration, and publish its declarative Custom Domain
		// before reporting the deployment as complete.
		if err := workerproject.Prepare(paths.template, paths.workspace, *deployment); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{
			Message: "cf-vless managed-domain publication preflight", DryRun: true,
		}); err != nil {
			return printError(stderr, "deploy", err)
		}
		if _, err := client.Deploy(ctx, cloudflare.DeployOptions{
			Message: "cf-vless managed-domain publication",
		}); err != nil {
			return printError(stderr, "deploy", err)
		}
	}
	status, err := client.WorkerStatus(ctx, deployment.WorkerName)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	finalPacks, _, err := client.ListCertificatePacks(ctx, deployment.ZoneID)
	if err != nil {
		return printError(stderr, "deploy", err)
	}
	if !statusComplete(status, *deployment, finalPacks) {
		return printError(stderr, "deploy", errors.New("post-deployment resource verification failed"))
	}
	if deps.probePublicHTTPS == nil {
		return printError(stderr, "deploy", errors.New("public HTTPS readiness probe is unavailable"))
	}
	if err := deps.probePublicHTTPS(ctx, deployment.Hostname); err != nil {
		return printError(stderr, "deploy", fmt.Errorf("public HTTPS readiness verification failed: %w", err))
	}
	fmt.Fprintf(stdout, "deployed Worker %s on https://%s\n", deployment.WorkerName, deployment.Hostname)
	fmt.Fprintf(stdout, "secret binding: %s; destination ports: %s\n", config.WorkerSecretName, portsText(deployment.AllowedPorts))
	return 0
}

func statusComplete(status cloudflare.WorkerStatus, deployment config.Deployment, packs []cloudflare.CertificatePack) bool {
	if !status.Exists || len(status.Domains) != 1 {
		return false
	}
	var managedBinding *cloudflare.DomainBinding
	for _, domain := range status.Domains {
		if strings.EqualFold(domain.Hostname, deployment.Hostname) && domain.Service == deployment.WorkerName &&
			productionDomainEnvironment(domain.Environment) && (domain.ZoneID == "" || domain.ZoneID == deployment.ZoneID) {
			if managedBinding != nil {
				return false
			}
			domainCopy := domain
			managedBinding = &domainCopy
		}
	}
	hasSecret := false
	for _, secret := range status.Secrets {
		if secret.Name == config.WorkerSecretName {
			hasSecret = true
		}
	}
	if managedBinding == nil || deployment.ManagedDomain == nil || deployment.ManagedDomain.CertificatePackID == "" ||
		managedBinding.ID != deployment.ManagedDomain.DomainID {
		return false
	}
	pack, err := cloudflare.SelectGeneratedCertificatePackByID(
		packs, deployment.ManagedDomain.CertificatePackID, deployment.Hostname,
	)
	return err == nil && pack.ID == deployment.ManagedDomain.CertificatePackID && pack.Status == "active" && hasSecret &&
		status.DeploymentCount > 0 && status.OwnershipMarker == deployment.OwnershipMarker
}

func validateServiceDomainInventory(domains []cloudflare.DomainBinding, deployment config.Deployment) error {
	managed := deployment.ManagedDomain
	if managed == nil {
		if len(domains) != 0 {
			return errors.New("Worker has a Custom Domain without creation-time provenance")
		}
		return nil
	}
	if len(domains) != 1 {
		return errors.New("Worker service-wide Custom Domain inventory does not contain exactly the stored managed domain")
	}
	domain := domains[0]
	if domain.ID != managed.DomainID || !strings.EqualFold(strings.TrimSuffix(domain.Hostname, "."), deployment.Hostname) ||
		domain.Service != deployment.WorkerName || !productionDomainEnvironment(domain.Environment) ||
		(domain.ZoneID != "" && domain.ZoneID != deployment.ZoneID) ||
		(domain.ZoneName != "" && !strings.EqualFold(strings.TrimSuffix(domain.ZoneName, "."), deployment.ZoneName)) {
		return errors.New("Worker service-wide Custom Domain inventory differs from stored provenance")
	}
	return nil
}

func validateManagedDomainState(check cloudflare.HostnameCheck, deployment config.Deployment) (*cloudflare.DomainBinding, error) {
	managed := deployment.ManagedDomain
	if managed == nil {
		if check.Owned {
			return nil, errors.New("owned Custom Domain exists without creation-time certificate provenance")
		}
		return nil, nil
	}
	if !check.Owned || len(check.Domains) != 1 {
		return nil, errors.New("stored managed Custom Domain is not the one currently attached to the Worker")
	}
	domain := check.Domains[0]
	if domain.ID != managed.DomainID {
		return nil, errors.New("current Custom Domain ID does not match stored provenance")
	}
	if managed.CertificatePackID == "" && !cloudflare.CertificateIDsEquivalent(domain.CertID, managed.InitialCertificateID) {
		return nil, errors.New("pending Custom Domain certificate changed before pack provenance was established")
	}
	return &domain, nil
}

func managedDomainFromChangedBind(result cloudflare.DomainBindResult, deployment config.Deployment) (*config.ManagedDomain, error) {
	binding := result.Binding
	if !result.Changed || result.Existing || result.DryRun || binding.ID == "" || binding.CertID == "" ||
		!strings.EqualFold(strings.TrimSuffix(binding.Hostname, "."), deployment.Hostname) ||
		binding.Service != deployment.WorkerName || !productionDomainEnvironment(binding.Environment) || binding.ZoneID != deployment.ZoneID ||
		!strings.EqualFold(strings.TrimSuffix(binding.ZoneName, "."), deployment.ZoneName) {
		return nil, errors.New("live Custom Domain bind did not return exact immutable resource identity")
	}
	managed := &config.ManagedDomain{
		DomainID: strings.ToLower(binding.ID), InitialCertificateID: strings.ToLower(binding.CertID),
	}
	candidate := deployment
	candidate.ManagedDomain = managed
	if err := candidate.Validate(); err != nil {
		return nil, errors.New("live Custom Domain bind returned invalid resource identity")
	}
	return managed, nil
}

func recoverInterruptedDomain(
	status cloudflare.WorkerStatus,
	deployment config.Deployment,
	expectedDomainID string,
) (*config.ManagedDomain, error) {
	if !status.Exists || status.OwnershipMarker != deployment.OwnershipMarker ||
		!hasSecret(status, config.WorkerSecretName) || len(status.Domains) != 1 {
		return nil, errors.New("interrupted Custom Domain recovery preconditions are not satisfied")
	}
	domain := status.Domains[0]
	if domain.ID != expectedDomainID || !strings.EqualFold(strings.TrimSuffix(domain.Hostname, "."), deployment.Hostname) ||
		domain.Service != deployment.WorkerName || !productionDomainEnvironment(domain.Environment) ||
		(domain.ZoneID != "" && domain.ZoneID != deployment.ZoneID) ||
		(domain.ZoneName != "" && !strings.EqualFold(strings.TrimSuffix(domain.ZoneName, "."), deployment.ZoneName)) {
		return nil, errors.New("interrupted Custom Domain does not match the explicit recovery identity")
	}
	managed := &config.ManagedDomain{
		DomainID:             strings.ToLower(domain.ID),
		InitialCertificateID: strings.ToLower(domain.CertID),
	}
	candidate := deployment
	candidate.ManagedDomain = managed
	if err := candidate.Validate(); err != nil {
		return nil, errors.New("interrupted Custom Domain returned invalid immutable resource identity")
	}
	return managed, nil
}

func productionDomainEnvironment(value string) bool {
	return value == "" || value == "production"
}

func hasExactAdvancedCertificate(packs []cloudflare.CertificatePack, hostname string) bool {
	for _, pack := range packs {
		if pack.Status == "deleted" || pack.Type != "advanced" {
			continue
		}
		for _, host := range pack.Hosts {
			if strings.EqualFold(strings.TrimSuffix(host, "."), hostname) {
				return true
			}
		}
	}
	return false
}

func certificatePackBaseline(packs []cloudflare.CertificatePack) ([]string, error) {
	if len(packs) > 100 {
		return nil, errors.New("certificate pack inventory is too large to checkpoint safely")
	}
	ids := make([]string, 0, len(packs))
	seen := make(map[string]struct{}, len(packs))
	for _, pack := range packs {
		if !canonicalCertificatePackIDPattern.MatchString(pack.ID) {
			return nil, errors.New("certificate pack inventory contains an invalid ID")
		}
		if _, duplicate := seen[pack.ID]; duplicate {
			return nil, errors.New("certificate pack inventory contains duplicate IDs")
		}
		seen[pack.ID] = struct{}{}
		ids = append(ids, strings.ToLower(pack.ID))
	}
	sort.Strings(ids)
	return ids, nil
}

var canonicalCertificatePackIDPattern = regexp.MustCompile(`^([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, deployment, err := loadDeployment(common)
	if err != nil {
		return printError(stderr, "status", err)
	}
	client, err := newCloudflareClient(deps, paths, deployment.AccountID, true)
	if err != nil {
		return printError(stderr, "status", err)
	}
	status, err := client.WorkerStatus(ctx, deployment.WorkerName)
	if err != nil {
		return printError(stderr, "status", err)
	}
	packs, _, err := client.ListCertificatePacks(ctx, deployment.ZoneID)
	if err != nil {
		return printError(stderr, "status", err)
	}
	complete := statusComplete(status, *deployment, packs)
	endpointReady := false
	var readinessErr error
	if deps.probePublicHTTPS == nil {
		readinessErr = errors.New("public HTTPS readiness probe is unavailable")
	} else {
		readinessErr = deps.probePublicHTTPS(ctx, deployment.Hostname)
		endpointReady = readinessErr == nil
	}
	fmt.Fprintf(stdout, "worker=%s exists=%t owned=%t deployments=%d domain=%t secret=%t certificate_proven=%t endpoint_ready=%t\n",
		deployment.WorkerName,
		status.Exists,
		status.OwnershipMarker == deployment.OwnershipMarker,
		status.DeploymentCount,
		hasDomain(status, deployment.Hostname),
		hasSecret(status, config.WorkerSecretName),
		complete,
		endpointReady,
	)
	if !complete || !endpointReady {
		if readinessErr != nil {
			fmt.Fprintf(stderr, "status: public HTTPS readiness verification failed: %v\n", readinessErr)
		}
		return 1
	}
	return 0
}

func hasDomain(status cloudflare.WorkerStatus, hostname string) bool {
	for _, domain := range status.Domains {
		if strings.EqualFold(domain.Hostname, hostname) {
			return true
		}
	}
	return false
}

func hasSecret(status cloudflare.WorkerStatus, name string) bool {
	for _, secret := range status.Secrets {
		if secret.Name == name {
			return true
		}
	}
	return false
}

func runIntegration(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	clients := flags.String("clients", "all", "all or comma-separated: xray,sing-box,mihomo")
	singBoxBinary := flags.String("sing-box-binary", "", "sing-box executable path; empty uses PATH")
	mihomoBinary := flags.String("mihomo-binary", "", "Mihomo executable path; empty uses PATH")
	httpsURL := flags.String("https-url", "", "HTTPS browsing/DNS probe URL")
	downloadURL := flags.String("download-url", "", "multi-megabyte download URL")
	uploadURL := flags.String("upload-url", "", "POST endpoint that echoes the exact ASCII body")
	tcpEcho := flags.String("tcp-echo", "", "controlled line-oriented public TCP echo host:port")
	longLived := flags.Duration("long-lived", 30*time.Second, "active same-connection TCP duration")
	concurrency := flags.Int("concurrency", 4, "simultaneous TCP connections")
	reconnects := flags.Int("reconnects", 3, "fresh reconnect attempts")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, _, operationLock, err := loadSettledDeploymentLocked(common)
	if err != nil {
		return printError(stderr, "test", err)
	}
	// The standalone integration command takes and holds this same lock for the
	// complete credential-bearing run. Release the wrapper's preflight lock
	// before starting it so the child can acquire the lock itself.
	if err := operationLock.Release(); err != nil {
		return printError(stderr, "test", fmt.Errorf("release preflight operation lock: %w", err))
	}
	commandArgs := []string{
		"run", "./cmd/integration-test",
		"-deployment", paths.config,
		"-clients", *clients,
		"-https-url", *httpsURL,
		"-download-url", *downloadURL,
		"-upload-url", *uploadURL,
		"-tcp-echo", *tcpEcho,
		"-long-lived", longLived.String(),
		"-concurrency", strconv.Itoa(*concurrency),
		"-reconnects", strconv.Itoa(*reconnects),
	}
	if *singBoxBinary != "" {
		commandArgs = append(commandArgs, "-sing-box-binary", *singBoxBinary)
	}
	if *mihomoBinary != "" {
		commandArgs = append(commandArgs, "-mihomo-binary", *mihomoBinary)
	}
	if err := deps.runLocal(ctx, paths.root, "go", commandArgs, stdout, stderr); err != nil {
		return 1
	}
	return 0
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	outputDirectory := flags.String("output", "client-configs", "owner-only client output directory")
	force := flags.Bool("force", false, "replace existing generated artifacts")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, deployment, operationLock, err := loadSettledDeploymentLocked(common)
	if err != nil {
		return printError(stderr, "config", err)
	}
	defer releaseOperationLock(operationLock, stderr)
	output := *outputDirectory
	if !filepath.IsAbs(output) {
		output = filepath.Join(paths.root, output)
	}
	if err := clientformats.WriteArtifacts(output, *deployment, *force); err != nil {
		return printError(stderr, "config", err)
	}
	fmt.Fprintf(stdout, "wrote 5 private client artifacts to %s\n", output)
	fmt.Fprintln(stdout, "Shadowrocket URI/QR manual verification is still required")
	return 0
}

func runRotate(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("rotate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	overlap := flags.Duration("overlap", 24*time.Hour, "old credential overlap")
	emergency := flags.Bool("emergency-revoke", false, "immediately replace and revoke all old credentials")
	finalize := flags.Bool("finalize", false, "remove an expired previous credential without rotating again")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	if *emergency && *finalize {
		fmt.Fprintln(stderr, "rotate: --emergency-revoke and --finalize are mutually exclusive")
		return 2
	}
	paths, deployment, operationLock, err := loadDeploymentLocked(common)
	if err != nil {
		return printError(stderr, "rotate", err)
	}
	defer releaseOperationLock(operationLock, stderr)
	client, err := newCloudflareClient(deps, paths, deployment.AccountID, true)
	if err != nil {
		return printError(stderr, "rotate", err)
	}
	if err := client.RequireSupportedCFVersion(ctx); err != nil {
		return printError(stderr, "rotate", err)
	}
	now := deps.now().UTC()
	candidate := *deployment
	pending, loadErr := config.Load(paths.pending)
	pendingExists := loadErr == nil
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return printError(stderr, "rotate", loadErr)
	}
	if pendingExists && !sameDeploymentConfiguration(*deployment, *pending) {
		return printError(stderr, "rotate", errors.New("pending credential operation changes noncredential deployment state"))
	}
	if pendingExists && sameCredentialSet(pending.Credentials, deployment.Credentials) {
		// Canonical state is written only after the remote secret update succeeds.
		// Equality therefore means the prior operation completed and only marker
		// cleanup was interrupted. Reconcile it without starting a second rotation,
		// regardless of which rotate mode the operator used to resume.
		if err := config.RemoveSecretFile(paths.pending); err != nil {
			return printError(stderr, "rotate", err)
		}
		fmt.Fprintln(stdout, "reconciled completed credential operation; no new rotation performed")
		return 0
	}

	switch {
	case *emergency:
		if pendingExists && pending.Credentials.Previous == nil && pending.Credentials.Current != deployment.Credentials.Current {
			candidate = *pending
			fmt.Fprintln(stdout, "resuming pending emergency revocation")
		} else {
			if err := candidate.EmergencyRotateCredential(); err != nil {
				return printError(stderr, "rotate", err)
			}
			if err := savePendingCandidate(paths.pending, &candidate, pendingExists); err != nil {
				return printError(stderr, "rotate", err)
			}
		}
	case *finalize:
		if pendingExists && pending.Credentials.Previous == nil && pending.Credentials.Current == deployment.Credentials.Current && deployment.Credentials.Previous != nil {
			candidate = *pending
			fmt.Fprintln(stdout, "resuming pending overlap finalization")
		} else {
			if err := candidate.FinalizeCredential(now); err != nil {
				return printError(stderr, "rotate", err)
			}
			if deployment.Credentials.Previous == nil {
				fmt.Fprintln(stdout, "no previous credential remains to finalize")
				return 0
			}
			if err := savePendingCandidate(paths.pending, &candidate, pendingExists); err != nil {
				return printError(stderr, "rotate", err)
			}
		}
	default:
		if pendingExists {
			if !validPendingRotation(*deployment, *pending) {
				return printError(stderr, "rotate", errors.New("pending rotation does not safely extend the current deployment"))
			}
			candidate = *pending
			fmt.Fprintln(stdout, "resuming pending credential rotation")
		} else {
			if err := candidate.RotateCredential(now, *overlap); err != nil {
				return printError(stderr, "rotate", err)
			}
			if err := config.SaveNew(paths.pending, &candidate); err != nil {
				return printError(stderr, "rotate", err)
			}
		}
	}
	secret, err := candidate.WorkerSecretJSON()
	if err != nil {
		return printError(stderr, "rotate", err)
	}
	defer zero(secret)
	if _, err := client.SetSecret(ctx, cloudflare.SecretRequest{
		Worker:          candidate.WorkerName,
		OwnershipMarker: candidate.OwnershipMarker,
		Name:            config.WorkerSecretName,
		Value:           secret,
	}); err != nil {
		fmt.Fprintf(stderr, "rotate: remote update failed; pending state retained at %s\n", paths.pending)
		return 1
	}
	if err := config.Save(paths.config, &candidate); err != nil {
		fmt.Fprintf(stderr, "rotate: remote credential changed; resume using pending state at %s\n", paths.pending)
		return 1
	}
	if err := config.RemoveSecretFile(paths.pending); err != nil {
		fmt.Fprintf(stderr, "warning: remove completed pending marker: %v\n", err)
	}
	if *emergency {
		fmt.Fprintln(stdout, "rotated UUID and path; all previous credentials were revoked immediately")
	} else if *finalize {
		fmt.Fprintln(stdout, "removed the expired previous credential from local and Worker state")
	} else {
		expiresAt := candidate.Credentials.Previous.ExpiresAt.UTC().Format(time.RFC3339)
		fmt.Fprintf(stdout, "rotated UUID and path; previous pair expires at %s\n", expiresAt)
	}
	fmt.Fprintln(stdout, "regenerate and redistribute client artifacts now")
	return 0
}

func savePendingCandidate(path string, candidate *config.Deployment, overwrite bool) error {
	if overwrite {
		return config.Save(path, candidate)
	}
	return config.SaveNew(path, candidate)
}

func sameDeploymentConfiguration(left, right config.Deployment) bool {
	return left.Version == right.Version && left.WorkerName == right.WorkerName && left.AccountID == right.AccountID &&
		left.ZoneID == right.ZoneID && left.ZoneName == right.ZoneName && left.Hostname == right.Hostname &&
		left.Port == right.Port && left.DisplayName == right.DisplayName && left.OwnershipMarker == right.OwnershipMarker &&
		slices.Equal(left.AllowedPorts, right.AllowedPorts) && sameManagedDomain(left.ManagedDomain, right.ManagedDomain)
}

func sameManagedDomain(left, right *config.ManagedDomain) bool {
	if (left == nil) != (right == nil) {
		return false
	}
	return left == nil || (left.DomainID == right.DomainID &&
		left.InitialCertificateID == right.InitialCertificateID &&
		left.CertificatePackID == right.CertificatePackID &&
		left.CertificatePackBaselineRecorded == right.CertificatePackBaselineRecorded &&
		slices.Equal(left.CertificatePackBaselineIDs, right.CertificatePackBaselineIDs))
}

func sameCredentialSet(left, right config.CredentialSet) bool {
	if left.Current != right.Current || (left.Previous == nil) != (right.Previous == nil) {
		return false
	}
	if left.Previous == nil {
		return true
	}
	return left.Previous.Credential == right.Previous.Credential && left.Previous.ExpiresAt.Equal(right.Previous.ExpiresAt)
}

func validPendingRotation(current, pending config.Deployment) bool {
	if !sameDeploymentConfiguration(current, pending) || pending.Credentials.Previous == nil {
		return false
	}
	previous := pending.Credentials.Previous.Credential
	return previous == current.Credentials.Current && pending.Credentials.Current != current.Credentials.Current
}

func runLogs(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("logs", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	status := flags.String("status", "", "optional ok, error, or canceled filter")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, deployment, err := loadDeployment(common)
	if err != nil {
		return printError(stderr, "logs", err)
	}
	client, err := newCloudflareClient(deps, paths, deployment.AccountID, true)
	if err != nil {
		return printError(stderr, "logs", err)
	}
	workerStatus, err := client.WorkerStatus(ctx, deployment.WorkerName)
	if err != nil {
		return printError(stderr, "logs", err)
	}
	if !workerStatus.Exists || workerStatus.OwnershipMarker != deployment.OwnershipMarker {
		return printError(stderr, "logs", errors.New("refusing to tail a Worker not owned by this deployment"))
	}
	statuses := []string(nil)
	if *status != "" {
		statuses = []string{*status}
	}
	sanitizer := &logSanitizer{output: stdout}
	if _, err := client.TailLogs(ctx, cloudflare.LogsOptions{
		Worker:   deployment.WorkerName,
		Statuses: statuses,
		Stdout:   sanitizer,
		Stderr:   stderr,
	}); err != nil {
		_ = sanitizer.Flush()
		return printError(stderr, "logs", err)
	}
	if err := sanitizer.Flush(); err != nil {
		return printError(stderr, "logs", err)
	}
	return 0
}

type logSanitizer struct {
	mu     sync.Mutex
	output io.Writer
	buffer []byte
	err    error
}

func (sanitizer *logSanitizer) Write(content []byte) (int, error) {
	sanitizer.mu.Lock()
	defer sanitizer.mu.Unlock()
	if sanitizer.err != nil {
		return 0, sanitizer.err
	}
	sanitizer.buffer = append(sanitizer.buffer, content...)
	for {
		index := bytesIndexByte(sanitizer.buffer, '\n')
		if index < 0 {
			break
		}
		line := append([]byte(nil), sanitizer.buffer[:index]...)
		sanitizer.buffer = sanitizer.buffer[index+1:]
		if err := sanitizer.writeLine(line); err != nil {
			sanitizer.err = err
			return 0, err
		}
	}
	if len(sanitizer.buffer) > 512*1024 {
		sanitizer.buffer = sanitizer.buffer[:0]
		if err := sanitizer.writeLine(nil); err != nil {
			sanitizer.err = err
			return 0, err
		}
	}
	return len(content), nil
}

func (sanitizer *logSanitizer) Flush() error {
	sanitizer.mu.Lock()
	defer sanitizer.mu.Unlock()
	if sanitizer.err != nil {
		return sanitizer.err
	}
	if len(sanitizer.buffer) == 0 {
		return nil
	}
	line := append([]byte(nil), sanitizer.buffer...)
	sanitizer.buffer = sanitizer.buffer[:0]
	sanitizer.err = sanitizer.writeLine(line)
	return sanitizer.err
}

func (sanitizer *logSanitizer) writeLine(line []byte) error {
	var value any
	if len(line) == 0 || json.Unmarshal(line, &value) != nil {
		value = map[string]any{"event": "unparsed_log_redacted"}
	} else {
		value = sanitizeLogValue(value)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode sanitized log")
	}
	encoded = append(encoded, '\n')
	_, err = sanitizer.output.Write(encoded)
	return err
}

func sanitizeLogValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		sanitized := make(map[string]any, len(typed))
		for key, child := range typed {
			if sensitiveDynamicLogKey(key) {
				sanitized["[REDACTED_KEY]"] = "[REDACTED]"
			} else if sensitiveLogKey(key) {
				sanitized[key] = "[REDACTED]"
			} else if text, ok := child.(string); ok {
				sanitized[key] = sanitizeOperationalLogString(key, text)
			} else {
				sanitized[key] = sanitizeLogValue(child)
			}
		}
		return sanitized
	case []any:
		for index, child := range typed {
			typed[index] = sanitizeLogValue(child)
		}
		return typed
	default:
		if _, ok := value.(string); ok {
			return "[REDACTED]"
		}
		return value
	}
}

func sanitizeOperationalLogString(key, value string) string {
	switch strings.ToLower(key) {
	case "level", "outcome", "status":
		if len(value) == 0 || len(value) > 64 {
			return "[REDACTED]"
		}
		for _, character := range value {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || strings.ContainsRune("_.-", character) {
				continue
			}
			return "[REDACTED]"
		}
		return value
	default:
		return "[REDACTED]"
	}
}

func sensitiveLogKey(key string) bool {
	normalized := strings.ToLower(key)
	for _, fragment := range []string{
		"uuid", "destination", "client", "ip", "url", "path", "header", "request", "message", "exception", "log",
		"body", "content", "payload", "data", "bytes", "frame",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

var (
	logUUIDKeyPattern     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	logHostnameKeyPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$`)
)

func sensitiveDynamicLogKey(key string) bool {
	return logUUIDKeyPattern.MatchString(key) || strings.Contains(key, "://") || logHostnameKeyPattern.MatchString(key)
}

func bytesIndexByte(value []byte, target byte) int {
	for index, current := range value {
		if current == target {
			return index
		}
	}
	return -1
}

func runRemove(ctx context.Context, args []string, stdout, stderr io.Writer, deps dependencies) int {
	flags := flag.NewFlagSet("remove", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var common commonFlags
	common.bind(flags)
	confirm := flags.Bool("yes", false, "confirm exact named resource removal")
	dryRun := flags.Bool("dry-run", false, "show exact removals without changing resources")
	if code, ok := parseFlagSet(flags, args); !ok {
		return code
	}
	paths, deployment, operationLock, err := loadDeploymentLocked(common)
	if err != nil {
		return printError(stderr, "remove", err)
	}
	defer releaseOperationLock(operationLock, stderr)
	if !*dryRun && !*confirm {
		fmt.Fprintln(stderr, "remove requires --yes; cf will still present its safe Worker confirmation")
		return 2
	}
	if deployment.ManagedDomain == nil || deployment.ManagedDomain.CertificatePackID == "" {
		return printError(stderr, "remove", errors.New("complete creation-time Custom Domain and certificate-pack provenance is required before automatic removal"))
	}
	client, err := newCloudflareClient(deps, paths, deployment.AccountID, true)
	if err != nil {
		return printError(stderr, "remove", err)
	}
	if err := client.RequireSupportedCFVersion(ctx); err != nil {
		return printError(stderr, "remove", err)
	}
	checkpoint, loadErr := config.LoadRemovalCheckpoint(paths.removal)
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return printError(stderr, "remove", loadErr)
	}
	if checkpoint != nil && !checkpoint.Matches(*deployment) {
		return printError(stderr, "remove", errors.New("removal checkpoint belongs to a different deployment"))
	}
	if checkpoint != nil && (checkpoint.DomainID != deployment.ManagedDomain.DomainID ||
		checkpoint.CertificatePackID != deployment.ManagedDomain.CertificatePackID) {
		return printError(stderr, "remove", errors.New("removal checkpoint does not match stored creation-time resource provenance"))
	}
	resources := cloudflare.NamedResources{
		Worker:                           deployment.WorkerName,
		OwnershipMarker:                  deployment.OwnershipMarker,
		Hostname:                         deployment.Hostname,
		Environment:                      "production",
		ZoneID:                           deployment.ZoneID,
		ZoneName:                         deployment.ZoneName,
		SecretNames:                      []string{config.WorkerSecretName},
		ExpectedDomainID:                 deployment.ManagedDomain.DomainID,
		EnforceExpectedDomainID:          true,
		ExpectedCertificatePackID:        deployment.ManagedDomain.CertificatePackID,
		EnforceExpectedCertificatePackID: true,
	}

	// A confirmed removal first executes the complete provider dry-run and
	// durably checkpoints the exact domain/certificate IDs. No live deletion is
	// allowed to begin until that checkpoint is on disk.
	preflight, err := client.RemoveNamed(ctx, cloudflare.RemoveOptions{DryRun: true, Resources: resources})
	if err != nil {
		return printError(stderr, "remove", err)
	}
	if checkpoint == nil {
		checkpointValue, checkpointErr := config.NewRemovalCheckpoint(
			*deployment, []string{deployment.ManagedDomain.DomainID}, []string{deployment.ManagedDomain.CertificatePackID},
		)
		if checkpointErr != nil {
			return printError(stderr, "remove", checkpointErr)
		}
		checkpoint = &checkpointValue
		if !*dryRun {
			if err := config.SaveRemovalCheckpointNew(paths.removal, checkpoint); err != nil {
				return printError(stderr, "remove", err)
			}
		}
	} else if err := removalPlanMatchesCheckpoint(preflight.Plan, *checkpoint); err != nil {
		return printError(stderr, "remove", err)
	}

	result := preflight
	if !*dryRun {
		result, err = client.RemoveNamed(ctx, cloudflare.RemoveOptions{
			Confirm: true, Resources: resources,
		})
		if err != nil {
			fmt.Fprintf(stderr, "remove: %v\n", err)
			fmt.Fprintf(stderr, "remove: partial removal may have occurred; resume with checkpoint %s\n", paths.removal)
			return 1
		}
		verification, verifyErr := client.RemoveNamed(ctx, cloudflare.RemoveOptions{
			DryRun: true, Resources: resources,
		})
		if verifyErr != nil || !removalPlanEmpty(verification.Plan) {
			if verifyErr != nil {
				fmt.Fprintf(stderr, "remove: post-removal verification: %v\n", verifyErr)
			} else {
				fmt.Fprintln(stderr, "remove: post-removal verification has not converged")
			}
			fmt.Fprintf(stderr, "remove: resume with checkpoint %s\n", paths.removal)
			return 1
		}
		if err := config.RemoveSecretFile(paths.removal); err != nil {
			fmt.Fprintf(stderr, "warning: remove completed removal checkpoint: %v\n", err)
		}
	}
	planJSON, err := json.Marshal(preflight.Plan)
	if err != nil {
		return printError(stderr, "encode removal plan", err)
	}
	fmt.Fprintf(stdout, "deletion plan: %s\n", planJSON)
	fmt.Fprintf(stdout, "removed domain bindings=%d certificate_packs=%d secrets=%d worker=%t dry_run=%t\n",
		len(result.RemovedDomainIDs), len(result.RemovedCertificatePackIDs), len(result.RemovedSecrets), result.WorkerRemoved, result.DryRun)
	fmt.Fprintln(stdout, "local deployment and client files were retained")
	return 0
}

func removalPlanEmpty(plan cloudflare.RemovalPlan) bool {
	return !plan.DeleteWorker && len(plan.DomainIDs) == 0 && len(plan.CertificatePackIDs) == 0 && len(plan.SecretNames) == 0
}

func removalPlanMatchesCheckpoint(plan cloudflare.RemovalPlan, checkpoint config.RemovalCheckpoint) error {
	if plan.Worker != checkpoint.WorkerName || plan.Hostname != checkpoint.Hostname {
		return errors.New("remote removal plan no longer matches the checkpointed deployment")
	}
	if len(plan.DomainIDs) > 1 || len(plan.CertificatePackIDs) > 1 {
		return errors.New("remote removal plan became ambiguous")
	}
	if len(plan.DomainIDs) == 1 && plan.DomainIDs[0] != checkpoint.DomainID {
		return errors.New("Custom Domain ID changed after removal was checkpointed")
	}
	if checkpoint.DomainID == "" && len(plan.DomainIDs) != 0 {
		return errors.New("an unplanned Custom Domain appeared after removal was checkpointed")
	}
	if len(plan.CertificatePackIDs) == 1 && plan.CertificatePackIDs[0] != checkpoint.CertificatePackID {
		return errors.New("certificate pack ID changed after removal was checkpointed")
	}
	if checkpoint.CertificatePackID == "" && len(plan.CertificatePackIDs) != 0 {
		return errors.New("an unplanned certificate pack appeared after removal was checkpointed")
	}
	return nil
}

func loadDeployment(common commonFlags) (resolvedPaths, *config.Deployment, error) {
	paths, err := common.resolve()
	if err != nil {
		return paths, nil, err
	}
	deployment, err := config.Load(paths.config)
	if err != nil {
		return paths, nil, err
	}
	return paths, deployment, nil
}

func loadDeploymentLocked(common commonFlags) (resolvedPaths, *config.Deployment, *config.OperationLock, error) {
	paths, err := common.resolve()
	if err != nil {
		return paths, nil, nil, err
	}
	operationLock, err := config.AcquireOperationLock(paths.stateDir)
	if err != nil {
		return paths, nil, nil, err
	}
	deployment, err := config.Load(paths.config)
	if err != nil {
		_ = operationLock.Release()
		return paths, nil, nil, err
	}
	return paths, deployment, operationLock, nil
}

func loadSettledDeploymentLocked(common commonFlags) (resolvedPaths, *config.Deployment, *config.OperationLock, error) {
	paths, err := common.resolve()
	if err != nil {
		return paths, nil, nil, err
	}
	operationLock, err := config.AcquireOperationLock(paths.stateDir)
	if err != nil {
		return paths, nil, nil, err
	}
	if err := config.RequireSettledCredentials(paths.config); err != nil {
		_ = operationLock.Release()
		return paths, nil, nil, err
	}
	deployment, err := config.Load(paths.config)
	if err != nil {
		_ = operationLock.Release()
		return paths, nil, nil, err
	}
	return paths, deployment, operationLock, nil
}

func releaseOperationLock(operationLock *config.OperationLock, stderr io.Writer) {
	if err := operationLock.Release(); err != nil {
		fmt.Fprintf(stderr, "warning: release operation lock: %v\n", err)
	}
}

func portsText(ports []uint16) string {
	parts := make([]string, len(ports))
	for index, port := range ports {
		parts[index] = strconv.Itoa(int(port))
	}
	return strings.Join(parts, ",")
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func printError(writer io.Writer, command string, err error) int {
	message := err.Error()
	if len(message) > 4096 {
		message = message[:4096] + "...[truncated]"
	}
	fmt.Fprintf(writer, "%s: %s\n", command, message)
	return 1
}
