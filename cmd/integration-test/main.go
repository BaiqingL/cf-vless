// Command integration-test runs identical end-to-end probes through
// unmodified Xray, sing-box, and Mihomo clients. Endpoint credentials are read
// only from a canonical 0600 deployment file.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/BaiqingL/cf-vless/internal/clientintegration"
	"github.com/BaiqingL/cf-vless/internal/config"
	"github.com/BaiqingL/cf-vless/internal/xray"
)

type options struct {
	deployment     string
	clients        string
	xraySource     string
	xrayBinary     string
	singBoxBinary  string
	mihomoBinary   string
	httpsURL       string
	downloadURL    string
	uploadURL      string
	downloadSize   int64
	uploadSize     int64
	tcpAddress     string
	longLived      time.Duration
	concurrency    int
	reconnects     int
	probeTimeout   time.Duration
	overallTimeout time.Duration
}

type integrationReport struct {
	SchemaVersion int               `json:"schema_version"`
	Passed        bool              `json:"passed"`
	StartedAt     time.Time         `json:"started_at"`
	DurationMS    int64             `json:"duration_ms"`
	Gates         []xray.GateResult `json:"gates,omitempty"`
	Clients       []clientReport    `json:"clients"`
}

type clientReport struct {
	Name            string            `json:"name"`
	Version         string            `json:"version,omitempty"`
	ReferenceCommit string            `json:"reference_commit,omitempty"`
	ReferenceTag    string            `json:"reference_tag,omitempty"`
	Passed          bool              `json:"passed"`
	DurationMS      int64             `json:"duration_ms"`
	Gates           []xray.GateResult `json:"gates"`
}

type operationLock interface {
	Release() error
}

type privateWorkspaceOperations struct {
	create    func(string, string) (string, error)
	removeAll func(string) error
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithPrivateWorkspaceOperations(args, stdout, stderr, privateWorkspaceOperations{
		create:    os.MkdirTemp,
		removeAll: os.RemoveAll,
	})
}

func runWithPrivateWorkspaceOperations(args []string, stdout, stderr io.Writer, workspaceOperations privateWorkspaceOperations) (exitCode int) {
	started := time.Now().UTC()
	configuration, parseError := parseOptions(args, stderr)
	if parseError != nil {
		if errors.Is(parseError, flag.ErrHelp) {
			return 0
		}
		writeGlobalFailure(stdout, started, "arguments_invalid")
		return 2
	}
	selection, err := clientintegration.ParseSelection(configuration.clients)
	if err != nil {
		writeGlobalFailure(stdout, started, "client_selection_invalid")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), configuration.overallTimeout)
	defer cancel()
	lock, err := config.AcquireOperationLock(filepath.Dir(configuration.deployment))
	if err != nil {
		writeGlobalFailure(stdout, started, "deployment_prerequisites_invalid")
		return 1
	}
	lockReleased := false
	defer func() {
		if lockReleased {
			return
		}
		if err := lock.Release(); err != nil {
			fmt.Fprintln(stderr, "operation lock cleanup failed")
			exitCode = 1
		}
	}()
	if err := config.RequireSettledCredentials(configuration.deployment); err != nil {
		lockReleased = true
		return finishIntegrationRun(stdout, stderr, started, globalFailureReport(started, "credential_operation_pending"), nil, lock)
	}
	deployment, err := config.Load(configuration.deployment)
	if err != nil {
		lockReleased = true
		return finishIntegrationRun(stdout, stderr, started, globalFailureReport(started, "deployment_prerequisites_invalid"), nil, lock)
	}
	probeOptions := xray.ProbeOptions{
		HTTPSURL:         configuration.httpsURL,
		DownloadURL:      configuration.downloadURL,
		UploadURL:        configuration.uploadURL,
		DownloadMinBytes: configuration.downloadSize,
		UploadBytes:      configuration.uploadSize,
		TCPAddress:       configuration.tcpAddress,
		LongLived:        configuration.longLived,
		Concurrency:      configuration.concurrency,
		Reconnects:       configuration.reconnects,
		ProbeTimeout:     configuration.probeTimeout,
	}
	if err := probeOptions.Validate(); err != nil {
		lockReleased = true
		return finishIntegrationRun(stdout, stderr, started, globalFailureReport(started, "probe_prerequisites_invalid"), nil, lock)
	}
	temporaryDirectory, err := workspaceOperations.create("", "cf-vless-client-integration-*")
	if err != nil {
		lockReleased = true
		return finishIntegrationRun(stdout, stderr, started, globalFailureReport(started, "private_workspace_unavailable"), nil, lock)
	}

	report := integrationReport{
		SchemaVersion: 2,
		StartedAt:     started,
		Clients:       make([]clientReport, 0, len(selection)),
	}
	for _, name := range selection {
		client := runSelectedClient(ctx, name, configuration, deployment, probeOptions, temporaryDirectory)
		report.Clients = append(report.Clients, client)
	}
	cleanupStarted := time.Now()
	cleanupError := workspaceOperations.removeAll(temporaryDirectory)
	if cleanupError != nil {
		report.Gates = append(report.Gates, failedGate("cleanup", "private_workspace_cleanup_failed", cleanupStarted))
	}
	lockReleased = true
	return finishIntegrationRun(stdout, stderr, started, report, cleanupError, lock)
}

func finishIntegrationRun(stdout, stderr io.Writer, started time.Time, report integrationReport, cleanupError error, lock operationLock) int {
	lockReleaseStarted := time.Now()
	lockReleaseError := lock.Release()
	if lockReleaseError != nil {
		report.Gates = append(report.Gates, failedGate("operation_lock", "operation_lock_release_failed", lockReleaseStarted))
		fmt.Fprintln(stderr, "operation lock cleanup failed")
	}
	report.Passed = len(report.Clients) > 0 && cleanupError == nil && lockReleaseError == nil
	for _, client := range report.Clients {
		if !client.Passed {
			report.Passed = false
			break
		}
	}
	report.DurationMS = time.Since(started).Milliseconds()
	if err := writeReport(stdout, report); err != nil {
		fmt.Fprintln(stderr, "write integration report failed")
		return 1
	}
	if !report.Passed {
		fmt.Fprintln(stderr, "integration test failed")
		return 1
	}
	return 0
}

func runSelectedClient(ctx context.Context, name clientintegration.Name, configuration options, deployment *config.Deployment, probeOptions xray.ProbeOptions, workspace string) clientReport {
	started := time.Now()
	report := clientReport{Name: string(name), Gates: make([]xray.GateResult, 0, 12)}
	binaryStarted := time.Now()
	binary, err := clientBinary(ctx, name, configuration)
	if err != nil {
		report.Gates = append(report.Gates, failedGate("binary", "client_binary_unavailable", binaryStarted))
		report.DurationMS = time.Since(started).Milliseconds()
		return report
	}
	if name == clientintegration.Xray {
		report.ReferenceCommit = xray.PinnedCommit
		report.ReferenceTag = xray.PinnedTag
	}
	report.Gates = append(report.Gates, passedGate("binary", binaryStarted, map[string]int64{"bytes": fileSize(binary)}))

	portStarted := time.Now()
	socksPort, err := xray.ReserveLoopbackPort()
	if err != nil {
		report.Gates = append(report.Gates, failedGate("listener", "socks_port_unavailable", portStarted))
		report.DurationMS = time.Since(started).Milliseconds()
		return report
	}
	report.Gates = append(report.Gates, passedGate("listener", portStarted, nil))

	configStarted := time.Now()
	directory := filepath.Join(workspace, string(name))
	specification, err := clientintegration.Prepare(name, binary, directory, deployment, socksPort)
	if err != nil {
		report.Gates = append(report.Gates, failedGate("config", "client_config_failed", configStarted))
		report.DurationMS = time.Since(started).Milliseconds()
		return report
	}
	report.Gates = append(report.Gates, passedGate("config", configStarted, nil))

	runner := clientintegration.Runner{StartupTimeout: configuration.probeTimeout}
	versionStarted := time.Now()
	report.Version, err = runner.Version(ctx, specification)
	if err != nil {
		report.Gates = append(report.Gates, failedGate("version", "client_version_failed", versionStarted))
		report.DurationMS = time.Since(started).Milliseconds()
		return report
	}
	report.Gates = append(report.Gates, passedGate("version", versionStarted, nil))

	startStarted := time.Now()
	process, err := runner.Start(ctx, specification)
	if err != nil {
		report.Gates = append(report.Gates, failedGate("start", "client_start_failed", startStarted))
		report.DurationMS = time.Since(started).Milliseconds()
		return report
	}
	report.Gates = append(report.Gates, passedGate("start", startStarted, nil))

	dialer := xray.SOCKS5Dialer{ProxyAddress: specification.SOCKSAddress, Timeout: configuration.probeTimeout}
	probeReport, probeError := xray.RunProbes(ctx, dialer.DialContext, probeOptions)
	report.Gates = append(report.Gates, probeReport.Gates...)

	stopStarted := time.Now()
	stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	stopError := process.Stop(stopContext)
	stopCancel()
	if stopError != nil {
		report.Gates = append(report.Gates, failedGate("shutdown", "client_shutdown_failed", stopStarted))
	} else {
		report.Gates = append(report.Gates, passedGate("shutdown", stopStarted, nil))
	}
	report.Passed = probeError == nil && stopError == nil
	report.DurationMS = time.Since(started).Milliseconds()
	return report
}

func clientBinary(ctx context.Context, name clientintegration.Name, configuration options) (string, error) {
	switch name {
	case clientintegration.Xray:
		result, err := (xray.Builder{RepoDir: configuration.xraySource, OutputPath: configuration.xrayBinary}).Build(ctx)
		if err != nil {
			return "", err
		}
		return result.Path, nil
	case clientintegration.SingBox:
		return clientintegration.LocateBinary(name, configuration.singBoxBinary)
	case clientintegration.Mihomo:
		return clientintegration.LocateBinary(name, configuration.mihomoBinary)
	default:
		return "", errors.New("unsupported client")
	}
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var configuration options
	flags := flag.NewFlagSet("integration-test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&configuration.deployment, "deployment", "", "canonical 0600 deployment JSON file")
	flags.StringVar(&configuration.clients, "clients", "all", "all or comma-separated: xray,sing-box,mihomo")
	flags.StringVar(&configuration.xraySource, "xray-source", "third_party/xray-core", "pinned Xray submodule path")
	flags.StringVar(&configuration.xrayBinary, "xray-binary", filepath.Join("bin", "xray-"+xray.PinnedTag), "output path for the freshly built Xray binary")
	flags.StringVar(&configuration.singBoxBinary, "sing-box-binary", "", "sing-box executable path; empty uses PATH")
	flags.StringVar(&configuration.mihomoBinary, "mihomo-binary", "", "Mihomo executable path; empty uses PATH")
	flags.StringVar(&configuration.httpsURL, "https-url", "", "HTTPS hostname URL used for DNS and browsing gate")
	flags.StringVar(&configuration.downloadURL, "download-url", "", "multi-megabyte HTTP(S) download URL")
	flags.StringVar(&configuration.uploadURL, "upload-url", "", "HTTP(S) POST endpoint that echoes the exact ASCII body")
	flags.Int64Var(&configuration.downloadSize, "download-min-bytes", xray.MinimumDownloadBytes, "minimum accepted download body size")
	flags.Int64Var(&configuration.uploadSize, "upload-bytes", 2*1024*1024, "number of deterministic bytes to upload")
	flags.StringVar(&configuration.tcpAddress, "tcp-echo", "", "line-oriented public TCP echo host:port")
	flags.DurationVar(&configuration.longLived, "long-lived", 30*time.Second, "active same-connection TCP duration")
	flags.IntVar(&configuration.concurrency, "concurrency", 4, "simultaneous TCP echo connections")
	flags.IntVar(&configuration.reconnects, "reconnects", 3, "sequential fresh TCP connections")
	flags.DurationVar(&configuration.probeTimeout, "probe-timeout", 60*time.Second, "timeout for each network operation")
	flags.DurationVar(&configuration.overallTimeout, "overall-timeout", 30*time.Minute, "hard timeout for all selected clients and gates")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 || configuration.overallTimeout <= 0 || configuration.deployment == "" {
		return options{}, errors.New("invalid arguments")
	}
	return configuration, nil
}

func passedGate(name string, started time.Time, metrics map[string]int64) xray.GateResult {
	return xray.GateResult{Name: name, Passed: true, DurationMS: time.Since(started).Milliseconds(), Metrics: metrics}
}

func failedGate(name, code string, started time.Time) xray.GateResult {
	return xray.GateResult{Name: name, Passed: false, DurationMS: time.Since(started).Milliseconds(), Error: code}
}

func writeGlobalFailure(writer io.Writer, started time.Time, code string) {
	_ = writeReport(writer, globalFailureReport(started, code))
}

func globalFailureReport(started time.Time, code string) integrationReport {
	return integrationReport{
		SchemaVersion: 2,
		Passed:        false,
		StartedAt:     started,
		DurationMS:    time.Since(started).Milliseconds(),
		Gates: []xray.GateResult{{
			Name:   "prerequisites",
			Passed: false,
			Error:  code,
		}},
		Clients: []clientReport{},
	}
}

func writeReport(writer io.Writer, report integrationReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
