package xray

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	MinimumDownloadBytes int64 = 2 * 1024 * 1024
	MinimumUploadBytes   int64 = 1 * 1024 * 1024
)

type ProbeOptions struct {
	HTTPSURL         string
	DownloadURL      string
	UploadURL        string
	DownloadMinBytes int64
	UploadBytes      int64
	TCPAddress       string
	LongLived        time.Duration
	Concurrency      int
	Reconnects       int
	ProbeTimeout     time.Duration

	// TLSConfig exists for unit tests with private trust roots. The live
	// command leaves it nil and always uses the system verifier.
	TLSConfig *tls.Config
}

func (options ProbeOptions) Validate() error {
	if err := validateProbeURL(options.HTTPSURL, true); err != nil {
		return errors.New("HTTPS DNS probe URL is invalid")
	}
	if err := validateProbeURL(options.DownloadURL, false); err != nil {
		return errors.New("download probe URL is invalid")
	}
	if err := validateProbeURL(options.UploadURL, false); err != nil {
		return errors.New("upload probe URL is invalid")
	}
	if options.DownloadMinBytes < MinimumDownloadBytes {
		return fmt.Errorf("download probe must require at least %d bytes", MinimumDownloadBytes)
	}
	if options.UploadBytes < MinimumUploadBytes {
		return fmt.Errorf("upload probe must send at least %d bytes", MinimumUploadBytes)
	}
	host, port, err := net.SplitHostPort(options.TCPAddress)
	if err != nil || host == "" {
		return errors.New("TCP echo address is invalid")
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return errors.New("TCP echo port is invalid")
	}
	if options.LongLived <= 0 {
		return errors.New("long-lived probe duration must be positive")
	}
	if options.Concurrency < 2 {
		return errors.New("concurrency probe requires at least two connections")
	}
	if options.Reconnects < 2 {
		return errors.New("reconnect probe requires at least two connections")
	}
	if options.ProbeTimeout <= 0 {
		return errors.New("probe timeout must be positive")
	}
	return nil
}

func validateProbeURL(raw string, requireHTTPSDomain bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return errors.New("invalid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("unsupported URL scheme")
	}
	if requireHTTPSDomain && (parsed.Scheme != "https" || net.ParseIP(parsed.Hostname()) != nil || parsed.Hostname() == "") {
		return errors.New("HTTPS DNS probe requires a hostname")
	}
	return nil
}

type GateResult struct {
	Name       string           `json:"name"`
	Passed     bool             `json:"passed"`
	DurationMS int64            `json:"duration_ms"`
	Metrics    map[string]int64 `json:"metrics,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Passed        bool         `json:"passed"`
	StartedAt     time.Time    `json:"started_at"`
	DurationMS    int64        `json:"duration_ms"`
	XrayCommit    string       `json:"xray_commit"`
	XrayTag       string       `json:"xray_tag"`
	Gates         []GateResult `json:"gates"`
}

// RunProbes executes every required live gate through dial. It never includes
// endpoint credentials, URLs, or destinations in its JSON-safe error fields.
func RunProbes(ctx context.Context, dial DialContextFunc, options ProbeOptions) (Report, error) {
	started := time.Now().UTC()
	report := Report{
		SchemaVersion: 1,
		StartedAt:     started,
		XrayCommit:    PinnedCommit,
		XrayTag:       PinnedTag,
		Gates:         make([]GateResult, 0, 6),
	}
	if dial == nil {
		report.Gates = append(report.Gates, failedGate("prerequisites", "dialer_unavailable", 0))
		report.DurationMS = time.Since(started).Milliseconds()
		return report, errors.New("probe dialer is unavailable")
	}
	if err := options.Validate(); err != nil {
		report.Gates = append(report.Gates, failedGate("prerequisites", "invalid_probe_configuration", 0))
		report.DurationMS = time.Since(started).Milliseconds()
		return report, err
	}

	transport := &http.Transport{
		DialContext:           dial,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   options.ProbeTimeout,
		ResponseHeaderTimeout: options.ProbeTimeout,
	}
	if options.TLSConfig != nil {
		transport.TLSClientConfig = options.TLSConfig.Clone()
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: options.ProbeTimeout}

	report.Gates = append(report.Gates, executeGate(ctx, "dns_https", options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		return nil, probeHTTPS(gateContext, client, options.HTTPSURL)
	}))
	report.Gates = append(report.Gates, executeGate(ctx, "download", options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		read, err := probeDownload(gateContext, client, options.DownloadURL, options.DownloadMinBytes)
		return map[string]int64{"bytes": read}, err
	}))
	report.Gates = append(report.Gates, executeGate(ctx, "upload", options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		received, err := probeUpload(gateContext, client, options.UploadURL, options.UploadBytes)
		return map[string]int64{"bytes": received}, err
	}))
	report.Gates = append(report.Gates, executeGate(ctx, "long_lived_tcp", options.LongLived+options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		err := probeLongLived(gateContext, dial, options.TCPAddress, options.LongLived, options.ProbeTimeout)
		return map[string]int64{"hold_ms": options.LongLived.Milliseconds()}, err
	}))
	report.Gates = append(report.Gates, executeGate(ctx, "concurrency", options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		err := probeConcurrent(gateContext, dial, options.TCPAddress, options.Concurrency, options.ProbeTimeout)
		return map[string]int64{"connections": int64(options.Concurrency)}, err
	}))
	report.Gates = append(report.Gates, executeGate(ctx, "reconnect", time.Duration(options.Reconnects)*options.ProbeTimeout, func(gateContext context.Context) (map[string]int64, error) {
		err := probeReconnect(gateContext, dial, options.TCPAddress, options.Reconnects, options.ProbeTimeout)
		return map[string]int64{"connections": int64(options.Reconnects)}, err
	}))

	report.Passed = true
	for _, gate := range report.Gates {
		if !gate.Passed {
			report.Passed = false
			break
		}
	}
	report.DurationMS = time.Since(started).Milliseconds()
	if !report.Passed {
		return report, errors.New("one or more integration gates failed")
	}
	return report, nil
}

func executeGate(parent context.Context, name string, timeout time.Duration, probe func(context.Context) (map[string]int64, error)) GateResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	metrics, err := probe(ctx)
	duration := time.Since(started).Milliseconds()
	if err != nil {
		return failedGate(name, name+"_failed", duration)
	}
	return GateResult{Name: name, Passed: true, DurationMS: duration, Metrics: metrics}
}

func failedGate(name, code string, duration int64) GateResult {
	return GateResult{Name: name, Passed: false, DurationMS: duration, Error: code}
}

func probeHTTPS(ctx context.Context, client *http.Client, target string) (returnErr error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return errors.New("create HTTPS request")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("HTTPS request failed")
	}
	defer func() {
		returnErr = joinResponseCloseError(returnErr, response.Body, "close HTTPS response")
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("HTTPS status failed")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return errors.New("read HTTPS response")
	}
	return nil
}

func probeDownload(ctx context.Context, client *http.Client, target string, minimum int64) (read int64, returnErr error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, errors.New("create download request")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("download request failed")
	}
	defer func() {
		returnErr = joinResponseCloseError(returnErr, response.Body, "close download response")
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, errors.New("download status failed")
	}
	read, err = io.Copy(io.Discard, response.Body)
	if err != nil {
		return read, errors.New("download body failed")
	}
	if read < minimum {
		return read, errors.New("download was smaller than required")
	}
	return read, nil
}

func probeUpload(ctx context.Context, client *http.Client, target string, size int64) (receivedBytes int64, returnErr error) {
	if size <= 0 {
		return 0, errors.New("upload size is invalid")
	}
	upload := &uploadTrackingReader{
		reader: io.LimitReader(randomASCIIReader{}, size),
		hash:   sha256.New(),
	}
	body := io.NopCloser(upload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, body)
	if err != nil {
		return 0, errors.New("create upload request")
	}
	request.ContentLength = size
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("upload request failed")
	}
	defer func() {
		returnErr = joinResponseCloseError(returnErr, response.Body, "close upload response")
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return 0, errors.New("upload status failed")
	}
	const receiptOverheadLimit int64 = 1024 * 1024
	if size > int64(^uint64(0)>>1)-receiptOverheadLimit-1 {
		return 0, errors.New("upload receipt limit overflow")
	}
	receiptLimit := size + receiptOverheadLimit
	receipt, err := io.ReadAll(io.LimitReader(response.Body, receiptLimit+1))
	if err != nil {
		return 0, errors.New("read upload response")
	}
	if int64(len(receipt)) > receiptLimit {
		return 0, errors.New("upload receipt was too large")
	}

	received := receipt
	var echoed struct {
		Data *string `json:"data"`
	}
	if json.Unmarshal(receipt, &echoed) == nil && echoed.Data != nil {
		received = []byte(*echoed.Data)
	}
	uploaded, uploadDigest := upload.snapshot()
	if uploaded != size {
		return 0, errors.New("upload body was not fully sent")
	}
	if int64(len(received)) != size || !hashMatches(received, uploadDigest) {
		return 0, errors.New("upload receipt did not match payload")
	}
	return int64(len(received)), nil
}

func joinResponseCloseError(result error, body io.Closer, message string) error {
	if err := body.Close(); err != nil {
		return errors.Join(result, errors.New(message))
	}
	return result
}

type uploadTrackingReader struct {
	reader io.Reader
	mutex  sync.Mutex
	count  int64
	hash   hash.Hash
}

func (reader *uploadTrackingReader) Read(buffer []byte) (int, error) {
	read, err := reader.reader.Read(buffer)
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	reader.count += int64(read)
	if read > 0 {
		_, _ = reader.hash.Write(buffer[:read])
	}
	return read, err
}

func (reader *uploadTrackingReader) snapshot() (int64, []byte) {
	reader.mutex.Lock()
	defer reader.mutex.Unlock()
	return reader.count, reader.hash.Sum(nil)
}

type randomASCIIReader struct{}

const uploadAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"

func (randomASCIIReader) Read(buffer []byte) (int, error) {
	read, err := rand.Read(buffer)
	for index := 0; index < read; index++ {
		buffer[index] = uploadAlphabet[int(buffer[index])%len(uploadAlphabet)]
	}
	return read, err
}

func hashMatches(payload, expected []byte) bool {
	actual := sha256.Sum256(payload)
	return bytes.Equal(actual[:], expected)
}

func probeLongLived(ctx context.Context, dial DialContextFunc, address string, hold, timeout time.Duration) error {
	connection, err := dial(ctx, "tcp", address)
	if err != nil {
		return errors.New("long-lived connect failed")
	}
	defer func() { _ = connection.Close() }()
	if err := echoRoundTrip(ctx, connection, []byte("cf-vless-long-lived-before"), timeout); err != nil {
		return err
	}
	keepaliveInterval := 5 * time.Second
	if third := hold / 3; third < keepaliveInterval {
		keepaliveInterval = third
	}
	if keepaliveInterval <= 0 {
		return errors.New("long-lived keepalive interval is invalid")
	}
	timer := time.NewTimer(hold)
	defer timer.Stop()
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for keepalive := 0; ; keepalive++ {
		select {
		case <-ctx.Done():
			return errors.New("long-lived hold canceled")
		case <-timer.C:
			return echoRoundTrip(ctx, connection, []byte("cf-vless-long-lived-after"), timeout)
		case <-ticker.C:
			payload := []byte(fmt.Sprintf("cf-vless-long-lived-keepalive-%04d", keepalive))
			if err := echoRoundTrip(ctx, connection, payload, timeout); err != nil {
				return err
			}
		}
	}
}

func probeConcurrent(ctx context.Context, dial DialContextFunc, address string, count int, timeout time.Duration) error {
	start := make(chan struct{})
	errorsChannel := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			select {
			case <-ctx.Done():
				errorsChannel <- ctx.Err()
				return
			case <-start:
			}
			connection, err := dial(ctx, "tcp", address)
			if err != nil {
				errorsChannel <- err
				return
			}
			defer func() { _ = connection.Close() }()
			payload := []byte(fmt.Sprintf("cf-vless-concurrent-%04d", index))
			errorsChannel <- echoRoundTrip(ctx, connection, payload, timeout)
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			return errors.New("concurrent connection failed")
		}
	}
	return nil
}

func probeReconnect(ctx context.Context, dial DialContextFunc, address string, count int, timeout time.Duration) error {
	for index := 0; index < count; index++ {
		connection, err := dial(ctx, "tcp", address)
		if err != nil {
			return errors.New("reconnect failed")
		}
		payload := []byte(fmt.Sprintf("cf-vless-reconnect-%04d", index))
		err = echoRoundTrip(ctx, connection, payload, timeout)
		closeErr := connection.Close()
		if err != nil || closeErr != nil {
			return errors.New("reconnect round trip failed")
		}
	}
	return nil
}

func echoRoundTrip(ctx context.Context, connection net.Conn, payload []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return errors.New("set echo deadline")
	}
	// The controlled public echo endpoint is line-oriented. Preserve the
	// deterministic probe bytes and add one explicit delimiter, then verify the
	// complete framed payload byte-for-byte.
	framedPayload := make([]byte, len(payload)+1)
	copy(framedPayload, payload)
	framedPayload[len(payload)] = '\n'
	if err := writeAll(connection, framedPayload); err != nil {
		return errors.New("write echo payload")
	}
	response := make([]byte, len(framedPayload))
	if _, err := io.ReadFull(connection, response); err != nil {
		return errors.New("read echo payload")
	}
	if !bytes.Equal(response, framedPayload) {
		return errors.New("echo payload mismatch")
	}
	return nil
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func stringInt(value int) string {
	return strconv.Itoa(value)
}
