package xray

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type closeErrorBody struct {
	io.Reader
}

func (closeErrorBody) Close() error {
	return errors.New("sensitive response close detail")
}

func TestEchoRoundTripSupportsLineDelimitedPublicEchoService(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		line, err := bufio.NewReader(server).ReadBytes('\n')
		if err == nil {
			_, _ = server.Write(line)
		}
	}()

	if err := echoRoundTrip(context.Background(), client, []byte("line-oriented-echo"), 250*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestLongLivedProbeKeepsAnOtherwiseIdleConnectionActive(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		reader := bufio.NewReader(server)
		for {
			_ = server.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			if _, err := server.Write(line); err != nil {
				return
			}
		}
	}()
	dialed := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		if dialed {
			t.Fatal("long-lived probe opened more than one connection")
		}
		dialed = true
		return client, nil
	}

	if err := probeLongLived(context.Background(), dial, "echo.example:443", 180*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-done
}

func TestHTTPDownloadAndUploadProbes(t *testing.T) {
	t.Parallel()

	const downloadBytes = 2 * 1024 * 1024
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/download":
			writer.Header().Set("Content-Length", stringInt(downloadBytes))
			_, _ = io.CopyN(writer, zeroReader{}, downloadBytes)
		case "/upload":
			payload, err := io.ReadAll(request.Body)
			if err != nil || len(payload) != 1024*1024 {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"data": string(payload)})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := server.Client()
	bytesRead, err := probeDownload(context.Background(), client, server.URL+"/download", downloadBytes)
	if err != nil || bytesRead != downloadBytes {
		t.Fatalf("download bytes=%d err=%v", bytesRead, err)
	}
	uploaded, err := probeUpload(context.Background(), client, server.URL+"/upload", 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if uploaded != 1024*1024 {
		t.Fatalf("uploaded bytes=%d", uploaded)
	}
}

func TestHTTPProbesSurfaceSanitizedResponseCloseFailures(t *testing.T) {
	t.Parallel()

	newClient := func(body []byte) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Body != nil {
				uploaded, err := io.ReadAll(request.Body)
				if err != nil {
					return nil, err
				}
				body = uploaded
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       closeErrorBody{Reader: bytes.NewReader(body)},
				Header:     make(http.Header),
				Request:    request,
			}, nil
		})}
	}

	if err := probeHTTPS(context.Background(), newClient([]byte("ok")), "https://probe.example/"); err == nil || !strings.Contains(err.Error(), "close HTTPS response") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("HTTPS close error = %v", err)
	}
	downloaded, err := probeDownload(context.Background(), newClient(make([]byte, MinimumDownloadBytes)), "https://probe.example/download", MinimumDownloadBytes)
	if downloaded != MinimumDownloadBytes || err == nil || !strings.Contains(err.Error(), "close download response") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("downloaded = %d, close error = %v", downloaded, err)
	}
	uploaded, err := probeUpload(context.Background(), newClient(nil), "https://probe.example/upload", MinimumUploadBytes)
	if uploaded != MinimumUploadBytes || err == nil || !strings.Contains(err.Error(), "close upload response") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("uploaded = %d, close error = %v", uploaded, err)
	}
}

func TestUploadProbeRejectsUnverifiableSuccessResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if _, err := probeUpload(context.Background(), server.Client(), server.URL, MinimumUploadBytes); err == nil {
		t.Fatal("upload probe accepted a 2xx response without proof of receipt")
	}
}

func TestUploadProbeAcceptsRawPayloadReceipt(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.Copy(writer, request.Body)
	}))
	defer server.Close()

	received, err := probeUpload(context.Background(), server.Client(), server.URL, MinimumUploadBytes)
	if err != nil {
		t.Fatal(err)
	}
	if received != MinimumUploadBytes {
		t.Fatalf("received bytes=%d", received)
	}
}

func TestUploadProbeRejectsMismatchedJSONReceipt(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"data": "not-the-upload"})
	}))
	defer server.Close()

	if _, err := probeUpload(context.Background(), server.Client(), server.URL, MinimumUploadBytes); err == nil {
		t.Fatal("upload probe accepted a mismatched receipt")
	}
}

func TestRunProbesReportsAllLiveGates(t *testing.T) {
	t.Parallel()

	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			_, _ = writer.Write([]byte("ok"))
		case "/download":
			_, _ = io.CopyN(writer, zeroReader{}, MinimumDownloadBytes)
		case "/upload":
			payload, err := io.ReadAll(request.Body)
			if err != nil || int64(len(payload)) != MinimumUploadBytes {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"data": string(payload)})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer httpServer.Close()

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		for {
			connection, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()

	dial := func(ctx context.Context, _, address string) (net.Conn, error) {
		target := httpServer.Listener.Addr().String()
		if address == "echo.example:443" {
			target = echoListener.Addr().String()
		}
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", target)
	}
	options := ProbeOptions{
		HTTPSURL:         "https://probe.example/",
		DownloadURL:      "https://probe.example/download",
		UploadURL:        "https://probe.example/upload",
		DownloadMinBytes: MinimumDownloadBytes,
		UploadBytes:      MinimumUploadBytes,
		TCPAddress:       "echo.example:443",
		LongLived:        5 * time.Millisecond,
		Concurrency:      2,
		Reconnects:       2,
		ProbeTimeout:     5 * time.Second,
		// Test server certificates are private; the production command never
		// exposes this override and uses normal system verification.
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	}
	report, err := RunProbes(context.Background(), dial, options)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed || len(report.Gates) != 6 {
		t.Fatalf("report = %+v", report)
	}
	for _, gate := range report.Gates {
		if !gate.Passed || gate.Error != "" {
			t.Fatalf("gate = %+v", gate)
		}
		if gate.Name == "upload" && gate.Metrics["bytes"] != MinimumUploadBytes {
			t.Fatalf("upload metrics = %+v", gate.Metrics)
		}
	}
}

func TestTCPConcurrencyReconnectAndLongLivedProbes(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	dial := (&net.Dialer{Timeout: time.Second}).DialContext
	if err := probeLongLived(context.Background(), dial, listener.Addr().String(), 5*time.Millisecond, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := probeConcurrent(context.Background(), dial, listener.Addr().String(), 4, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := probeReconnect(context.Background(), dial, listener.Addr().String(), 3, time.Second); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	workers.Wait()
}

func TestProbeOptionsRequireEveryRealGate(t *testing.T) {
	t.Parallel()

	options := ProbeOptions{}
	if err := options.Validate(); err == nil {
		t.Fatal("empty options were accepted")
	}
	options = ProbeOptions{
		HTTPSURL:         "https://probe.example/",
		DownloadURL:      "https://probe.example/download",
		UploadURL:        "https://probe.example/upload",
		DownloadMinBytes: MinimumDownloadBytes,
		UploadBytes:      MinimumUploadBytes,
		TCPAddress:       "echo.example:443",
		LongLived:        time.Second,
		Concurrency:      2,
		Reconnects:       2,
		ProbeTimeout:     time.Second,
	}
	if err := options.Validate(); err != nil {
		t.Fatal(err)
	}
}
