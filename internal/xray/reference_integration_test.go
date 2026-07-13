package xray

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestLocalPinnedXrayVLESSWebSocketReferencePair is the Stage-1 protocol
// reference gate. It is intentionally opt-in because it builds two real Xray
// processes. It also sanitizes and checks a captured request from the real
// pinned client. All listeners and destinations are loopback-only; it performs
// no Cloudflare API calls and does not contact a deployed Worker.
func TestLocalPinnedXrayVLESSWebSocketReferencePair(t *testing.T) {
	if os.Getenv("CF_VLESS_TEST_LOCAL_REFERENCE") != "1" {
		t.Skip("set CF_VLESS_TEST_LOCAL_REFERENCE=1 to run the local Xray reference pair")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "xray")
	build, err := (Builder{
		RepoDir:    filepath.Join(repositoryRoot, "third_party", "xray-core"),
		OutputPath: binaryPath,
	}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if build.Commit != PinnedCommit || build.Tag != PinnedTag {
		t.Fatalf("unexpected Xray pin %s/%s", build.Commit, build.Tag)
	}

	httpServer := newLocalReferenceHTTPServer(t)
	defer httpServer.Close()
	echoListener := newLocalReferenceEchoServer(t)
	defer echoListener.Close()
	ipv6EchoListener, ipv6Unavailable, err := newOptionalLocalReferenceIPv6EchoServer()
	if err != nil {
		t.Fatal("start IPv6 loopback reference destination")
	}
	if ipv6EchoListener != nil {
		defer ipv6EchoListener.Close()
	}

	serverPort, err := ReserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	socksPort, err := ReserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	for socksPort == serverPort {
		socksPort, err = ReserveLoopbackPort()
		if err != nil {
			t.Fatal(err)
		}
	}
	serverAddress := net.JoinHostPort("127.0.0.1", stringPort(serverPort))
	var captureProxy *loopbackCaptureProxy
	for {
		captureProxy, err = newLoopbackCaptureProxy(serverAddress)
		if err != nil {
			t.Fatal(err)
		}
		if captureProxy.Port() != serverPort && captureProxy.Port() != socksPort {
			break
		}
		if err := captureProxy.Close(); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := captureProxy.Close(); err != nil {
			t.Errorf("close local capture proxy: %v", err)
		}
	}()
	options := LocalReferenceOptions{
		// This fixed synthetic credential is not usable outside the temporary,
		// loopback-only reference pair.
		UUID:             "27848739-7e62-4138-9fd3-098a63964b6b",
		WebSocketPath:    "/local-reference-01",
		ServerPort:       serverPort,
		ClientTargetPort: captureProxy.Port(),
		SOCKSPort:        socksPort,
	}
	paths, err := WriteLocalReferenceConfigs(filepath.Join(t.TempDir(), "configs"), options)
	if err != nil {
		t.Fatal(err)
	}
	runner := ClientRunner{StartupTimeout: 10 * time.Second, StopTimeout: 5 * time.Second}
	serverProcess, err := runner.Start(ctx, binaryPath, paths.ServerPath, serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer stopReferenceProcess(t, serverProcess)
	socksAddress := net.JoinHostPort("127.0.0.1", stringPort(socksPort))
	clientProcess, err := runner.Start(ctx, binaryPath, paths.ClientPath, socksAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer stopReferenceProcess(t, clientProcess)

	dialer := SOCKS5Dialer{ProxyAddress: socksAddress, Timeout: 10 * time.Second}

	// The transparent proxy observes the pinned, unmodified client's real
	// masked WebSocket traffic for every VLESS address type. Each raw header is
	// held only in memory, sanitized before comparison, and never included in a
	// failure message.
	t.Run("IPv4 header", func(t *testing.T) {
		verifyCapturedReferenceRequest(t, ctx, dialer, captureProxy, echoListener.Addr().String(), "ipv4", true)
	})
	t.Run("domain header", func(t *testing.T) {
		fixture, _ := canonicalVLESSCase(t, "domain")
		_, port, splitErr := net.SplitHostPort(echoListener.Addr().String())
		if splitErr != nil {
			t.Fatal("inspect loopback reference destination")
		}
		verifyCapturedReferenceRequest(t, ctx, dialer, captureProxy, net.JoinHostPort(fixture.Host, port), "domain", true)
	})
	t.Run("IPv6 header", func(t *testing.T) {
		targetPort := uint16(echoListener.Addr().(*net.TCPAddr).Port)
		requireRoundTrip := !ipv6Unavailable
		if ipv6EchoListener != nil {
			targetPort = uint16(ipv6EchoListener.Addr().(*net.TCPAddr).Port)
		}
		verifyCapturedReferenceRequest(t, ctx, dialer, captureProxy, net.JoinHostPort("::1", stringPort(targetPort)), "ipv6", requireRoundTrip)
		if ipv6Unavailable {
			// The real pinned client header was still exercised and verified
			// above; only the platform-dependent echo leg is skipped.
			t.Skip("IPv6 loopback is unavailable; real VLESS header capture passed")
		}
	})

	transport := &http.Transport{DialContext: dialer.DialContext, DisableCompression: true}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	verifyReferenceDownload(t, httpClient, httpServer.URL+"/download")
	verifyReferenceUpload(t, httpClient, httpServer.URL+"/upload")
}

func verifyCapturedReferenceRequest(t *testing.T, ctx context.Context, dialer SOCKS5Dialer, captureProxy *loopbackCaptureProxy, target, fixtureName string, requireRoundTrip bool) {
	t.Helper()
	connection, dialErr := dialer.DialContext(ctx, "tcp", target)
	if requireRoundTrip {
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if err := echoRoundTrip(ctx, connection, []byte("local-xray-reference-echo"), 10*time.Second); err != nil {
			connection.Close()
			t.Fatal(err)
		}
	}
	if connection != nil {
		if err := connection.Close(); err != nil && requireRoundTrip {
			t.Fatal("close local Xray reference connection")
		}
	}

	captureContext, cancelCapture := context.WithTimeout(ctx, 10*time.Second)
	capturedHeader, err := captureProxy.Await(captureContext)
	cancelCapture()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(capturedHeader)
	_, canonicalHeader := canonicalVLESSCase(t, fixtureName)
	sanitizedHeader, err := sanitizeCapturedVLESSHeader(capturedHeader, canonicalHeader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sanitizedHeader, canonicalHeader) {
		t.Fatal("sanitized pinned-Xray capture differs from canonical VLESS fixture")
	}
}

func newLocalReferenceHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()
	const downloadBytes = 256 * 1024
	const uploadBytes = 128 * 1024
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/download":
			writer.Header().Set("Content-Length", stringInt(downloadBytes))
			_, _ = io.CopyN(writer, zeroReader{}, downloadBytes)
		case "/upload":
			read, err := io.Copy(io.Discard, request.Body)
			if err != nil || read != uploadBytes {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newLocalReferenceEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveLocalReferenceEcho(listener)
	return listener
}

func newOptionalLocalReferenceIPv6EchoServer() (net.Listener, bool, error) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		if isIPv6LoopbackUnavailable(err) {
			return nil, true, nil
		}
		return nil, false, err
	}
	serveLocalReferenceEcho(listener)
	return listener, false, nil
}

func isIPv6LoopbackUnavailable(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EADDRNOTAVAIL)
}

func TestIPv6LoopbackSkipRecognizesOnlyPlatformAbsence(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "address family", err: syscall.EAFNOSUPPORT, want: true},
		{name: "protocol", err: syscall.EPROTONOSUPPORT, want: true},
		{name: "address unavailable", err: syscall.EADDRNOTAVAIL, want: true},
		{name: "wrapped absence", err: &net.OpError{Op: "listen", Net: "tcp6", Err: syscall.EAFNOSUPPORT}, want: true},
		{name: "permission", err: syscall.EACCES, want: false},
		{name: "generic", err: errors.New("unexpected listen failure"), want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			if got := isIPv6LoopbackUnavailable(testCase.err); got != testCase.want {
				t.Fatalf("IPv6 platform-absence classification = %t, want %t", got, testCase.want)
			}
		})
	}
}

func serveLocalReferenceEcho(listener net.Listener) {
	go func() {
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
}

func verifyReferenceDownload(t *testing.T, client *http.Client, target string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d", response.StatusCode)
	}
	read, err := io.Copy(io.Discard, response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if read != 256*1024 {
		t.Fatalf("download bytes = %d", read)
	}
}

func verifyReferenceUpload(t *testing.T, client *http.Client, target string) {
	t.Helper()
	payload := bytes.Repeat([]byte{0x5a}, 128*1024)
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("upload status = %d", response.StatusCode)
	}
}

func stopReferenceProcess(t *testing.T, process *ClientProcess) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := process.Stop(ctx); err != nil {
		t.Errorf("stop local Xray process: %v", err)
	}
}
