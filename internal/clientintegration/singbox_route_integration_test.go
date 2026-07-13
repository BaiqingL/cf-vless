package clientintegration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiqingL/cf-vless/internal/config"
	"github.com/BaiqingL/cf-vless/internal/xray"
)

const (
	liveSingBoxPolicyEnvironment = "CF_VLESS_TEST_LIVE_SING_BOX_POLICY"
	liveDeploymentEnvironment    = "CF_VLESS_DEPLOYMENT"
)

// TestLiveSingBoxChinaDirectForeignProxyPolicy is intentionally opt-in: it
// uses the owner-only deployment record and two stable public IP probes. The
// test retains client logs only in memory and reports no deployment values.
func TestLiveSingBoxChinaDirectForeignProxyPolicy(t *testing.T) {
	if os.Getenv(liveSingBoxPolicyEnvironment) != "1" {
		t.Skip("live sing-box policy test is disabled")
	}
	deploymentPath := os.Getenv(liveDeploymentEnvironment)
	if deploymentPath == "" {
		t.Fatal("live deployment path is required")
	}
	deployment, err := config.Load(deploymentPath)
	if err != nil {
		t.Fatal("load live deployment")
	}
	binary, err := LocateBinary(SingBox, os.Getenv("SING_BOX_BIN"))
	if err != nil {
		t.Fatal("locate pinned sing-box")
	}
	port, err := xray.ReserveLoopbackPort()
	if err != nil {
		t.Fatal("reserve sing-box mixed port")
	}
	specification, err := Prepare(SingBox, binary, filepath.Join(t.TempDir(), "sing-box"), deployment, port)
	if err != nil {
		t.Fatalf("prepare sing-box policy probe: %v", err)
	}
	enableSingBoxDebugLogging(t, specification.ConfigPath)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var output bytes.Buffer
	runner := Runner{Output: &output, StartupTimeout: 60 * time.Second, StopTimeout: 10 * time.Second}
	process, err := runner.Start(ctx, specification)
	if err != nil {
		t.Fatal("start sing-box policy probe")
	}
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = process.Stop(stopContext)
	})

	dialer := xray.SOCKS5Dialer{ProxyAddress: specification.SOCKSAddress, Timeout: 30 * time.Second}
	chinaConnection, err := dialer.DialContext(ctx, "tcp", "223.5.5.5:443")
	if err != nil {
		t.Fatal("sing-box policy probe could not connect to the China target")
	}
	if err := verifyTLSHandshake(ctx, chinaConnection, "dns.alidns.com"); err != nil {
		t.Fatal("China direct route did not complete a verified TLS handshake")
	}

	foreignConnection, err := dialer.DialContext(ctx, "tcp", "8.8.8.8:443")
	if err != nil {
		t.Fatal("sing-box policy probe could not connect to the foreign target")
	}
	if err := verifyTLSHandshake(ctx, foreignConnection, "dns.google"); err != nil {
		t.Fatal("foreign proxy route did not complete a verified TLS handshake")
	}
	time.Sleep(250 * time.Millisecond)
	stopContext, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := process.Stop(stopContext); err != nil {
		t.Fatal("stop sing-box policy probe")
	}
	stopped = true

	logs := output.String()
	direct := hasSingBoxRouteEvidence(logs, "outbound/direct[direct]", "223.5.5.5:443")
	proxy := hasSingBoxRouteEvidence(logs, "outbound/vless[proxy]", "8.8.8.8:443")
	if !direct || !proxy {
		t.Fatalf("sing-box route evidence missing: china_direct=%t foreign_proxy=%t", direct, proxy)
	}
}

func verifyTLSHandshake(ctx context.Context, connection net.Conn, serverName string) error {
	tlsConnection := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	})
	defer tlsConnection.Close()
	return tlsConnection.HandshakeContext(ctx)
}

func enableSingBoxDebugLogging(t *testing.T, path string) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read private sing-box test config")
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal("decode private sing-box test config")
	}
	document["log"].(map[string]any)["level"] = "debug"
	encoded, err = json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal("encode private sing-box test config")
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal("write private sing-box test config")
	}
}

func hasSingBoxRouteEvidence(logs, outbound, target string) bool {
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, outbound) && strings.Contains(line, target) {
			return true
		}
	}
	return false
}
