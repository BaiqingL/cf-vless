package cloudflare

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	publicHTTPSReadinessTimeout = 15 * time.Second
	publicHTTPSReadinessBody    = "Not Found\n"
)

// ProbePublicHTTPSReadiness verifies that the exact HTTPS root for hostname is
// served by the protected Worker. A ready Worker returns its deliberately
// generic root response: HTTP 404 with the exact body "Not Found\n".
//
// The probe verifies TLS with the system trust store, follows no redirects,
// sends no credentials, bounds both elapsed time and response bytes, and keeps
// endpoint details out of returned errors.
func ProbePublicHTTPSReadiness(ctx context.Context, hostname string) error {
	return probePublicHTTPSReadinessWithClient(
		ctx,
		hostname,
		newPublicHTTPSReadinessClient(),
		publicHTTPSReadinessTimeout,
	)
}

func newPublicHTTPSReadinessClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   publicHTTPSReadinessTimeout,
	}
}

// probePublicHTTPSReadinessWithClient is the transport seam used by package
// tests. Production callers use ProbePublicHTTPSReadiness, whose client always
// performs normal certificate and hostname verification.
func probePublicHTTPSReadinessWithClient(
	ctx context.Context,
	hostname string,
	httpClient *http.Client,
	timeout time.Duration,
) error {
	if ctx == nil {
		return errors.New("public HTTPS readiness context is required")
	}
	normalizedHostname, err := normalizeHostname("public HTTPS hostname", hostname)
	if err != nil {
		return err
	}
	if timeout <= 0 || timeout > publicHTTPSReadinessTimeout {
		timeout = publicHTTPSReadinessTimeout
	}
	if httpClient == nil {
		httpClient = newPublicHTTPSReadinessClient()
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > timeout {
		clientCopy.Timeout = timeout
	}

	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint := url.URL{Scheme: "https", Host: normalizedHostname, Path: "/"}
	request, err := http.NewRequestWithContext(probeContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return errors.New("construct public HTTPS readiness request")
	}
	response, err := clientCopy.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if probeContext.Err() != nil {
			return probeContext.Err()
		}
		return errors.New("public HTTPS readiness request failed")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("public HTTPS endpoint is not ready (HTTP %d)", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, int64(len(publicHTTPSReadinessBody)+1)))
	if err != nil {
		return errors.New("read public HTTPS readiness response")
	}
	if !bytes.Equal(body, []byte(publicHTTPSReadinessBody)) {
		return errors.New("public HTTPS endpoint returned an unexpected generic response")
	}
	return nil
}
