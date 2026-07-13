package cloudflare

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type readinessRoundTripFunc func(*http.Request) (*http.Response, error)

func (function readinessRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func readinessResponse(request *http.Request, status int, body io.Reader) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(body),
		Request:    request,
	}
}

func TestProbePublicHTTPSReadinessRequiresExactGeneric404(t *testing.T) {
	var observed *http.Request
	client := &http.Client{Transport: readinessRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		observed = request
		return readinessResponse(request, http.StatusNotFound, strings.NewReader("Not Found\n")), nil
	})}

	err := probePublicHTTPSReadinessWithClient(
		context.Background(),
		"Edge.Example.com.",
		client,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if observed == nil {
		t.Fatal("readiness request was not issued")
	}
	if observed.Method != http.MethodGet || observed.URL.String() != "https://edge.example.com/" {
		t.Fatalf("request = %s %s", observed.Method, observed.URL.Redacted())
	}
	if observed.URL.RawQuery != "" || observed.URL.User != nil || observed.Host != "edge.example.com" {
		t.Fatalf("request URL or Host override is not exact: %#v / %q", observed.URL, observed.Host)
	}
	for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Auth-Key"} {
		if observed.Header.Get(header) != "" {
			t.Fatalf("readiness request sent %s", header)
		}
	}
}

func TestProbePublicHTTPSReadinessRejectsStatusOrBodyMismatchWithoutEchoingBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "wrong status", status: http.StatusOK, body: "token=body-secret"},
		{name: "wrong body", status: http.StatusNotFound, body: "token=body-secret"},
		{name: "missing newline", status: http.StatusNotFound, body: "Not Found"},
		{name: "extra byte", status: http.StatusNotFound, body: "Not Found\nX"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: readinessRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return readinessResponse(request, test.status, strings.NewReader(test.body)), nil
			})}
			err := probePublicHTTPSReadinessWithClient(context.Background(), "edge.example.com", client, time.Second)
			if err == nil {
				t.Fatal("mismatched readiness response was accepted")
			}
			if strings.Contains(err.Error(), test.body) || strings.Contains(err.Error(), "body-secret") {
				t.Fatalf("readiness error echoed response body: %v", err)
			}
		})
	}
}

func TestProbePublicHTTPSReadinessDoesNotFollowRedirects(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: readinessRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		response := readinessResponse(request, http.StatusFound, strings.NewReader("redirect-secret"))
		response.Header.Set("Location", "https://attacker.example/?token=redirect-secret")
		return response, nil
	})}

	err := probePublicHTTPSReadinessWithClient(context.Background(), "edge.example.com", client, time.Second)
	if err == nil {
		t.Fatal("redirect was accepted")
	}
	if requests != 1 {
		t.Fatalf("readiness probe made %d requests after a redirect", requests)
	}
	if strings.Contains(err.Error(), "attacker.example") || strings.Contains(err.Error(), "redirect-secret") {
		t.Fatalf("redirect error leaked the target: %v", err)
	}
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.read += count
	return count, err
}

func TestProbePublicHTTPSReadinessBoundsResponseBody(t *testing.T) {
	body := &countingReader{reader: strings.NewReader(strings.Repeat("x", 1<<20))}
	client := &http.Client{Transport: readinessRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return readinessResponse(request, http.StatusNotFound, body), nil
	})}

	if err := probePublicHTTPSReadinessWithClient(context.Background(), "edge.example.com", client, time.Second); err == nil {
		t.Fatal("oversized response was accepted")
	}
	if body.read > len(publicHTTPSReadinessBody)+1 {
		t.Fatalf("readiness probe read %d body bytes", body.read)
	}
}

func TestProbePublicHTTPSReadinessHonorsCancellationAndTimeout(t *testing.T) {
	client := &http.Client{Transport: readinessRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probePublicHTTPSReadinessWithClient(canceled, "edge.example.com", client, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe error = %v", err)
	}

	started := time.Now()
	err := probePublicHTTPSReadinessWithClient(context.Background(), "edge.example.com", client, 20*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out probe error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("readiness timeout took %s", elapsed)
	}
}

func TestProbePublicHTTPSReadinessSanitizesInputAndTransportErrors(t *testing.T) {
	const sensitive = "query-credential"
	client := &http.Client{Transport: readinessRoundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New(`dial https://edge.example.com/?token=` + sensitive)
	})}

	err := probePublicHTTPSReadinessWithClient(context.Background(), "edge.example.com", client, time.Second)
	if err == nil {
		t.Fatal("transport failure was accepted")
	}
	for _, forbidden := range []string{"edge.example.com", sensitive, "https://", "token="} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("transport error leaked %q: %v", forbidden, err)
		}
	}

	invalid := "user:" + sensitive + "@edge.example.com/?token=" + sensitive
	err = probePublicHTTPSReadinessWithClient(context.Background(), invalid, client, time.Second)
	if err == nil {
		t.Fatal("invalid hostname was accepted")
	}
	if strings.Contains(err.Error(), sensitive) || strings.Contains(err.Error(), invalid) {
		t.Fatalf("validation error leaked hostname input: %v", err)
	}
}

func TestPublicHTTPSReadinessClientVerifiesTLS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNotFound)
		_, _ = response.Write([]byte(publicHTTPSReadinessBody))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := newPublicHTTPSReadinessClient().Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("readiness client trusted an untrusted TLS certificate")
	}
}
