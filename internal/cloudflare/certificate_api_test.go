package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type certificateRoundTripFunc func(*http.Request) (*http.Response, error)

func (function certificateRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type recordingCertificatePackAPI struct {
	pages     map[int][]CertificatePack
	listPages []int
	deleted   []string
	listErr   error
	deleteErr error
}

func (api *recordingCertificatePackAPI) ListCertificatePacksPage(
	_ context.Context,
	zoneID string,
	page int,
	perPage int,
) ([]CertificatePack, error) {
	if zoneID != testZoneID || perPage != 50 {
		return nil, fmt.Errorf("unexpected certificate page request")
	}
	api.listPages = append(api.listPages, page)
	if api.listErr != nil {
		return nil, api.listErr
	}
	return append([]CertificatePack(nil), api.pages[page]...), nil
}

func (api *recordingCertificatePackAPI) DeleteCertificatePack(
	_ context.Context,
	zoneID string,
	packID string,
) error {
	if zoneID != testZoneID {
		return fmt.Errorf("unexpected certificate zone")
	}
	api.deleted = append(api.deleted, packID)
	return api.deleteErr
}

func newTestClientWithCertificateAPI(t *testing.T, runner Runner, api CertificatePackAPI) *Client {
	t.Helper()
	client, err := NewClient(runner, Options{
		ProjectDir:     testProject,
		AccountID:      testAccountID,
		CertificateAPI: api,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCertificateInventoryFallsBackOnlyForCFAuthorizationFailure(t *testing.T) {
	pack := CertificatePack{ID: testCertificatePack, Type: "advanced", Status: "active"}
	api := &recordingCertificatePackAPI{pages: map[int][]CertificatePack{1: {pack}}}
	runner := &scriptedRunner{t: t, steps: []runStep{{
		stderr:   "403 Forbidden [9109] Unauthorized to access requested resource",
		exitCode: 1,
		err:      errors.New("exit status 1"),
	}}}
	client := newTestClientWithCertificateAPI(t, runner, api)

	packs, operation, err := client.ListCertificatePacks(context.Background(), testZoneID)
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 1 || packs[0].ID != testCertificatePack {
		t.Fatalf("fallback packs = %#v", packs)
	}
	if operation.Provider != ProviderCloudflareAPI || operation.FallbackReason == "" ||
		strings.Contains(operation.Command, testZoneID) {
		t.Fatalf("fallback operation = %#v", operation)
	}
	if fmt.Sprintf("%#v", operation) == "" || len(api.listPages) != 1 || api.listPages[0] != 1 {
		t.Fatalf("fallback calls = %#v", api.listPages)
	}
	runner.assertDone(t)
}

func TestConfiguredGlobalKeyFallbackResolvesIdentityPrivately(t *testing.T) {
	const email = "owner@example.com"
	const key = "0123456789abcdef0123456789abcdef01234"
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stderr: "403 Forbidden [9109] Unauthorized to access requested resource", exitCode: 1, err: errors.New("exit status 1")},
		{stdout: `{"authenticated":true,"tokenValid":true,"email":"` + email + `"}`},
	}}
	httpClient := &http.Client{Transport: certificateRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != cloudflareAPIBaseURL+"/zones/"+testZoneID+"/ssl/certificate_packs?page=1&per_page=50&status=all" {
			t.Errorf("API URL = %s", request.URL.String())
		}
		if request.Header.Get("X-Auth-Email") != email || request.Header.Get("X-Auth-Key") != key {
			t.Error("Global API Key identity headers are missing")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"success":true,"result":[]}`)),
			Request:    request,
		}, nil
	})}
	client, err := NewClient(runner, Options{
		ProjectDir:            testProject,
		AccountID:             testAccountID,
		GlobalAPIKey:          []byte(key),
		CertificateHTTPClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	packs, operation, err := client.ListCertificatePacks(context.Background(), testZoneID)
	if err != nil || len(packs) != 0 || operation.Provider != ProviderCloudflareAPI {
		t.Fatalf("ListCertificatePacks = %#v, %#v, %v", packs, operation, err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call.printable, key) || strings.Contains(strings.Join(call.args, "\n"), key) ||
			strings.Contains(strings.Join(call.environment, "\n"), key) {
			t.Fatal("Global API Key entered a cf command")
		}
	}
	runner.assertDone(t)
}

func TestCertificateInventoryDoesNotMaskNonAuthorizationCFFailure(t *testing.T) {
	api := &recordingCertificatePackAPI{pages: map[int][]CertificatePack{}}
	runner := &scriptedRunner{t: t, steps: []runStep{{
		stderr:   "500 Internal Server Error",
		exitCode: 1,
		err:      errors.New("exit status 1"),
	}}}
	client := newTestClientWithCertificateAPI(t, runner, api)

	if _, _, err := client.ListCertificatePacks(context.Background(), testZoneID); err == nil {
		t.Fatal("non-authorization cf failure was masked")
	}
	if len(api.listPages) != 0 {
		t.Fatalf("fallback was called for a non-authorization error: %#v", api.listPages)
	}
	runner.assertDone(t)
}

func TestCertificateDeleteUsesCFDryRunAndAuthorizationFallbackForLiveDelete(t *testing.T) {
	api := &recordingCertificatePackAPI{pages: map[int][]CertificatePack{}}
	runner := &scriptedRunner{t: t, steps: []runStep{
		{stdout: `{"method":"DELETE"}`},
		{stderr: "403 Forbidden [9109] Unauthorized to access requested resource", exitCode: 1, err: errors.New("exit status 1")},
	}}
	client := newTestClientWithCertificateAPI(t, runner, api)

	dryOperation, err := client.deleteCertificatePack(context.Background(), testZoneID, testCertificatePack, true)
	if err != nil || dryOperation.Provider != ProviderCF || len(api.deleted) != 0 {
		t.Fatalf("dry-run delete = %#v, %v, API deletes %#v", dryOperation, err, api.deleted)
	}
	liveOperation, err := client.deleteCertificatePack(context.Background(), testZoneID, testCertificatePack, false)
	if err != nil {
		t.Fatal(err)
	}
	if liveOperation.Provider != ProviderCloudflareAPI || liveOperation.FallbackReason == "" ||
		len(api.deleted) != 1 || api.deleted[0] != testCertificatePack {
		t.Fatalf("live fallback = %#v / deletes %#v", liveOperation, api.deleted)
	}
	runner.assertDone(t)
}

func TestGlobalKeyCertificateAPISendsCredentialsOnlyAsHeaders(t *testing.T) {
	const email = "owner@example.com"
	const key = "0123456789abcdef0123456789abcdef01234"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("X-Auth-Email") != email || request.Header.Get("X-Auth-Key") != key {
			t.Error("Global API Key headers are missing")
		}
		if strings.Contains(request.URL.String(), key) {
			t.Error("Global API Key entered the request URL")
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			if request.URL.Path != "/client/v4/zones/"+testZoneID+"/ssl/certificate_packs" ||
				request.URL.Query().Get("status") != "all" || request.URL.Query().Get("page") != "1" ||
				request.URL.Query().Get("per_page") != "50" {
				t.Errorf("list request = %s %s", request.Method, request.URL.String())
			}
			_, _ = io.WriteString(writer, `{"success":true,"result":[{"id":"`+testCertificatePack+`","type":"advanced","status":"active","hosts":["edge.example.com"],"certificates":[]}]}`)
		case http.MethodDelete:
			if request.URL.Path != "/client/v4/zones/"+testZoneID+"/ssl/certificate_packs/"+testCertificatePack {
				t.Errorf("delete request = %s %s", request.Method, request.URL.String())
			}
			body, err := io.ReadAll(request.Body)
			if err != nil || strings.TrimSpace(string(body)) != "{}" {
				t.Errorf("delete body = %q, %v", body, err)
			}
			_, _ = io.WriteString(writer, `{"success":true,"result":{"id":"`+testCertificatePack+`"}}`)
		default:
			t.Errorf("unexpected method %s", request.Method)
		}
	}))
	defer server.Close()

	api, err := newGlobalKeyCertificateAPI(server.URL+"/client/v4", server.Client(), email, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	packs, err := api.ListCertificatePacksPage(context.Background(), testZoneID, 1, 50)
	if err != nil || len(packs) != 1 || packs[0].ID != testCertificatePack {
		t.Fatalf("ListCertificatePacksPage = %#v, %v", packs, err)
	}
	if err := api.DeleteCertificatePack(context.Background(), testZoneID, testCertificatePack); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestGlobalKeyCertificateAPIErrorsNeverContainCredential(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef01234"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, `{"success":false,"errors":[{"code":9109,"message":"echo `+key+`"}]}`)
	}))
	defer server.Close()

	api, err := newGlobalKeyCertificateAPI(server.URL, server.Client(), "owner@example.com", []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.ListCertificatePacksPage(context.Background(), testZoneID, 1, 50)
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("credential-bearing API error = %v", err)
	}
}

func TestGlobalKeyCertificateAPIRejectsRedirects(t *testing.T) {
	followed := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			followed = true
			writer.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	api, err := newGlobalKeyCertificateAPI(server.URL, server.Client(), "owner@example.com", []byte("0123456789abcdef0123456789abcdef01234"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ListCertificatePacksPage(context.Background(), testZoneID, 1, 50); err == nil {
		t.Fatal("redirected credential-bearing request succeeded")
	}
	if followed {
		t.Fatal("credential-bearing redirect was followed")
	}
}

func TestGlobalAPIKeyFormatAcceptsCurrentAndPre2026Keys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "configured legacy key", key: "0123456789abcdef0123456789abcdef01234", want: true},
		{name: "longest pre-2026 key", key: strings.Repeat("a", 45), want: true},
		{name: "current scannable key", key: "cfk_" + strings.Repeat("A", 40) + strings.Repeat("0", 8), want: true},
		{name: "uppercase legacy rejected", key: strings.Repeat("A", 37)},
		{name: "API token rejected", key: "cfut_" + strings.Repeat("A", 40) + strings.Repeat("0", 8)},
		{name: "short key rejected", key: strings.Repeat("a", 36)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := globalAPIKeyPattern.MatchString(test.key); got != test.want {
				t.Fatalf("format accepted = %v, want %v", got, test.want)
			}
		})
	}
}
