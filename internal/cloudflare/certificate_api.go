package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cloudflareAPIBaseURL           = "https://api.cloudflare.com/client/v4"
	certificateAPIResponseLimit    = 2 << 20
	certificateAPITimeout          = 30 * time.Second
	certificateAPIFallbackReason   = "cf 0.2.0 OAuth was denied certificate-pack access with Cloudflare 9109/403; used the configured Global API Key only for this certificate-pack operation"
	certificateAPIListDiagnostic   = "GET /zones/[REDACTED]/ssl/certificate_packs"
	certificateAPIDeleteDiagnostic = "DELETE /zones/[REDACTED]/ssl/certificate_packs/[REDACTED]"
)

var globalAPIKeyPattern = regexp.MustCompile(`^([0-9a-f]{37,45}|cfk_[A-Za-z0-9]{40}[0-9a-fA-F]{8})$`)

type globalKeyCertificateAPI struct {
	baseURL    *url.URL
	httpClient *http.Client
	email      string
	apiKey     []byte
}

type certificateAPIEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code int `json:"code"`
	} `json:"errors"`
}

func newGlobalKeyCertificateAPI(
	baseURL string,
	httpClient *http.Client,
	email string,
	apiKey []byte,
) (CertificatePackAPI, error) {
	parsedEmail, err := mail.ParseAddress(email)
	if err != nil || parsedEmail.Address != email || strings.TrimSpace(email) != email {
		return nil, errors.New("Cloudflare account email is not a plain valid email address")
	}
	if !globalAPIKeyPattern.Match(apiKey) {
		return nil, errors.New("Cloudflare Global API Key does not match a supported Cloudflare key format")
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "https" && parsedURL.Scheme != "http") ||
		parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("Cloudflare certificate API base URL is invalid")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clientCopy.Timeout <= 0 || clientCopy.Timeout > certificateAPITimeout {
		clientCopy.Timeout = certificateAPITimeout
	}
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")
	return &globalKeyCertificateAPI{
		baseURL:    parsedURL,
		httpClient: &clientCopy,
		email:      email,
		apiKey:     append([]byte(nil), apiKey...),
	}, nil
}

func (api *globalKeyCertificateAPI) ListCertificatePacksPage(
	ctx context.Context,
	zoneID string,
	page int,
	perPage int,
) ([]CertificatePack, error) {
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return nil, err
	}
	if page < 1 || page > 100 {
		return nil, errors.New("certificate pack page is outside the safe bound")
	}
	if perPage != 50 {
		return nil, errors.New("certificate pack page size must be 50")
	}
	endpoint := api.endpoint("/zones/" + zoneID + "/ssl/certificate_packs")
	query := endpoint.Query()
	query.Set("status", "all")
	query.Set("page", strconv.Itoa(page))
	query.Set("per_page", strconv.Itoa(perPage))
	endpoint.RawQuery = query.Encode()
	envelope, err := api.request(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	packs, err := parseCertificatePacks(string(envelope.Result))
	if err != nil {
		return nil, api.sanitizeError("decode certificate inventory", err)
	}
	return packs, nil
}

func (api *globalKeyCertificateAPI) DeleteCertificatePack(
	ctx context.Context,
	zoneID string,
	packID string,
) error {
	if err := validateCloudflareID("zone ID", zoneID); err != nil {
		return err
	}
	if err := validateCertificatePackID("certificate pack ID", packID); err != nil {
		return err
	}
	endpoint := api.endpoint("/zones/" + zoneID + "/ssl/certificate_packs/" + packID)
	envelope, err := api.request(ctx, http.MethodDelete, endpoint, []byte("{}"))
	if err != nil {
		return err
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return api.sanitizeError("decode certificate deletion", err)
	}
	if result.ID != packID {
		return errors.New("Cloudflare certificate API returned a different deleted certificate pack")
	}
	return nil
}

func (api *globalKeyCertificateAPI) endpoint(suffix string) url.URL {
	endpoint := *api.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + suffix
	return endpoint
}

func (api *globalKeyCertificateAPI) request(
	ctx context.Context,
	method string,
	endpoint url.URL,
	body []byte,
) (certificateAPIEnvelope, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return certificateAPIEnvelope{}, api.sanitizeError("construct request", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Auth-Email", api.email)
	request.Header.Set("X-Auth-Key", string(api.apiKey))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := api.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return certificateAPIEnvelope{}, ctx.Err()
		}
		return certificateAPIEnvelope{}, api.sanitizeError("request failed", err)
	}
	defer func() { _ = response.Body.Close() }()
	responseBody, err := readBoundedAPIResponse(response.Body)
	if err != nil {
		return certificateAPIEnvelope{}, api.sanitizeError("read response", err)
	}
	var envelope certificateAPIEnvelope
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return certificateAPIEnvelope{}, api.sanitizeError("decode response", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices || !envelope.Success {
		return certificateAPIEnvelope{}, certificateAPIStatusError(response.StatusCode, envelope.Errors)
	}
	if len(envelope.Result) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Result), []byte("null")) {
		return certificateAPIEnvelope{}, errors.New("Cloudflare certificate API response is missing its result")
	}
	return envelope, nil
}

func readBoundedAPIResponse(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, certificateAPIResponseLimit+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(contents) > certificateAPIResponseLimit {
		return nil, errors.New("Cloudflare certificate API response exceeded the safe size bound")
	}
	return contents, nil
}

func certificateAPIStatusError(status int, apiErrors []struct {
	Code int `json:"code"`
}) error {
	codes := make([]int, 0, len(apiErrors))
	for _, apiError := range apiErrors {
		if apiError.Code > 0 {
			codes = append(codes, apiError.Code)
		}
	}
	sort.Ints(codes)
	if len(codes) == 0 {
		return fmt.Errorf("Cloudflare certificate API request failed (HTTP %d)", status)
	}
	textCodes := make([]string, 0, len(codes))
	for _, code := range codes {
		textCodes = append(textCodes, strconv.Itoa(code))
	}
	return fmt.Errorf("Cloudflare certificate API request failed (HTTP %d, codes %s)", status, strings.Join(textCodes, ","))
}

func (api *globalKeyCertificateAPI) sanitizeError(action string, err error) error {
	diagnostic := redactText(err.Error(), api.apiKey, []byte(api.email))
	return fmt.Errorf("Cloudflare certificate API %s: %s", action, compactDiagnostic(diagnostic))
}

func (c *Client) certificateAPIForFallback(ctx context.Context) (CertificatePackAPI, error) {
	if c.certificateAPI != nil {
		return c.certificateAPI, nil
	}
	if len(c.globalAPIKey) == 0 {
		return nil, nil
	}
	operation, err := c.execute(ctx, ProviderCF, c.cfGlobalCommand("auth", "whoami"), false, c.globalAPIKey)
	if err != nil {
		return nil, fmt.Errorf("verify cf identity for certificate API fallback: %w", err)
	}
	var identity struct {
		Authenticated bool   `json:"authenticated"`
		TokenValid    bool   `json:"tokenValid"`
		Email         string `json:"email"`
	}
	if err := json.Unmarshal([]byte(operation.Stdout), &identity); err != nil {
		return nil, errors.New("decode cf identity for certificate API fallback")
	}
	if !identity.Authenticated || !identity.TokenValid || identity.Email == "" {
		return nil, errors.New("cf identity is not valid for certificate API fallback")
	}
	return newGlobalKeyCertificateAPI(cloudflareAPIBaseURL, c.certificateHTTP, identity.Email, c.globalAPIKey)
}

func certificateAuthorizationDenied(err error) bool {
	var commandError *CommandError
	if !errors.As(err, &commandError) || commandError.Provider != ProviderCF {
		return false
	}
	diagnostic := strings.ToLower(commandError.Stderr)
	return strings.Contains(diagnostic, "403 forbidden") && strings.Contains(diagnostic, "[9109]")
}
