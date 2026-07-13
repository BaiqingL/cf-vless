package cloudflare

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	cloudflareIDPattern   = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	workerDomainIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}([0-9a-fA-F]{8})?$`)
	uuidPattern           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	workerNamePattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	secretNamePattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostLabelPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

func decodeObjectList(output string) ([]map[string]any, error) {
	if strings.TrimSpace(output) == "" {
		return nil, nil
	}
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return objectList(value)
}

func objectList(value any) ([]map[string]any, error) {
	switch typed := value.(type) {
	case []any:
		objects := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("list item is %T, not an object", item)
			}
			objects = append(objects, object)
		}
		return objects, nil
	case map[string]any:
		for _, key := range []string{"result", "items", "data", "accounts", "zones", "scripts", "deployments", "domains", "secrets"} {
			if nested, ok := typed[key]; ok {
				if objects, err := objectList(nested); err == nil {
					return objects, nil
				}
			}
		}
		return []map[string]any{typed}, nil
	default:
		return nil, fmt.Errorf("JSON root is %T, not an object or list", value)
	}
}

func firstString(object map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := object[key]
		if !ok || value == nil {
			continue
		}
		if text, ok := value.(string); ok {
			return text
		}
	}
	return ""
}

func nestedObject(object map[string]any, key string) map[string]any {
	if nested, ok := object[key].(map[string]any); ok {
		return nested
	}
	return nil
}

func parseDomains(output string) ([]DomainBinding, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	domains := make([]DomainBinding, 0, len(objects))
	for _, object := range objects {
		domains = append(domains, DomainBinding{
			ID:          firstString(object, "id", "domain_id"),
			CertID:      firstString(object, "cert_id", "certificate_id"),
			Hostname:    firstString(object, "hostname"),
			Service:     firstString(object, "service", "script_name"),
			Environment: firstString(object, "environment"),
			ZoneID:      firstString(object, "zone_id"),
			ZoneName:    firstString(object, "zone_name"),
		})
	}
	return domains, nil
}

func parseCertificatePacks(output string) ([]CertificatePack, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	packs := make([]CertificatePack, 0, len(objects))
	for _, object := range objects {
		pack := CertificatePack{
			ID:     firstString(object, "id"),
			Type:   firstString(object, "type"),
			Status: firstString(object, "status"),
			Hosts:  stringList(object["hosts"]),
		}
		if certificates, ok := object["certificates"].([]any); ok {
			pack.Certificates = make([]CertificatePackCertificate, 0, len(certificates))
			for _, raw := range certificates {
				certificate, ok := raw.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("certificate pack child is %T, not an object", raw)
				}
				pack.Certificates = append(pack.Certificates, CertificatePackCertificate{
					ID:    firstString(certificate, "id"),
					Hosts: stringList(certificate["hosts"]),
				})
			}
		}
		packs = append(packs, pack)
	}
	return packs, nil
}

func stringList(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func parseSecrets(output string) ([]SecretBinding, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	secrets := make([]SecretBinding, 0, len(objects))
	for _, object := range objects {
		secrets = append(secrets, SecretBinding{
			Name: firstString(object, "name"),
			Type: firstString(object, "type"),
		})
	}
	return secrets, nil
}

func parseDNSRecords(output string) ([]DNSRecord, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	records := make([]DNSRecord, 0, len(objects))
	for _, object := range objects {
		records = append(records, DNSRecord{
			ID:      firstString(object, "id"),
			Type:    firstString(object, "type"),
			Name:    firstString(object, "name"),
			Content: firstString(object, "content"),
		})
	}
	return records, nil
}

func parseWorkerRoutes(output string) ([]WorkerRoute, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	routes := make([]WorkerRoute, 0, len(objects))
	for _, object := range objects {
		pattern := firstString(object, "pattern")
		if pattern == "" {
			return nil, fmt.Errorf("Worker route is missing its pattern")
		}
		routes = append(routes, WorkerRoute{
			ID:      firstString(object, "id"),
			Pattern: pattern,
			Script:  firstString(object, "script"),
		})
	}
	return routes, nil
}

func parseScriptNames(output string) ([]string, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(objects))
	for _, object := range objects {
		name := firstString(object, "id", "name", "script_name")
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func parseOwnershipMarker(output, bindingName string) (string, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return "", err
	}
	marker := ""
	for _, object := range objects {
		bindings, ok := object["bindings"].([]any)
		if !ok {
			continue
		}
		for _, raw := range bindings {
			binding, ok := raw.(map[string]any)
			if !ok || firstString(binding, "name") != bindingName || firstString(binding, "type") != "plain_text" {
				continue
			}
			value := firstString(binding, "text")
			if marker != "" || value == "" {
				return "", fmt.Errorf("ownership marker binding is ambiguous")
			}
			marker = value
		}
	}
	return marker, nil
}

type workerBinding struct {
	Name string
	Type string
}

// parseWorkerBindings reads the complete binding inventory returned by the
// script-and-version-settings endpoint. Unlike parseOwnershipMarker, this is
// deliberately strict: removal safety depends on proving that every attached
// binding is one managed by this project.
func parseWorkerBindings(output string) ([]workerBinding, error) {
	objects, err := decodeObjectList(output)
	if err != nil {
		return nil, err
	}
	var bindings []workerBinding
	found := false
	for _, object := range objects {
		rawBindings, exists := object["bindings"]
		if !exists {
			continue
		}
		if found {
			return nil, fmt.Errorf("Worker settings contain multiple binding inventories")
		}
		found = true
		items, ok := rawBindings.([]any)
		if !ok {
			return nil, fmt.Errorf("Worker settings bindings are %T, not a list", rawBindings)
		}
		bindings = make([]workerBinding, 0, len(items))
		for _, raw := range items {
			binding, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("Worker binding is %T, not an object", raw)
			}
			name := firstString(binding, "name")
			bindingType := firstString(binding, "type")
			if name == "" || bindingType == "" {
				return nil, fmt.Errorf("Worker binding is missing a name or type")
			}
			bindings = append(bindings, workerBinding{Name: name, Type: bindingType})
		}
	}
	if !found {
		return nil, fmt.Errorf("Worker settings do not contain a binding inventory")
	}
	return bindings, nil
}

func validateArgument(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", label)
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s must not begin with a hyphen", label)
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func validateCloudflareID(label, value string) error {
	if !cloudflareIDPattern.MatchString(value) {
		return fmt.Errorf("%s must be a 32-character hexadecimal identifier", label)
	}
	return nil
}

func validateWorkerDomainID(label, value string) error {
	if !workerDomainIDPattern.MatchString(value) {
		return fmt.Errorf("%s must be a 32- or 40-character hexadecimal identifier", label)
	}
	return nil
}

func validateCertificatePackID(label, value string) error {
	if !cloudflareIDPattern.MatchString(value) && !uuidPattern.MatchString(value) {
		return fmt.Errorf("%s must be a 32-character hexadecimal identifier or canonical UUID", label)
	}
	return nil
}

func validateUUID(label, value string) error {
	if !uuidPattern.MatchString(value) {
		return fmt.Errorf("%s must be a canonical UUID", label)
	}
	return nil
}

func validateWorkerName(value string) error {
	if !workerNamePattern.MatchString(value) {
		return fmt.Errorf("worker name is invalid")
	}
	return nil
}

func validateSecretName(value string) error {
	if !secretNamePattern.MatchString(value) {
		return fmt.Errorf("secret name is not a JavaScript identifier")
	}
	return nil
}

func normalizeHostname(label, value string) (string, error) {
	if err := validateArgument(label, value); err != nil {
		return "", err
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) > 253 || strings.Contains(value, "*") || strings.ContainsAny(value, "/:@[]") {
		return "", fmt.Errorf("%s is not a valid ASCII hostname", label)
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%s must be a fully-qualified hostname", label)
	}
	for _, hostnameLabel := range labels {
		if len(hostnameLabel) > 63 || !hostLabelPattern.MatchString(hostnameLabel) {
			return "", fmt.Errorf("%s is not a valid ASCII hostname", label)
		}
	}
	return value, nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
