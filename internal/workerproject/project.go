// Package workerproject materializes the tested Worker source into an ignored,
// owner-only deployment workspace with variables derived from canonical state.
package workerproject

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BaiqingL/cf-vless/internal/config"
)

const (
	maxTemplateFileBytes    = 4 << 20
	workerCompatibilityDate = "2026-07-12"
	handshakeTimeout        = "10000"
	connectTimeout          = "10000"
	idleTimeout             = "300000"
	sessionTimeout          = "3600000"
)

type generatedConfig struct {
	Schema             string              `json:"$schema"`
	Name               string              `json:"name"`
	Main               string              `json:"main"`
	CompatibilityDate  string              `json:"compatibility_date"`
	CompatibilityFlags []string            `json:"compatibility_flags"`
	WorkersDev         bool                `json:"workers_dev"`
	PreviewURLs        bool                `json:"preview_urls"`
	Secrets            *requiredSecrets    `json:"secrets,omitempty"`
	Routes             []generatedRoute    `json:"routes,omitempty"`
	Vars               map[string]string   `json:"vars"`
	Observability      observabilityConfig `json:"observability"`
}

type generatedRoute struct {
	Pattern      string `json:"pattern"`
	ZoneName     string `json:"zone_name"`
	CustomDomain bool   `json:"custom_domain"`
}

type requiredSecrets struct {
	Required []string `json:"required"`
}

type observabilityConfig struct {
	Enabled bool              `json:"enabled"`
	Logs    observabilityLogs `json:"logs"`
}

type observabilityLogs struct {
	Enabled          bool    `json:"enabled"`
	HeadSamplingRate float64 `json:"head_sampling_rate"`
	InvocationLogs   bool    `json:"invocation_logs"`
}

// Prepare copies the minimal tracked project inputs and writes equivalent
// Wrangler and cf 0.2.0 configurations. It never copies .dev.vars, generated
// clients, node_modules, or any credential value.
func Prepare(sourceDirectory, targetDirectory string, deployment config.Deployment) error {
	return prepare(sourceDirectory, targetDirectory, deployment, true)
}

// PrepareBootstrap emits the same tested Worker without a required-secret
// declaration. It is used only for the first unroutable upload so cf can create
// the script before the secret is supplied over protected stdin.
func PrepareBootstrap(sourceDirectory, targetDirectory string, deployment config.Deployment) error {
	return prepare(sourceDirectory, targetDirectory, deployment, false)
}

func prepare(sourceDirectory, targetDirectory string, deployment config.Deployment, requireSecret bool) error {
	if err := deployment.Validate(); err != nil {
		return err
	}
	source, err := filepath.Abs(sourceDirectory)
	if err != nil {
		return fmt.Errorf("resolve Worker source: %w", err)
	}
	target, err := filepath.Abs(targetDirectory)
	if err != nil {
		return fmt.Errorf("resolve Worker workspace: %w", err)
	}
	separator := string(filepath.Separator)
	if source == target || strings.HasPrefix(source+separator, target+separator) || strings.HasPrefix(target+separator, source+separator) {
		return errors.New("Worker workspace must not contain its source template")
	}
	if err := validateSourceDirectory(source); err != nil {
		return err
	}
	if err := config.EnsureSecretDirectory(target); err != nil {
		return fmt.Errorf("prepare Worker workspace: %w", err)
	}

	for _, name := range []string{"package.json", "package-lock.json", "tsconfig.json"} {
		if err := copyTemplateFile(filepath.Join(source, name), filepath.Join(target, name)); err != nil {
			return err
		}
	}
	if err := copySourceTree(filepath.Join(source, "src"), filepath.Join(target, "src")); err != nil {
		return err
	}
	encoded, err := marshalWranglerConfig(deployment, requireSecret)
	if err != nil {
		return err
	}
	if err := config.WriteSecretFile(filepath.Join(target, "wrangler.jsonc"), encoded, true); err != nil {
		return fmt.Errorf("write generated Wrangler configuration: %w", err)
	}
	cloudflareConfig, err := marshalCloudflareConfig(deployment, requireSecret)
	if err != nil {
		return err
	}
	if err := config.WriteSecretFile(filepath.Join(target, "cloudflare.config.ts"), cloudflareConfig, true); err != nil {
		return fmt.Errorf("write generated cf configuration: %w", err)
	}
	return nil
}

func validateSourceDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect Worker source: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Worker source must be a regular directory")
	}
	return nil
}

func copySourceTree(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in Worker source: %s", relative)
		}
		if entry.IsDir() {
			return config.EnsureSecretDirectory(filepath.Join(target, relative))
		}
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".ts" {
			return fmt.Errorf("unexpected Worker source entry: %s", relative)
		}
		return copyTemplateFile(path, filepath.Join(target, relative))
	})
}

func copyTemplateFile(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("inspect Worker template %s: %w", filepath.Base(source), err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Worker template %s is not a regular file", filepath.Base(source))
	}
	if info.Size() > maxTemplateFileBytes {
		return fmt.Errorf("Worker template %s is too large", filepath.Base(source))
	}
	file, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open Worker template %s: %w", filepath.Base(source), err)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, maxTemplateFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		readErr = fmt.Errorf("read Worker template %s: %w", filepath.Base(source), readErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close Worker template %s: %w", filepath.Base(source), closeErr)
	}
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if len(content) > maxTemplateFileBytes {
		return fmt.Errorf("Worker template %s is too large", filepath.Base(source))
	}
	if err := config.WriteSecretFile(target, content, true); err != nil {
		return fmt.Errorf("copy Worker template %s: %w", filepath.Base(source), err)
	}
	return nil
}

func marshalWranglerConfig(deployment config.Deployment, requireSecret bool) ([]byte, error) {
	document := generatedConfig{
		Schema:             "./node_modules/wrangler/config-schema.json",
		Name:               deployment.WorkerName,
		Main:               "src/index.ts",
		CompatibilityDate:  workerCompatibilityDate,
		CompatibilityFlags: []string{"nodejs_compat"},
		WorkersDev:         false,
		PreviewURLs:        false,
		Vars:               generatedVars(deployment),
		Observability: observabilityConfig{
			Enabled: false,
			Logs: observabilityLogs{
				Enabled:          false,
				HeadSamplingRate: 0,
				InvocationLogs:   false,
			},
		},
	}
	if requireSecret {
		document.Secrets = &requiredSecrets{Required: []string{config.WorkerSecretName}}
		if deployment.ManagedDomain != nil {
			document.Routes = []generatedRoute{{
				Pattern: deployment.Hostname, ZoneName: deployment.ZoneName, CustomDomain: true,
			}}
		}
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, errors.New("encode generated Wrangler configuration")
	}
	return append(encoded, '\n'), nil
}

// marshalCloudflareConfig emits the installed cf 0.2.0 Build Output API
// configuration. cf forces Wrangler's experimental new-config path, which
// reads cloudflare.config.ts rather than wrangler.jsonc. Both files describe
// the same single Worker; only cf consumes this one.
func marshalCloudflareConfig(deployment config.Deployment, requireSecret bool) ([]byte, error) {
	if err := deployment.Validate(); err != nil {
		return nil, err
	}
	variables := generatedVars(deployment)

	var document strings.Builder
	document.WriteString("import { bindings, defineWorker } from \"wrangler/experimental-config\";\n\n")
	document.WriteString("export default defineWorker({\n")
	fmt.Fprintf(&document, "  name: %s,\n", strconv.Quote(deployment.WorkerName))
	fmt.Fprintf(&document, "  compatibilityDate: %s,\n", strconv.Quote(workerCompatibilityDate))
	document.WriteString("  compatibilityFlags: [\"nodejs_compat\"],\n")
	document.WriteString("  entrypoint: \"./src/index.ts\",\n")
	document.WriteString("  workersDev: false,\n")
	document.WriteString("  previewUrls: false,\n")
	if requireSecret && deployment.ManagedDomain != nil {
		fmt.Fprintf(&document, "  domains: [%s],\n", strconv.Quote(deployment.Hostname))
	}
	document.WriteString("  observability: {\n")
	document.WriteString("    enabled: false,\n")
	document.WriteString("    headSamplingRate: 0,\n")
	document.WriteString("    logs: { enabled: false, headSamplingRate: 0, invocationLogs: false, persist: false },\n")
	document.WriteString("    traces: { enabled: false, headSamplingRate: 0, persist: false }\n")
	document.WriteString("  },\n")
	document.WriteString("  env: {\n")
	fmt.Fprintf(&document, "    EXPECTED_HOST: bindings.text(%s),\n", strconv.Quote(variables["EXPECTED_HOST"]))
	fmt.Fprintf(&document, "    %s: bindings.text(%s),\n", config.OwnershipMarkerBinding, strconv.Quote(variables[config.OwnershipMarkerBinding]))
	fmt.Fprintf(&document, "    ALLOWED_PORTS: bindings.text(%s),\n", strconv.Quote(variables["ALLOWED_PORTS"]))
	fmt.Fprintf(&document, "    HANDSHAKE_TIMEOUT_MS: bindings.text(%s),\n", strconv.Quote(variables["HANDSHAKE_TIMEOUT_MS"]))
	fmt.Fprintf(&document, "    CONNECT_TIMEOUT_MS: bindings.text(%s),\n", strconv.Quote(variables["CONNECT_TIMEOUT_MS"]))
	fmt.Fprintf(&document, "    IDLE_TIMEOUT_MS: bindings.text(%s),\n", strconv.Quote(variables["IDLE_TIMEOUT_MS"]))
	fmt.Fprintf(&document, "    SESSION_TIMEOUT_MS: bindings.text(%s),\n", strconv.Quote(variables["SESSION_TIMEOUT_MS"]))
	if requireSecret {
		fmt.Fprintf(&document, "    %s: bindings.secret(),\n", config.WorkerSecretName)
	}
	document.WriteString("  }\n")
	document.WriteString("});\n")
	return []byte(document.String()), nil
}

func generatedVars(deployment config.Deployment) map[string]string {
	ports := make([]string, 0, len(deployment.AllowedPorts))
	for _, port := range deployment.AllowedPorts {
		ports = append(ports, strconv.Itoa(int(port)))
	}
	return map[string]string{
		"EXPECTED_HOST":               deployment.Hostname,
		config.OwnershipMarkerBinding: deployment.OwnershipMarker,
		"ALLOWED_PORTS":               strings.Join(ports, ","),
		"HANDSHAKE_TIMEOUT_MS":        handshakeTimeout,
		"CONNECT_TIMEOUT_MS":          connectTimeout,
		"IDLE_TIMEOUT_MS":             idleTimeout,
		"SESSION_TIMEOUT_MS":          sessionTimeout,
	}
}
