package workerproject

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BaiqingL/cf-vless/internal/config"
)

func testDeployment() config.Deployment {
	return config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "personal-edge",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Personal Edge",
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
			Path: "/random-path-0001",
		}},
	}
}

func TestPrepareCopiesSourceAndDerivesNonSecretConfiguration(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "template")
	target := filepath.Join(root, "state", "worker")
	for _, directory := range []string{source, filepath.Join(source, "src"), filepath.Join(source, "src", "protocol")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"package.json":          `{"private":true}`,
		"package-lock.json":     `{"lockfileVersion":3}`,
		"tsconfig.json":         `{}`,
		"src/index.ts":          `export default {};`,
		"src/protocol/vless.ts": `export const version = 0;`,
	} {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	deployment := testDeployment()
	if err := Prepare(source, target, deployment); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	for _, name := range []string{"package.json", "package-lock.json", "tsconfig.json", "src/index.ts", "src/protocol/vless.ts"} {
		if _, err := os.Stat(filepath.Join(target, filepath.FromSlash(name))); err != nil {
			t.Fatalf("missing copied %s: %v", name, err)
		}
	}
	wranglerBytes, err := os.ReadFile(filepath.Join(target, "wrangler.jsonc"))
	if err != nil {
		t.Fatal(err)
	}
	var wrangler map[string]any
	if err := json.Unmarshal(wranglerBytes, &wrangler); err != nil {
		t.Fatalf("generated Wrangler config is not JSON: %v", err)
	}
	if wrangler["name"] != deployment.WorkerName {
		t.Fatalf("generated name = %#v", wrangler["name"])
	}
	vars, ok := wrangler["vars"].(map[string]any)
	if !ok || vars["EXPECTED_HOST"] != deployment.Hostname || vars["ALLOWED_PORTS"] != "22,80,443" {
		t.Fatalf("generated vars = %#v", wrangler["vars"])
	}
	if vars[config.OwnershipMarkerBinding] != deployment.OwnershipMarker {
		t.Fatalf("generated ownership marker = %#v", vars[config.OwnershipMarkerBinding])
	}
	observability, ok := wrangler["observability"].(map[string]any)
	if !ok || observability["enabled"] != false {
		t.Fatalf("generated observability = %#v, want disabled", wrangler["observability"])
	}
	logs, ok := observability["logs"].(map[string]any)
	if !ok || logs["enabled"] != false || logs["invocation_logs"] != false {
		t.Fatalf("generated invocation logs = %#v, want disabled", observability["logs"])
	}
	text := string(wranglerBytes)
	if strings.Contains(text, deployment.Credentials.Current.UUID) || strings.Contains(text, deployment.Credentials.Current.Path) {
		t.Fatal("generated Worker configuration contains credentials")
	}
	cloudflareBytes, err := os.ReadFile(filepath.Join(target, "cloudflare.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	cloudflareText := string(cloudflareBytes)
	for _, expected := range []string{
		`name: "personal-edge"`,
		`EXPECTED_HOST: bindings.text("edge.example.com")`,
		`DEPLOYMENT_MARKER: bindings.text("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")`,
		`ALLOWED_PORTS: bindings.text("22,80,443")`,
		`VLESS_CREDENTIALS: bindings.secret()`,
		`workersDev: false`,
		`previewUrls: false`,
		`persist: false`,
	} {
		if !strings.Contains(cloudflareText, expected) {
			t.Fatalf("generated cf configuration omitted %q", expected)
		}
	}
	if strings.Contains(cloudflareText, deployment.Credentials.Current.UUID) || strings.Contains(cloudflareText, deployment.Credentials.Current.Path) {
		t.Fatal("generated cf configuration contains credentials")
	}
}

func TestPrepareBootstrapOmitsRequiredSecretButRetainsOwnershipMarker(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "template")
	target := filepath.Join(root, "state", "worker")
	if err := os.MkdirAll(filepath.Join(source, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"package.json":      `{"private":true}`,
		"package-lock.json": `{"lockfileVersion":3}`,
		"tsconfig.json":     `{}`,
		"src/index.ts":      `export default {};`,
	} {
		if err := os.WriteFile(filepath.Join(source, filepath.FromSlash(name)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	deployment := testDeployment()
	if err := PrepareBootstrap(source, target, deployment); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrangler.jsonc", "cloudflare.config.ts"} {
		encoded, err := os.ReadFile(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), config.WorkerSecretName) {
			t.Fatalf("bootstrap %s declared a required secret", name)
		}
		if !strings.Contains(string(encoded), deployment.OwnershipMarker) {
			t.Fatalf("bootstrap %s omitted ownership marker", name)
		}
	}
}

func TestGeneratedConfigsPublishDomainOnlyAfterProtectedProvenance(t *testing.T) {
	deployment := testDeployment()
	deployment.ManagedDomain = &config.ManagedDomain{
		DomainID:             "cccccccccccccccccccccccccccccccccccccccc",
		InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
		CertificatePackID:    "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
	}
	wrangler, err := marshalWranglerConfig(deployment, true)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Routes []generatedRoute `json:"routes"`
	}
	if err := json.Unmarshal(wrangler, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Routes) != 1 || document.Routes[0].Pattern != deployment.Hostname ||
		document.Routes[0].ZoneName != deployment.ZoneName || !document.Routes[0].CustomDomain {
		t.Fatalf("generated routes = %#v", document.Routes)
	}
	cloudflareConfig, err := marshalCloudflareConfig(deployment, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cloudflareConfig), `domains: ["edge.example.com"]`) {
		t.Fatal("protected cf configuration omitted the Custom Domain")
	}
	bootstrap, err := marshalCloudflareConfig(deployment, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bootstrap), "domains:") {
		t.Fatal("unprotected bootstrap published the Custom Domain")
	}
}

func TestTrackedCFTemplateMatchesGeneratedConfiguration(t *testing.T) {
	deployment := testDeployment()
	deployment.WorkerName = config.DefaultWorkerName
	generated, err := marshalCloudflareConfig(deployment, true)
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := os.ReadFile(filepath.Join("..", "..", "worker", "cloudflare.config.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if string(generated) != string(tracked) {
		t.Fatal("tracked cf configuration drifted from the canonical generator")
	}
}

func TestTrackedWranglerTemplateMatchesGeneratedConfiguration(t *testing.T) {
	deployment := testDeployment()
	deployment.WorkerName = config.DefaultWorkerName
	generated, err := marshalWranglerConfig(deployment, true)
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := os.ReadFile(filepath.Join("..", "..", "worker", "wrangler.jsonc"))
	if err != nil {
		t.Fatal(err)
	}
	var generatedDocument, trackedDocument any
	if err := json.Unmarshal(generated, &generatedDocument); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(tracked, &trackedDocument); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(generatedDocument, trackedDocument) {
		t.Fatal("tracked Wrangler configuration drifted from the canonical generator")
	}
}

func TestPrepareRejectsSymlinkedSourceEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "template")
	if err := os.MkdirAll(filepath.Join(source, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "package-lock.json", "tsconfig.json"} {
		if err := os.WriteFile(filepath.Join(source, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(root, "outside.ts")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "src", "index.ts")); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(source, filepath.Join(root, "state", "worker"), testDeployment()); err == nil {
		t.Fatal("Prepare() accepted a symlinked source entry")
	}
}
