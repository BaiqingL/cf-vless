package conformance_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BaiqingL/cf-vless/internal/clientformats"
	"github.com/BaiqingL/cf-vless/internal/config"
)

func TestGeneratedClientConfigurationsWithAvailableBinaries(t *testing.T) {
	cfg := config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     `Conformance: "東京" #1`,
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{
			Current: config.Credential{
				UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
				Path: "/conformance-path-01",
			},
		},
	}
	outputs, err := clientformats.Generate(cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	directory := t.TempDir()

	t.Run("xray", func(t *testing.T) {
		binary := clientBinary(t, "XRAY_BIN", "xray")
		path := writeFixture(t, directory, "xray.json", outputs.XrayJSON)
		command := exec.Command(binary, "run", "-test", "-format=json", "-config", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("Xray rejected generated configuration: %v\n%s", err, output)
		}
	})

	t.Run("sing-box", func(t *testing.T) {
		binary := clientBinary(t, "SING_BOX_BIN", "sing-box")
		path := writeFixture(t, directory, "sing-box.json", outputs.SingBoxJSON)
		command := exec.Command(binary, "check", "-c", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("sing-box rejected generated configuration: %v\n%s", err, output)
		}
	})

	t.Run("mihomo", func(t *testing.T) {
		binary := clientBinary(t, "MIHOMO_BIN", "mihomo")
		path := writeFixture(t, directory, "mihomo.yaml", outputs.MihomoYAML)
		command := exec.Command(binary, "-t", "-f", path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("Mihomo rejected generated configuration: %v\n%s", err, output)
		}
	})
}

func clientBinary(t *testing.T, environment, name string) string {
	t.Helper()
	if path := os.Getenv(environment); path != "" {
		return path
	}
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not available; set %s to run this conformance check", name, environment)
	}
	return path
}

func writeFixture(t *testing.T, directory, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}
