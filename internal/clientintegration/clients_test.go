package clientintegration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BaiqingL/cf-vless/internal/config"
)

func integrationDeployment() *config.Deployment {
	return &config.Deployment{
		Version:         config.CurrentVersion,
		WorkerName:      "cf-vless",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            config.TLSPort,
		DisplayName:     "Integration",
		AllowedPorts:    config.DefaultAllowedPorts(),
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: config.CredentialSet{Current: config.Credential{
			UUID: "27848739-7e62-4138-9fd3-098a63964b6b",
			Path: "/integration-path-01",
		}},
	}
}

func TestParseSelection(t *testing.T) {
	t.Parallel()

	all, err := ParseSelection("all")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(all, []Name{Xray, SingBox, Mihomo}) {
		t.Fatalf("all = %q", all)
	}
	selected, err := ParseSelection("mihomo,xray")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selected, []Name{Mihomo, Xray}) {
		t.Fatalf("selected = %q", selected)
	}
	for _, invalid := range []string{"", "all,xray", "xray,xray", "unknown"} {
		if _, err := ParseSelection(invalid); err == nil {
			t.Errorf("selection %q was accepted", invalid)
		}
	}
}

func TestPrepareWritesPrivateCanonicalConfigs(t *testing.T) {
	t.Parallel()

	for _, name := range []Name{Xray, SingBox, Mihomo} {
		t.Run(string(name), func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), string(name))
			specification, err := Prepare(name, "client-bin", directory, integrationDeployment(), 19080)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(specification.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode = %o", info.Mode().Perm())
			}
			if specification.SOCKSAddress != "127.0.0.1:19080" {
				t.Fatalf("SOCKS address = %q", specification.SOCKSAddress)
			}
			content, err := os.ReadFile(specification.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, secretValue := range []string{integrationDeployment().Credentials.Current.UUID, integrationDeployment().Credentials.Current.Path} {
				if !strings.Contains(string(content), secretValue) {
					t.Fatalf("config does not contain required credential component")
				}
			}
			switch name {
			case Xray:
				var document map[string]any
				if err := json.Unmarshal(content, &document); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(specification.CheckArgs, []string{"run", "-test", "-format=json", "-c", specification.ConfigPath}) {
					t.Fatalf("check args = %q", specification.CheckArgs)
				}
			case SingBox:
				var document map[string]any
				if err := json.Unmarshal(content, &document); err != nil {
					t.Fatal(err)
				}
				inbounds := document["inbounds"].([]any)
				if inbounds[0].(map[string]any)["listen_port"] != float64(19080) {
					t.Fatalf("sing-box inbound = %#v", inbounds[0])
				}
				if !slices.Equal(specification.CheckArgs, []string{"check", "-c", specification.ConfigPath}) {
					t.Fatalf("check args = %q", specification.CheckArgs)
				}
			case Mihomo:
				if !strings.Contains(string(content), "mixed-port: 19080") || !strings.Contains(string(content), "allow-lan: false") {
					t.Fatalf("mihomo config = %s", content)
				}
				if !slices.Equal(specification.CheckArgs, []string{"-t", "-d", directory, "-f", specification.ConfigPath}) {
					t.Fatalf("check args = %q", specification.CheckArgs)
				}
			}
		})
	}
}
