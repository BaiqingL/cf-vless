package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testCurrentUUID  = "27848739-7e62-4138-9fd3-098a63964b6b"
	testPreviousUUID = "550e8400-e29b-41d4-a716-446655440000"
)

func validDeployment() Deployment {
	return Deployment{
		Version:         CurrentVersion,
		WorkerName:      "cf-vless",
		AccountID:       "0123456789abcdef0123456789abcdef",
		ZoneID:          "fedcba9876543210fedcba9876543210",
		ZoneName:        "example.com",
		Hostname:        "edge.example.com",
		Port:            TLSPort,
		DisplayName:     "My Edge",
		AllowedPorts:    []uint16{22, 80, 443},
		OwnershipMarker: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Credentials: CredentialSet{
			Current: Credential{UUID: testCurrentUUID, Path: "/current-path-0001"},
		},
	}
}

func TestGenerateCreatesIndependentSecureValues(t *testing.T) {
	first, err := Generate("edge.example.com", "My Edge")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	second, err := Generate("edge.example.com", "My Edge")
	if err != nil {
		t.Fatalf("Generate() second error = %v", err)
	}

	if err := first.Validate(); err != nil {
		t.Fatalf("generated config is invalid: %v", err)
	}
	if first.Version != CurrentVersion || first.Port != TLSPort {
		t.Fatalf("generated fixed fields = version %d, port %d", first.Version, first.Port)
	}
	if first.WorkerName != "cf-vless" || first.ZoneName != "example.com" || !reflect.DeepEqual(first.AllowedPorts, []uint16{22, 80, 443}) {
		t.Fatalf("generated operational defaults = worker %q zone %q ports %#v", first.WorkerName, first.ZoneName, first.AllowedPorts)
	}
	if first.Credentials.Current.UUID == second.Credentials.Current.UUID {
		t.Fatal("Generate() reused a UUID")
	}
	if first.Credentials.Current.Path == second.Credentials.Current.Path {
		t.Fatal("Generate() reused a WebSocket path")
	}
	if len(first.Credentials.Current.Path) != 33 || first.Credentials.Current.Path[0] != '/' {
		t.Fatalf("generated WebSocket path length = %d, want slash plus 32 characters", len(first.Credentials.Current.Path))
	}
}

func TestNewPreservesExplicitOperationalTargets(t *testing.T) {
	cfg, err := New(InitOptions{
		WorkerName:   "personal-edge",
		AccountID:    "0123456789abcdef0123456789abcdef",
		ZoneID:       "fedcba9876543210fedcba9876543210",
		ZoneName:     "example.com",
		Hostname:     "tunnel.example.com",
		DisplayName:  "Personal Edge",
		AllowedPorts: []uint16{22, 443},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if cfg.WorkerName != "personal-edge" || cfg.AccountID == "" || cfg.ZoneID == "" || cfg.ZoneName != "example.com" || !reflect.DeepEqual(cfg.AllowedPorts, []uint16{22, 443}) {
		t.Fatalf("New() lost operational fields: %#v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("New() config is invalid: %v", err)
	}
}

func TestDeterministicRandomEncoding(t *testing.T) {
	uuid, err := generateUUID(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatalf("generateUUID() error = %v", err)
	}
	if want := "00000000-0000-4000-8000-000000000000"; uuid != want {
		t.Fatalf("generateUUID() = %q, want %q", uuid, want)
	}

	path, err := generateWebSocketPath(bytes.NewReader(make([]byte, 24)))
	if err != nil {
		t.Fatalf("generateWebSocketPath() error = %v", err)
	}
	if want := "/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; path != want {
		t.Fatalf("generateWebSocketPath() = %q, want %q", path, want)
	}
}

func TestValidateRejectsNonCanonicalConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deployment)
	}{
		{name: "version zero", mutate: func(c *Deployment) { c.Version = 0 }},
		{name: "unknown version", mutate: func(c *Deployment) { c.Version = CurrentVersion + 1 }},
		{name: "unsafe worker name", mutate: func(c *Deployment) { c.WorkerName = "../worker" }},
		{name: "worker name underscore", mutate: func(c *Deployment) { c.WorkerName = "bad_worker" }},
		{name: "missing ownership marker", mutate: func(c *Deployment) { c.OwnershipMarker = "" }},
		{name: "invalid account ID", mutate: func(c *Deployment) { c.AccountID = "account" }},
		{name: "invalid zone ID", mutate: func(c *Deployment) { c.ZoneID = "zone" }},
		{name: "invalid zone name", mutate: func(c *Deployment) { c.ZoneName = "Example.com" }},
		{name: "uppercase hostname", mutate: func(c *Deployment) { c.Hostname = "Edge.example.com" }},
		{name: "single label hostname", mutate: func(c *Deployment) { c.Hostname = "localhost" }},
		{name: "hostname with scheme", mutate: func(c *Deployment) { c.Hostname = "https://edge.example.com" }},
		{name: "hostname equals zone", mutate: func(c *Deployment) { c.Hostname = c.ZoneName }},
		{name: "hostname outside zone", mutate: func(c *Deployment) { c.Hostname = "edge.example.net" }},
		{name: "non TLS port", mutate: func(c *Deployment) { c.Port = 8443 }},
		{name: "empty allowed ports", mutate: func(c *Deployment) { c.AllowedPorts = nil }},
		{name: "unsorted allowed ports", mutate: func(c *Deployment) { c.AllowedPorts = []uint16{443, 80} }},
		{name: "duplicate allowed ports", mutate: func(c *Deployment) { c.AllowedPorts = []uint16{80, 80} }},
		{name: "prohibited SMTP port", mutate: func(c *Deployment) { c.AllowedPorts = []uint16{25} }},
		{name: "short path", mutate: func(c *Deployment) { c.Credentials.Current.Path = "/short" }},
		{name: "relative path", mutate: func(c *Deployment) { c.Credentials.Current.Path = "random-path-0001" }},
		{name: "path query", mutate: func(c *Deployment) { c.Credentials.Current.Path = "/random-path-0001?ed=2048" }},
		{name: "empty display name", mutate: func(c *Deployment) { c.DisplayName = "  " }},
		{name: "display name control", mutate: func(c *Deployment) { c.DisplayName = "edge\nname" }},
		{name: "invalid current UUID", mutate: func(c *Deployment) { c.Credentials.Current.UUID = "not-a-uuid" }},
		{name: "non v4 UUID", mutate: func(c *Deployment) { c.Credentials.Current.UUID = "550e8400-e29b-11d4-a716-446655440000" }},
		{name: "managed domain without ID", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145"}
		}},
		{name: "managed domain without certificate", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{DomainID: "cccccccccccccccccccccccccccccccc"}
		}},
		{name: "managed domain uppercase certificate", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{
				DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9FDF92C8-64C2-4A3D-B1AF-E15304961145",
			}
		}},
		{name: "managed domain uppercase ID", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{
				DomainID: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
			}
		}},
		{name: "managed domain uppercase pack", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{
				DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
				CertificatePackID: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
			}
		}},
		{name: "managed domain invalid pack", mutate: func(c *Deployment) {
			c.ManagedDomain = &ManagedDomain{
				DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
				CertificatePackID: "not-a-pack",
			}
		}},
		{name: "same previous UUID", mutate: func(c *Deployment) {
			c.Credentials.Previous = &PreviousCredential{Credential: Credential{UUID: c.Credentials.Current.UUID, Path: "/previous-path-01"}, ExpiresAt: time.Unix(1, 0)}
		}},
		{name: "same previous path", mutate: func(c *Deployment) {
			c.Credentials.Previous = &PreviousCredential{Credential: Credential{UUID: testPreviousUUID, Path: c.Credentials.Current.Path}, ExpiresAt: time.Unix(1, 0)}
		}},
		{name: "previous without expiration", mutate: func(c *Deployment) {
			c.Credentials.Previous = &PreviousCredential{Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"}}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validDeployment()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want rejection")
			}
		})
	}
}

func TestExpiredPreviousCredentialRemainsStructurallyValid(t *testing.T) {
	cfg := validDeployment()
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  time.Unix(100, 0).UTC(),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected an expired rotation record: %v", err)
	}

	active := cfg.Credentials.ActiveUUIDs(time.Unix(101, 0))
	if !reflect.DeepEqual(active, []string{testCurrentUUID}) {
		t.Fatalf("ActiveUUIDs() = %#v, want current UUID only", active)
	}
	active = cfg.Credentials.ActiveUUIDs(time.Unix(99, 0))
	if !reflect.DeepEqual(active, []string{testCurrentUUID, testPreviousUUID}) {
		t.Fatalf("ActiveUUIDs() before expiry = %#v", active)
	}
}

func TestRotateCredentialUsesOverlapWithoutLeakingOlderCredential(t *testing.T) {
	cfg := validDeployment()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.FixedZone("test", -7*60*60))
	random := bytes.NewReader(bytes.Repeat([]byte{1}, 40))

	if err := cfg.rotateCredential(now, 2*time.Hour, random); err != nil {
		t.Fatalf("rotateCredential() error = %v", err)
	}
	if cfg.Credentials.Current.UUID == testCurrentUUID {
		t.Fatal("rotation did not replace the current UUID")
	}
	if cfg.Credentials.Current.Path == "/current-path-0001" {
		t.Fatal("rotation did not replace the current WebSocket path")
	}
	if cfg.Credentials.Previous == nil {
		t.Fatal("rotation did not retain the previous UUID")
	}
	if cfg.Credentials.Previous.UUID != testCurrentUUID || cfg.Credentials.Previous.Path != "/current-path-0001" {
		t.Fatalf("previous UUID = %q, want outgoing current UUID", cfg.Credentials.Previous.UUID)
	}
	if want := now.UTC().Add(2 * time.Hour); !cfg.Credentials.Previous.ExpiresAt.Equal(want) {
		t.Fatalf("previous expiration = %v, want %v", cfg.Credentials.Previous.ExpiresAt, want)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("rotated config is invalid: %v", err)
	}
}

func TestRotateCredentialRejectsInvalidOverlapWithoutMutation(t *testing.T) {
	cfg := validDeployment()
	want := cfg
	if err := cfg.rotateCredential(time.Now(), 0, bytes.NewReader(make([]byte, 16))); err == nil {
		t.Fatal("rotateCredential() error = nil, want invalid overlap error")
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("failed rotation mutated config: got %#v want %#v", cfg, want)
	}
}

func TestRotateCredentialRefusesToDiscardActivePreviousCredential(t *testing.T) {
	cfg := validDeployment()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  now.Add(time.Hour),
	}
	want := cfg
	if err := cfg.rotateCredential(now, time.Hour, bytes.NewReader(make([]byte, 40))); !errors.Is(err, ErrRotationInProgress) {
		t.Fatalf("rotateCredential() error = %v, want ErrRotationInProgress", err)
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatal("failed overlapping rotation mutated config")
	}
}

func TestRotateCredentialReplacesExpiredPreviousCredential(t *testing.T) {
	cfg := validDeployment()
	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  now,
	}
	if err := cfg.rotateCredential(now, time.Hour, bytes.NewReader(bytes.Repeat([]byte{2}, 40))); err != nil {
		t.Fatalf("rotateCredential() error = %v", err)
	}
	if cfg.Credentials.Previous == nil || cfg.Credentials.Previous.UUID != testCurrentUUID || cfg.Credentials.Previous.Path != "/current-path-0001" {
		t.Fatalf("rotation did not replace the expired previous credential: %#v", cfg.Credentials.Previous)
	}
}

func TestEmergencyRotationImmediatelyDropsEveryOldCredential(t *testing.T) {
	cfg := validDeployment()
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	oldCurrent := cfg.Credentials.Current
	if err := cfg.emergencyRotateCredential(bytes.NewReader(bytes.Repeat([]byte{7}, 40))); err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.Previous != nil || cfg.Credentials.Current == oldCurrent {
		t.Fatalf("emergency credentials = %#v", cfg.Credentials)
	}
}

func TestFinalizeCredentialRequiresExpiredOverlapAndKeepsCurrent(t *testing.T) {
	now := time.Now().UTC()
	cfg := validDeployment()
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  now.Add(time.Hour),
	}
	wantCurrent := cfg.Credentials.Current
	if err := cfg.FinalizeCredential(now); !errors.Is(err, ErrRotationOverlapActive) {
		t.Fatalf("active finalization error = %v", err)
	}
	if err := cfg.FinalizeCredential(now.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if cfg.Credentials.Previous != nil || cfg.Credentials.Current != wantCurrent {
		t.Fatalf("finalized credentials = %#v", cfg.Credentials)
	}
}

func TestWorkerSecretJSONMatchesWorkerContract(t *testing.T) {
	cfg := validDeployment()
	cfg.Credentials.Previous = &PreviousCredential{
		Credential: Credential{UUID: testPreviousUUID, Path: "/previous-path-01"},
		ExpiresAt:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	got, err := cfg.WorkerSecretJSON()
	if err != nil {
		t.Fatalf("WorkerSecretJSON() error = %v", err)
	}
	want := "{\n" +
		"  \"current\": {\n" +
		"    \"uuid\": \"27848739-7e62-4138-9fd3-098a63964b6b\",\n" +
		"    \"path\": \"/current-path-0001\"\n" +
		"  },\n" +
		"  \"previous\": {\n" +
		"    \"uuid\": \"550e8400-e29b-41d4-a716-446655440000\",\n" +
		"    \"path\": \"/previous-path-01\",\n" +
		"    \"expiresAt\": \"2030-01-01T00:00:00Z\"\n" +
		"  }\n" +
		"}\n"
	if string(got) != want {
		t.Fatalf("WorkerSecretJSON() =\n%s\nwant\n%s", got, want)
	}
}

func TestWorkerSecretJSONOmitsOperationsMetadataAndAbsentPrevious(t *testing.T) {
	cfg := validDeployment()
	got, err := cfg.WorkerSecretJSON()
	if err != nil {
		t.Fatalf("WorkerSecretJSON() error = %v", err)
	}
	for _, forbidden := range []string{"previous", cfg.WorkerName, cfg.AccountID, cfg.ZoneID, cfg.Hostname, cfg.DisplayName} {
		if strings.Contains(string(got), forbidden) {
			t.Fatalf("WorkerSecretJSON() contains forbidden metadata %q", forbidden)
		}
	}
}

func TestSaveLoadAndOverwriteUseMode0600(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(temp dir) error = %v", err)
	}
	path := filepath.Join(dir, "deployment.json")
	cfg := validDeployment()
	cfg.ManagedDomain = &ManagedDomain{
		DomainID: "cccccccccccccccccccccccccccccccc", InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
	}

	if err := SaveNew(path, &cfg); err != nil {
		t.Fatalf("SaveNew() error = %v", err)
	}
	assertMode0600(t, path)
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !reflect.DeepEqual(*loaded, cfg) {
		t.Fatalf("Load() = %#v, want %#v", *loaded, cfg)
	}
	if err := SaveNew(path, &cfg); !errors.Is(err, ErrFileExists) {
		t.Fatalf("second SaveNew() error = %v, want ErrFileExists", err)
	}

	cfg.DisplayName = "Updated"
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if err := Save(path, &cfg); err != nil {
		t.Fatalf("Save() overwrite error = %v", err)
	}
	assertMode0600(t, path)
	loaded, err = Load(path)
	if err != nil {
		t.Fatalf("Load() after overwrite error = %v", err)
	}
	if loaded.DisplayName != "Updated" {
		t.Fatalf("Load() display name = %q, want Updated", loaded.DisplayName)
	}
}

func TestLoadEnforcesExactManagedDomainSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := `{"version":1,"worker_name":"cf-vless","zone_name":"example.com","hostname":"edge.example.com","port":443,"display_name":"edge","allowed_ports":[22,80,443],"deployment_marker":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","credentials":{"current":{"uuid":"27848739-7e62-4138-9fd3-098a63964b6b","path":"/current-path-0001"}},"managed_domain":%s}`
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "unknown", value: `{"domain_id":"cccccccccccccccccccccccccccccccc","initial_certificate_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145","source":"inferred"}`},
		{name: "missing certificate", value: `{"domain_id":"cccccccccccccccccccccccccccccccc"}`},
		{name: "duplicate", value: `{"domain_id":"cccccccccccccccccccccccccccccccc","domain_id":"dddddddddddddddddddddddddddddddd","initial_certificate_id":"9fdf92c8-64c2-4a3d-b1af-e15304961145"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name+".json")
			if err := WriteSecretFile(path, []byte(fmt.Sprintf(base, test.value)), false); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() accepted an invalid managed_domain object")
			}
		})
	}
}

func TestLoadRejectsUnsafeFilesAndStrictJSONViolations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("Chmod(temp dir) error = %v", err)
	}
	validPath := filepath.Join(dir, "valid.json")
	cfg := validDeployment()
	if err := SaveNew(validPath, &cfg); err != nil {
		t.Fatalf("SaveNew() error = %v", err)
	}

	if err := os.Chmod(validPath, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	if _, err := Load(validPath); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("Load() insecure mode error = %v, want ErrInsecurePermissions", err)
	}
	if err := os.Chmod(validPath, 0o600); err != nil {
		t.Fatalf("Chmod() restore error = %v", err)
	}

	unknownPath := filepath.Join(dir, "unknown.json")
	unknown := []byte(`{"version":1,"worker_name":"cf-vless","zone_name":"example.com","hostname":"edge.example.com","port":443,"display_name":"edge","allowed_ports":[22,80,443],"credentials":{"current":{"uuid":"27848739-7e62-4138-9fd3-098a63964b6b","path":"/current-path-0001"}},"api_token":"must-not-be-accepted"}`)
	if err := WriteSecretFile(unknownPath, unknown, false); err != nil {
		t.Fatalf("WriteSecretFile() error = %v", err)
	}
	if _, err := Load(unknownPath); err == nil {
		t.Fatal("Load() accepted an unknown field")
	}

	aliasPath := filepath.Join(dir, "alias.json")
	valid, err := marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	aliased := bytes.Replace(valid, []byte(`"version": 1`), []byte(`"Version": 1`), 1)
	if err := WriteSecretFile(aliasPath, aliased, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(aliasPath); err == nil {
		t.Fatal("Load() accepted a case-insensitive field alias")
	}

	trailingPath := filepath.Join(dir, "trailing.json")
	data, err := marshal(&cfg)
	if err != nil {
		t.Fatalf("marshal() error = %v", err)
	}
	data = append(data, []byte("{}")...)
	if err := WriteSecretFile(trailingPath, data, false); err != nil {
		t.Fatalf("WriteSecretFile() trailing error = %v", err)
	}
	if _, err := Load(trailingPath); err == nil {
		t.Fatal("Load() accepted trailing JSON")
	}

	duplicatePath := filepath.Join(dir, "duplicate.json")
	duplicate := []byte(`{"version":1,"version":1,"worker_name":"cf-vless","zone_name":"example.com","hostname":"edge.example.com","port":443,"display_name":"edge","allowed_ports":[22,80,443],"credentials":{"current":{"uuid":"27848739-7e62-4138-9fd3-098a63964b6b","path":"/current-path-0001"}}}`)
	if err := WriteSecretFile(duplicatePath, duplicate, false); err != nil {
		t.Fatalf("WriteSecretFile() duplicate error = %v", err)
	}
	if _, err := Load(duplicatePath); err == nil {
		t.Fatal("Load() accepted a duplicate JSON field")
	}

	if runtime.GOOS != "windows" {
		linkPath := filepath.Join(dir, "link.json")
		if err := os.Symlink(validPath, linkPath); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		if _, err := Load(linkPath); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("Load() symlink error = %v, want ErrUnsafeFile", err)
		}
	}
}

func TestWriteSecretFileRejectsSymlinkDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	dir := t.TempDir()
	realDirectory := filepath.Join(dir, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	linkedDirectory := filepath.Join(dir, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := WriteSecretFile(filepath.Join(linkedDirectory, "secret"), []byte("secret"), false); !errors.Is(err, ErrUnsafeFile) {
		t.Fatalf("WriteSecretFile() error = %v, want ErrUnsafeFile", err)
	}
}

func TestWriteSecretFileRejectsGroupReadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions are not available on Windows")
	}
	dir := filepath.Join(t.TempDir(), "insecure")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := WriteSecretFile(filepath.Join(dir, "secret"), []byte("secret"), false); !errors.Is(err, ErrInsecureDirectoryPermissions) {
		t.Fatalf("WriteSecretFile() error = %v, want ErrInsecureDirectoryPermissions", err)
	}
}

func TestLoadRejectsGroupAccessibleStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions are not available on Windows")
	}
	directory := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(directory, "deployment.json")
	cfg := validDeployment()
	if err := SaveNew(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInsecureDirectoryPermissions) {
		t.Fatalf("Load() directory error = %v, want ErrInsecureDirectoryPermissions", err)
	}
}

func TestRequireSettledCredentialsFailsClosedForAnyPendingEntry(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(directory, "deployment.json")
	cfg := validDeployment()
	if err := SaveNew(path, &cfg); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireOperationLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if err := RequireSettledCredentials(path); err != nil {
		t.Fatalf("settled state rejected: %v", err)
	}
	if err := WriteSecretFile(filepath.Join(directory, pendingDeploymentFilename), []byte("pending"), false); err != nil {
		t.Fatal(err)
	}
	if err := RequireSettledCredentials(path); !errors.Is(err, ErrCredentialOperationPending) {
		t.Fatalf("pending state error = %v, want ErrCredentialOperationPending", err)
	}
}

func TestRandomGenerationRejectsShortReads(t *testing.T) {
	if _, err := generateUUID(bytes.NewReader(make([]byte, 15))); err == nil {
		t.Fatal("generateUUID() accepted 15 random bytes")
	}
	if _, err := generateWebSocketPath(bytes.NewReader(make([]byte, 23))); err == nil {
		t.Fatal("generateWebSocketPath() accepted 23 random bytes")
	}
}

func TestErrorsDoNotContainCredentials(t *testing.T) {
	cfg := validDeployment()
	cfg.Hostname = "invalid host"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil")
	}
	message := err.Error()
	if strings.Contains(message, testCurrentUUID) || strings.Contains(message, testPreviousUUID) {
		t.Fatalf("validation error leaks a credential: %q", message)
	}
}

func assertMode0600(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode for %q = %#o, want 0600", path, got)
	}
}
