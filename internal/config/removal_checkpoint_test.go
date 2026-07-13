package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRemovalCheckpointRoundTripAndDeploymentMatch(t *testing.T) {
	deployment := validDeployment()
	checkpoint, err := NewRemovalCheckpoint(deployment,
		[]string{"cccccccccccccccccccccccccccccccc"},
		[]string{"dddddddddddddddddddddddddddddddd"},
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(directory, "removal.pending.json")
	if err := SaveRemovalCheckpointNew(path, &checkpoint); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRemovalCheckpoint(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Matches(deployment) || *loaded != checkpoint {
		t.Fatalf("loaded checkpoint does not match: %#v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint mode = %#o", info.Mode().Perm())
	}
}

func TestRemovalCheckpointAcceptsCurrent40HexWorkerDomainID(t *testing.T) {
	deployment := validDeployment()
	deployment.ManagedDomain = &ManagedDomain{
		DomainID:             "cccccccccccccccccccccccccccccccccccccccc",
		InitialCertificateID: "9fdf92c8-64c2-4a3d-b1af-e15304961145",
		CertificatePackID:    "dddddddddddddddddddddddddddddddd",
	}
	checkpoint, err := NewRemovalCheckpoint(
		deployment,
		[]string{deployment.ManagedDomain.DomainID},
		[]string{deployment.ManagedDomain.CertificatePackID},
	)
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.DomainID != deployment.ManagedDomain.DomainID {
		t.Fatalf("checkpoint Domain ID = %q", checkpoint.DomainID)
	}
}

func TestRemovalCheckpointRejectsAmbiguousAndMismatchedState(t *testing.T) {
	deployment := validDeployment()
	if _, err := NewRemovalCheckpoint(deployment, []string{"a", "b"}, nil); err == nil {
		t.Fatal("ambiguous domain IDs were accepted")
	}
	if _, err := NewRemovalCheckpoint(deployment, []string{"cccccccccccccccccccccccccccccccc"}, nil); err == nil {
		t.Fatal("incomplete resource IDs were accepted")
	}
	checkpoint, err := NewRemovalCheckpoint(deployment, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := deployment
	changed.Hostname = "other.example.com"
	if checkpoint.Matches(changed) {
		t.Fatal("checkpoint matched changed deployment")
	}
}

func TestLoadRemovalCheckpointRejectsUnknownDuplicateAndInsecureJSON(t *testing.T) {
	deployment := validDeployment()
	checkpoint, err := NewRemovalCheckpoint(deployment, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(directory, "removal.pending.json")
	if err := SaveRemovalCheckpointNew(path, &checkpoint); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(data), "\n}", ",\n  \"unexpected\": true\n}", 1)
	if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRemovalCheckpoint(path); err == nil {
		t.Fatal("unknown checkpoint field was accepted")
	}
	duplicate := strings.Replace(string(data), "\"version\": 1", "\"version\": 1, \"version\": 1", 1)
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRemovalCheckpoint(path); err == nil {
		t.Fatal("duplicate checkpoint field was accepted")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRemovalCheckpoint(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("insecure checkpoint error = %v", err)
	}
}

func TestLoadRemovalCheckpointRejectsGroupAccessibleStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions are not available on Windows")
	}
	checkpoint, err := NewRemovalCheckpoint(validDeployment(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(directory, "removal.pending.json")
	if err := SaveRemovalCheckpointNew(path, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRemovalCheckpoint(path); !errors.Is(err, ErrInsecureDirectoryPermissions) {
		t.Fatalf("checkpoint directory error = %v, want ErrInsecureDirectoryPermissions", err)
	}
}
