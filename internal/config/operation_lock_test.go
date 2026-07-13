package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOperationLockSerializesProcessesAndCanBeReacquired(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := AcquireOperationLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireOperationLock(directory); !errors.Is(err, ErrOperationInProgress) {
		t.Fatalf("second acquisition error = %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireOperationLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	info, err := os.Stat(filepath.Join(directory, "operation.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("operation lock mode = %#o", info.Mode().Perm())
	}
}
