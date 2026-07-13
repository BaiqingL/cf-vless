//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCloseOperationLockAfterFailurePreservesBothErrors(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "operation-lock-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	closeErr := file.Close()
	if closeErr == nil {
		t.Fatal("closing an already closed file unexpectedly succeeded")
	}
	cause := errors.New("acquisition failed")
	combined := closeOperationLockAfterFailure(file, cause)
	if !errors.Is(combined, cause) || !strings.Contains(combined.Error(), "close operation lock after acquisition failure") {
		t.Fatalf("combined error = %v, want acquisition and close errors", combined)
	}
}
