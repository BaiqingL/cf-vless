//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var ErrOperationInProgress = errors.New("another cf-vless operation is already in progress")

// OperationLock serializes credential-bearing operations across processes.
// The lock file remains in the private state directory; the kernel releases
// the advisory lock automatically if a process exits unexpectedly.
type OperationLock struct {
	file *os.File
}

func AcquireOperationLock(directory string) (*OperationLock, error) {
	if err := EnsureSecretDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "operation.lock")
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafeFile
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect operation lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open operation lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		return nil, closeOperationLockAfterFailure(file, fmt.Errorf("protect operation lock: %w", err))
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, closeOperationLockAfterFailure(file, ErrOperationInProgress)
		}
		return nil, closeOperationLockAfterFailure(file, fmt.Errorf("lock operation state: %w", err))
	}
	if err := file.Truncate(0); err == nil {
		_, _ = file.Seek(0, 0)
		_, _ = fmt.Fprintf(file, "pid=%d acquired=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
		_ = file.Sync()
	}
	return &OperationLock{file: file}, nil
}

func closeOperationLockAfterFailure(file *os.File, cause error) error {
	if err := file.Close(); err != nil {
		return errors.Join(cause, fmt.Errorf("close operation lock after acquisition failure: %w", err))
	}
	return cause
}

func (lock *OperationLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock operation state: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close operation lock: %w", closeErr)
	}
	return nil
}
