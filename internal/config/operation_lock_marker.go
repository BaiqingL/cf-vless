//go:build aix || solaris || windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrOperationInProgress = errors.New("another cf-vless operation is already in progress")

// OperationLock uses an exclusive marker on platforms without syscall.Flock.
// If a process is killed, the operator must remove operation.lock after
// confirming that no command remains.
type OperationLock struct {
	file *os.File
	path string
}

func AcquireOperationLock(directory string) (*OperationLock, error) {
	if err := EnsureSecretDirectory(directory); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "operation.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, ErrOperationInProgress
	}
	if err != nil {
		return nil, fmt.Errorf("create operation lock: %w", err)
	}
	return &OperationLock{file: file, path: path}, nil
}

func (lock *OperationLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	closeErr := file.Close()
	removeErr := os.Remove(lock.path)
	if closeErr != nil {
		closeErr = fmt.Errorf("close operation lock: %w", closeErr)
	}
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		removeErr = fmt.Errorf("remove operation lock: %w", removeErr)
	} else {
		removeErr = nil
	}
	return errors.Join(closeErr, removeErr)
}
