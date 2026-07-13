package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxConfigBytes = 64 << 10

var (
	// ErrFileExists is returned by non-overwriting secret-file writes.
	ErrFileExists = errors.New("file already exists")
	// ErrInsecurePermissions is returned when loading group- or world-accessible
	// deployment state.
	ErrInsecurePermissions = errors.New("file permissions must be 0600")
	// ErrInsecureDirectoryPermissions is returned when a secret-bearing
	// directory is accessible to group or other users.
	ErrInsecureDirectoryPermissions = errors.New("directory permissions must be 0700")
	// ErrUnsafeFile is returned for symlinks and non-regular files.
	ErrUnsafeFile = errors.New("refusing unsafe file")
	// ErrCredentialOperationPending is returned when a sibling pending
	// deployment exists. Credential consumers must not use the canonical state
	// until the resumable rotation has either completed or been reconciled.
	ErrCredentialOperationPending = errors.New("credential operation is pending")
)

const pendingDeploymentFilename = "deployment.pending.json"

// RequireSettledCredentials fails closed when the canonical deployment's
// private state directory contains a pending credential operation. Callers
// must hold the directory's OperationLock while checking and consuming the
// canonical deployment so a rotation cannot race the check.
func RequireSettledCredentials(deploymentPath string) error {
	directory := filepath.Dir(deploymentPath)
	if err := validateSecretDirectory(directory); err != nil {
		return err
	}
	pendingPath := filepath.Join(directory, pendingDeploymentFilename)
	if _, err := os.Lstat(pendingPath); err == nil {
		return fmt.Errorf("%w; resume cf-vless rotate before using or generating client credentials", ErrCredentialOperationPending)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pending credential state: %w", err)
	}
	return nil
}

// Load reads a strict, size-bounded JSON deployment from a regular 0600 file.
func Load(path string) (*Deployment, error) {
	if err := validateSecretDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect deployment file: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, ErrUnsafeFile
	}
	if before.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open deployment file: %w", err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened deployment file: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, ErrUnsafeFile
	}
	if after.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}

	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read deployment file: %w", err)
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("deployment file is too large")
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return nil, err
	}
	if err := validateExactDeploymentSchema(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Deployment
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode deployment file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("deployment file contains trailing JSON")
		}
		return nil, fmt.Errorf("decode deployment file trailer: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SaveNew creates a deployment file and refuses to overwrite any existing
// directory entry.
func SaveNew(path string, cfg *Deployment) error {
	data, err := marshal(cfg)
	if err != nil {
		return err
	}
	return WriteSecretFile(path, data, false)
}

// Save atomically replaces or creates a deployment file with mode 0600.
func Save(path string, cfg *Deployment) error {
	data, err := marshal(cfg)
	if err != nil {
		return err
	}
	return WriteSecretFile(path, data, true)
}

func marshal(cfg *Deployment) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("deployment is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, errors.New("encode deployment file")
	}
	return append(data, '\n'), nil
}

// WriteSecretFile writes secret-bearing bytes with mode 0600. When overwrite
// is true it uses a same-directory temporary file and atomic rename. It never
// follows an existing destination symlink.
func WriteSecretFile(path string, data []byte, overwrite bool) error {
	directory := filepath.Dir(path)
	if err := ensureSecretDirectory(directory); err != nil {
		return err
	}
	if overwrite {
		return replaceSecretFile(path, data)
	}
	return createSecretFile(path, data)
}

// EnsureSecretDirectory creates or validates an owner-only directory used for
// local deployment state and generated bearer credentials.
func EnsureSecretDirectory(directory string) error {
	return ensureSecretDirectory(directory)
}

func ensureSecretDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create secret directory: %w", err)
	}
	return validateSecretDirectory(directory)
}

func validateSecretDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect secret directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeFile
	}
	if info.Mode().Perm() != 0o700 {
		return ErrInsecureDirectoryPermissions
	}
	return nil
}

func rejectDuplicateJSONFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("decode deployment file: %w", err)
	}
	return nil
}

func validateExactDeploymentSchema(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("decode deployment file: %w", err)
	}
	if err := validateExactObject(root,
		[]string{"version", "worker_name", "account_id", "zone_id", "zone_name", "hostname", "port", "display_name", "allowed_ports", "deployment_marker", "credentials", "managed_domain"},
		[]string{"version", "worker_name", "zone_name", "hostname", "port", "display_name", "allowed_ports", "deployment_marker", "credentials"},
	); err != nil {
		return err
	}
	if managedRaw, present := root["managed_domain"]; present {
		var managed map[string]json.RawMessage
		if err := json.Unmarshal(managedRaw, &managed); err != nil {
			return errors.New("deployment file managed domain schema is invalid")
		}
		if err := validateExactObject(managed,
			[]string{"domain_id", "initial_certificate_id", "certificate_pack_id", "certificate_pack_baseline_ids", "certificate_pack_baseline_recorded"},
			[]string{"domain_id", "initial_certificate_id"},
		); err != nil {
			return err
		}
	}
	var credentials map[string]json.RawMessage
	if err := json.Unmarshal(root["credentials"], &credentials); err != nil {
		return errors.New("deployment file credentials schema is invalid")
	}
	if err := validateExactObject(credentials, []string{"current", "previous"}, []string{"current"}); err != nil {
		return err
	}
	var current map[string]json.RawMessage
	if err := json.Unmarshal(credentials["current"], &current); err != nil {
		return errors.New("deployment file current credential schema is invalid")
	}
	if err := validateExactObject(current, []string{"uuid", "path"}, []string{"uuid", "path"}); err != nil {
		return err
	}
	if previousRaw, present := credentials["previous"]; present {
		var previous map[string]json.RawMessage
		if err := json.Unmarshal(previousRaw, &previous); err != nil {
			return errors.New("deployment file previous credential schema is invalid")
		}
		if err := validateExactObject(previous, []string{"uuid", "path", "expires_at"}, []string{"uuid", "path", "expires_at"}); err != nil {
			return err
		}
	}
	return nil
}

func validateExactObject(object map[string]json.RawMessage, allowed, required []string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return errors.New("deployment file field names do not match the exact schema")
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return errors.New("deployment file is missing a required schema field")
		}
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("deployment file contains a duplicate JSON field")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func createSecretFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrFileExists
	}
	if err != nil {
		return fmt.Errorf("create secret file: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := writeAndSync(file, data); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close secret file: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	complete = true
	return nil
}

func replaceSecretFile(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return ErrUnsafeFile
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect secret file: %w", err)
	}

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary secret file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary secret file: %w", err)
	}
	if err := writeAndSync(temporary, data); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary secret file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace secret file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure secret file: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return nil
}

// RemoveSecretFile removes one regular file and durably syncs its parent.
func RemoveSecretFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect secret file for removal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeFile
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove secret file: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open secret directory for sync: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync secret directory: %w", err)
	}
	return nil
}

func writeAndSync(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write secret file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync secret file: %w", err)
	}
	return nil
}
