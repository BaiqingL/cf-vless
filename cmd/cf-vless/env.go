package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	globalAPIKeyVariable = "CLOUDFLARE_GLOBAL_TOKEN"
	maximumDotEnvSize    = 16 << 10
)

// loadGlobalAPIKey reads only the one credential needed for the narrow
// certificate-pack fallback. It deliberately does not source the file or put
// its contents in the process environment, so builds and subprocesses cannot
// inherit the Global API Key.
func loadGlobalAPIKey(projectRoot string) ([]byte, error) {
	path := filepath.Join(projectRoot, ".env")
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect .env: %w", err)
	}
	if err := validateDotEnvFile(before); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open .env: %w", err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened .env: %w", err)
	}
	if !os.SameFile(before, after) {
		return nil, errors.New(".env changed while it was being opened")
	}
	if err := validateDotEnvFile(after); err != nil {
		return nil, err
	}

	contents, err := io.ReadAll(io.LimitReader(file, maximumDotEnvSize+1))
	if err != nil {
		return nil, fmt.Errorf("read .env: %w", err)
	}
	if len(contents) > maximumDotEnvSize {
		zeroBytes(contents)
		return nil, errors.New(".env exceeds the safe size bound")
	}
	defer zeroBytes(contents)
	return parseGlobalAPIKey(contents)
}

func validateDotEnvFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New(".env must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm() != 0o600 {
		return errors.New(".env must have owner-only mode 0600")
	}
	if info.Size() > maximumDotEnvSize {
		return errors.New(".env exceeds the safe size bound")
	}
	return nil
}

func parseGlobalAPIKey(contents []byte) ([]byte, error) {
	var found []byte
	for _, rawLine := range bytes.Split(contents, []byte{'\n'}) {
		line := strings.TrimSpace(strings.TrimSuffix(string(rawLine), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, present := strings.Cut(line, "=")
		if !present || strings.TrimSpace(name) != globalAPIKeyVariable {
			continue
		}
		if found != nil {
			zeroBytes(found)
			return nil, errors.New(".env contains duplicate Cloudflare Global API Key entries")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') ||
			(value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		if value == "" {
			return nil, errors.New(".env Cloudflare Global API Key is empty")
		}
		for _, character := range value {
			if unicode.IsControl(character) || unicode.IsSpace(character) {
				return nil, errors.New(".env Cloudflare Global API Key contains invalid whitespace")
			}
		}
		found = []byte(value)
	}
	return found, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
