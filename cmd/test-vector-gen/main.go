// Command test-vector-gen emits deterministic, sanitized VLESS v0 TCP
// request/response fixtures for conformance tests.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BaiqingL/cf-vless/internal/testvectors"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("test-vector-gen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "-", "write fixture JSON to this path, or - for stdout")
	check := flags.String("check", "", "fail unless this file exactly matches generated output")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || (*check != "" && *output != "-") {
		fmt.Fprintln(stderr, "invalid arguments")
		return 2
	}
	encoded, err := testvectors.Marshal()
	if err != nil {
		fmt.Fprintln(stderr, "fixture generation failed")
		return 1
	}
	if *check != "" {
		current, err := os.ReadFile(*check)
		if err != nil || !bytes.Equal(current, encoded) {
			fmt.Fprintln(stderr, "fixture file is missing or stale")
			return 1
		}
		return 0
	}
	if *output == "-" {
		if _, err := stdout.Write(encoded); err != nil {
			fmt.Fprintln(stderr, "write fixture output failed")
			return 1
		}
		return 0
	}
	if err := atomicWrite(*output, encoded); err != nil {
		fmt.Fprintln(stderr, "write fixture file failed")
		return 1
	}
	return 0
}

func atomicWrite(path string, content []byte) (returnErr error) {
	if path == "" {
		return errors.New("output path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".vless-fixtures-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			if err := temporary.Close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close temporary fixture: %w", err))
			}
		}
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary fixture: %w", err))
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	return os.Rename(temporaryPath, path)
}
