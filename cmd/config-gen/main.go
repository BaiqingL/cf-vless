// Command config-gen renders all supported client configurations from a
// canonical local deployment file.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/BaiqingL/cf-vless/internal/clientformats"
	"github.com/BaiqingL/cf-vless/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type operationLock interface {
	Release() error
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithOperationLock(args, stdout, stderr, func(directory string) (operationLock, error) {
		return config.AcquireOperationLock(directory)
	})
}

func runWithOperationLock(args []string, stdout, stderr io.Writer, acquireOperationLock func(string) (operationLock, error)) (exitCode int) {
	flags := flag.NewFlagSet("config-gen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: config-gen -config DEPLOYMENT.json [-out DIRECTORY] [-force]")
	}
	configPath := flags.String("config", "", "path to the canonical deployment file")
	outputDirectory := flags.String("out", "client-configs", "directory for generated client files")
	force := flags.Bool("force", false, "replace existing generated files")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return 0
	} else if err != nil {
		return 2
	}
	if *configPath == "" {
		fmt.Fprintln(stderr, "config-gen: -config is required")
		flags.Usage()
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "config-gen: unexpected positional arguments")
		flags.Usage()
		return 2
	}

	lock, err := acquireOperationLock(filepath.Dir(*configPath))
	if err != nil {
		fmt.Fprintf(stderr, "config-gen: lock deployment: %v\n", err)
		return 1
	}
	defer func() {
		if err := lock.Release(); err != nil {
			fmt.Fprintln(stderr, "config-gen: release operation lock failed")
			exitCode = 1
		}
	}()
	if err := config.RequireSettledCredentials(*configPath); err != nil {
		fmt.Fprintf(stderr, "config-gen: credential state: %v\n", err)
		return 1
	}
	deployment, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "config-gen: load deployment: %v\n", err)
		return 1
	}
	if err := clientformats.WriteArtifacts(*outputDirectory, *deployment, *force); err != nil {
		fmt.Fprintf(stderr, "config-gen: write client configurations: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "wrote 5 client configuration files to %s\n", *outputDirectory)
	return 0
}
