package clientformats

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BaiqingL/cf-vless/internal/config"
)

var artifactNames = []string{"vless.txt", "vless.png", "xray.json", "sing-box.json", "mihomo.yaml"}

// WriteArtifacts renders and promotes all five credential-bearing artifacts as
// one directory generation. A crash can leave a private staging/backup
// directory, but never a target directory containing mixed credentials.
func WriteArtifacts(directory string, deployment config.Deployment, overwrite bool) error {
	outputs, err := Generate(deployment)
	if err != nil {
		return err
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return errors.New("resolve client artifact directory")
	}
	parent := filepath.Dir(directory)
	base := filepath.Base(directory)
	if base == "." || base == string(filepath.Separator) || directory == parent {
		return errors.New("client artifact directory is invalid")
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("client artifact parent directory is unavailable")
	}

	targetExists := false
	if info, inspectErr := os.Lstat(directory); inspectErr == nil {
		targetExists = true
		if !overwrite {
			return config.ErrFileExists
		}
		if err := validateArtifactDirectory(directory, info); err != nil {
			return err
		}
	} else if !errors.Is(inspectErr, os.ErrNotExist) {
		return fmt.Errorf("inspect client artifact directory: %w", inspectErr)
	}

	stage, err := os.MkdirTemp(parent, "."+base+".stage-*")
	if err != nil {
		return errors.New("create client artifact staging directory")
	}
	stageActive := true
	defer func() {
		if stageActive {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, 0o700); err != nil {
		return errors.New("protect client artifact staging directory")
	}
	files := map[string][]byte{
		"vless.txt":     append([]byte(outputs.VLESSURI), '\n'),
		"vless.png":     outputs.QRCodePNG,
		"xray.json":     outputs.XrayJSON,
		"sing-box.json": outputs.SingBoxJSON,
		"mihomo.yaml":   outputs.MihomoYAML,
	}
	for _, name := range artifactNames {
		if err := config.WriteSecretFile(filepath.Join(stage, name), files[name], false); err != nil {
			return fmt.Errorf("write staged client artifact %s: %w", name, err)
		}
	}

	if !targetExists {
		if err := os.Rename(stage, directory); err != nil {
			return errors.New("promote client artifact generation")
		}
		stageActive = false
		return syncArtifactParent(parent)
	}

	backup, err := os.MkdirTemp(parent, "."+base+".backup-*")
	if err != nil {
		return errors.New("reserve client artifact backup path")
	}
	if err := os.Remove(backup); err != nil {
		return errors.New("prepare client artifact backup path")
	}
	if err := os.Rename(directory, backup); err != nil {
		return errors.New("backup prior client artifact generation")
	}
	if err := os.Rename(stage, directory); err != nil {
		_ = os.Rename(backup, directory)
		return errors.New("promote replacement client artifact generation")
	}
	stageActive = false
	if err := syncArtifactParent(parent); err != nil {
		return err
	}
	if err := os.RemoveAll(backup); err != nil {
		return errors.New("remove prior client artifact generation")
	}
	return syncArtifactParent(parent)
}

func validateArtifactDirectory(directory string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return config.ErrUnsafeFile
	}
	if info.Mode().Perm() != 0o700 {
		return config.ErrInsecureDirectoryPermissions
	}
	allowed := make(map[string]struct{}, len(artifactNames))
	for _, name := range artifactNames {
		allowed[name] = struct{}{}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("read existing client artifact directory")
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace a client directory containing unexpected entries")
		}
		entryInfo, err := entry.Info()
		if err != nil || !entryInfo.Mode().IsRegular() || entryInfo.Mode().Perm() != 0o600 {
			return config.ErrUnsafeFile
		}
	}
	return nil
}

func syncArtifactParent(parent string) error {
	file, err := os.Open(parent)
	if err != nil {
		return errors.New("open client artifact parent for sync")
	}
	defer func() { _ = file.Close() }()
	if err := file.Sync(); err != nil {
		return errors.New("sync client artifact parent")
	}
	return nil
}
