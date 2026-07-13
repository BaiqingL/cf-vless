// Package clientintegration prepares and runs unmodified proxy clients for
// end-to-end testing against a deployed Worker endpoint.
package clientintegration

import (
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BaiqingL/cf-vless/internal/clientformats"
	"github.com/BaiqingL/cf-vless/internal/config"
)

type Name string

const (
	Xray    Name = "xray"
	SingBox Name = "sing-box"
	Mihomo  Name = "mihomo"
)

var allClients = []Name{Xray, SingBox, Mihomo}

func ParseSelection(value string) ([]Name, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "all" {
		return append([]Name(nil), allClients...), nil
	}
	if value == "" {
		return nil, errors.New("client selection is required")
	}
	parts := strings.Split(value, ",")
	selection := make([]Name, 0, len(parts))
	seen := make(map[Name]struct{}, len(parts))
	for _, part := range parts {
		name := Name(strings.TrimSpace(part))
		if !name.Valid() || name == Name("all") {
			return nil, errors.New("client selection is invalid")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.New("client selection contains a duplicate")
		}
		seen[name] = struct{}{}
		selection = append(selection, name)
	}
	return selection, nil
}

func (name Name) Valid() bool {
	return name == Xray || name == SingBox || name == Mihomo
}

func (name Name) DefaultBinary() string {
	switch name {
	case Xray:
		return "xray"
	case SingBox:
		return "sing-box"
	case Mihomo:
		return "mihomo"
	default:
		return ""
	}
}

// LocateBinary resolves an explicit path/name or the client's conventional
// executable name. It never downloads or modifies a client installation.
func LocateBinary(name Name, requested string) (string, error) {
	if !name.Valid() {
		return "", errors.New("client name is invalid")
	}
	candidate := requested
	if candidate == "" {
		candidate = name.DefaultBinary()
	}
	path, err := exec.LookPath(candidate)
	if err != nil {
		return "", errors.New("client binary is unavailable")
	}
	return path, nil
}

type Spec struct {
	Name             Name
	Binary           string
	ConfigPath       string
	WorkingDirectory string
	SOCKSAddress     string
	CheckArgs        []string
	RunArgs          []string
	VersionArgs      []string
}

// Prepare creates one private client configuration in directory. The supplied
// deployment has already passed config.Load's strict 0600 validation.
func Prepare(name Name, binary, directory string, deployment *config.Deployment, socksPort uint16) (Spec, error) {
	if !name.Valid() || binary == "" || deployment == nil || socksPort == 0 {
		return Spec{}, errors.New("client preparation input is invalid")
	}
	if err := deployment.Validate(); err != nil {
		return Spec{}, err
	}
	if err := config.EnsureSecretDirectory(directory); err != nil {
		return Spec{}, errors.New("create private client directory")
	}
	specification := Spec{
		Name:             name,
		Binary:           binary,
		WorkingDirectory: directory,
		SOCKSAddress:     net.JoinHostPort("127.0.0.1", strconv.Itoa(int(socksPort))),
	}
	switch name {
	case Xray:
		specification.ConfigPath = filepath.Join(directory, "xray.json")
		encoded, err := clientformats.XrayJSONWithLocalPort(*deployment, socksPort)
		if err != nil {
			return Spec{}, err
		}
		if err := config.WriteSecretFile(specification.ConfigPath, encoded, false); err != nil {
			return Spec{}, err
		}
		specification.CheckArgs = []string{"run", "-test", "-format=json", "-c", specification.ConfigPath}
		specification.RunArgs = []string{"run", "-format=json", "-c", specification.ConfigPath}
		specification.VersionArgs = []string{"version"}
	case SingBox:
		specification.ConfigPath = filepath.Join(directory, "sing-box.json")
		encoded, err := clientformats.SingBoxJSONWithLocalPort(*deployment, socksPort)
		if err != nil {
			return Spec{}, err
		}
		if err := config.WriteSecretFile(specification.ConfigPath, encoded, false); err != nil {
			return Spec{}, errors.New("write sing-box client config")
		}
		specification.CheckArgs = []string{"check", "-c", specification.ConfigPath}
		specification.RunArgs = []string{"run", "-c", specification.ConfigPath}
		specification.VersionArgs = []string{"version"}
	case Mihomo:
		specification.ConfigPath = filepath.Join(directory, "mihomo.yaml")
		encoded, err := clientformats.MihomoYAMLWithLocalPort(*deployment, socksPort)
		if err != nil {
			return Spec{}, err
		}
		if err := config.WriteSecretFile(specification.ConfigPath, encoded, false); err != nil {
			return Spec{}, errors.New("write Mihomo client config")
		}
		specification.CheckArgs = []string{"-t", "-d", directory, "-f", specification.ConfigPath}
		specification.RunArgs = []string{"-d", directory, "-f", specification.ConfigPath}
		specification.VersionArgs = []string{"-v"}
	}
	return specification, nil
}
