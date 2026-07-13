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

const (
	removalCheckpointVersion  = 1
	maxRemovalCheckpointBytes = 16 << 10
)

// RemovalCheckpoint is the non-secret ownership proof saved before the first
// remote deletion. It lets a retry target the same generated certificate pack
// after Cloudflare has already removed the Custom Domain that exposed cert_id.
type RemovalCheckpoint struct {
	Version           int    `json:"version"`
	WorkerName        string `json:"worker_name"`
	OwnershipMarker   string `json:"deployment_marker"`
	Hostname          string `json:"hostname"`
	ZoneID            string `json:"zone_id"`
	ZoneName          string `json:"zone_name"`
	DomainID          string `json:"domain_id,omitempty"`
	CertificatePackID string `json:"certificate_pack_id,omitempty"`
}

func NewRemovalCheckpoint(deployment Deployment, domainIDs, certificatePackIDs []string) (RemovalCheckpoint, error) {
	if err := deployment.Validate(); err != nil {
		return RemovalCheckpoint{}, err
	}
	if len(domainIDs) > 1 || len(certificatePackIDs) > 1 {
		return RemovalCheckpoint{}, errors.New("removal plan contains ambiguous resource IDs")
	}
	checkpoint := RemovalCheckpoint{
		Version:         removalCheckpointVersion,
		WorkerName:      deployment.WorkerName,
		OwnershipMarker: deployment.OwnershipMarker,
		Hostname:        deployment.Hostname,
		ZoneID:          deployment.ZoneID,
		ZoneName:        deployment.ZoneName,
	}
	if len(domainIDs) == 1 {
		checkpoint.DomainID = domainIDs[0]
	}
	if len(certificatePackIDs) == 1 {
		checkpoint.CertificatePackID = certificatePackIDs[0]
	}
	if (checkpoint.DomainID == "") != (checkpoint.CertificatePackID == "") {
		return RemovalCheckpoint{}, errors.New("Custom Domain and certificate pack must be checkpointed together")
	}
	if err := checkpoint.Validate(); err != nil {
		return RemovalCheckpoint{}, err
	}
	return checkpoint, nil
}

func (checkpoint RemovalCheckpoint) Validate() error {
	if checkpoint.Version != removalCheckpointVersion {
		return fmt.Errorf("removal checkpoint version must be %d", removalCheckpointVersion)
	}
	if !workerNamePattern.MatchString(checkpoint.WorkerName) {
		return errors.New("removal checkpoint Worker name is invalid")
	}
	if !ownershipMarkerPattern.MatchString(checkpoint.OwnershipMarker) {
		return errors.New("removal checkpoint ownership marker is invalid")
	}
	if err := validateHostname(checkpoint.Hostname); err != nil {
		return errors.New("removal checkpoint hostname is invalid")
	}
	if err := validateHostname(checkpoint.ZoneName); err != nil {
		return errors.New("removal checkpoint zone name is invalid")
	}
	if checkpoint.Hostname == checkpoint.ZoneName || !bytes.HasSuffix([]byte(checkpoint.Hostname), []byte("."+checkpoint.ZoneName)) {
		return errors.New("removal checkpoint hostname is outside its zone")
	}
	if !cloudflareIDPattern.MatchString(checkpoint.ZoneID) {
		return errors.New("removal checkpoint zone ID is invalid")
	}
	if (checkpoint.DomainID == "") != (checkpoint.CertificatePackID == "") {
		return errors.New("removal checkpoint resource IDs are incomplete")
	}
	if checkpoint.DomainID != "" && !canonicalWorkerDomainIDPattern.MatchString(checkpoint.DomainID) {
		return errors.New("removal checkpoint domain ID is invalid")
	}
	if checkpoint.CertificatePackID != "" && !canonicalCertificatePackIDPattern.MatchString(checkpoint.CertificatePackID) {
		return errors.New("removal checkpoint certificate pack ID is invalid")
	}
	return nil
}

func (checkpoint RemovalCheckpoint) Matches(deployment Deployment) bool {
	return checkpoint.Version == removalCheckpointVersion &&
		checkpoint.WorkerName == deployment.WorkerName &&
		checkpoint.OwnershipMarker == deployment.OwnershipMarker &&
		checkpoint.Hostname == deployment.Hostname &&
		checkpoint.ZoneID == deployment.ZoneID &&
		checkpoint.ZoneName == deployment.ZoneName
}

func SaveRemovalCheckpointNew(path string, checkpoint *RemovalCheckpoint) error {
	data, err := marshalRemovalCheckpoint(checkpoint)
	if err != nil {
		return err
	}
	return WriteSecretFile(path, data, false)
}

func marshalRemovalCheckpoint(checkpoint *RemovalCheckpoint) ([]byte, error) {
	if checkpoint == nil {
		return nil, errors.New("removal checkpoint is required")
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		return nil, errors.New("encode removal checkpoint")
	}
	return append(data, '\n'), nil
}

// LoadRemovalCheckpoint applies the same regular-file, owner-only, bounded,
// duplicate-free JSON rules as canonical credential state.
func LoadRemovalCheckpoint(path string) (*RemovalCheckpoint, error) {
	if err := validateSecretDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect removal checkpoint: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafeFile
	}
	if before.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open removal checkpoint: %w", err)
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, ErrUnsafeFile
	}
	if after.Mode().Perm() != 0o600 {
		return nil, ErrInsecurePermissions
	}
	data, err := io.ReadAll(io.LimitReader(file, maxRemovalCheckpointBytes+1))
	if err != nil {
		return nil, errors.New("read removal checkpoint")
	}
	if len(data) > maxRemovalCheckpointBytes {
		return nil, errors.New("removal checkpoint is too large")
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, errors.New("decode removal checkpoint")
	}
	if err := validateExactObject(fields,
		[]string{"version", "worker_name", "deployment_marker", "hostname", "zone_id", "zone_name", "domain_id", "certificate_pack_id"},
		[]string{"version", "worker_name", "deployment_marker", "hostname", "zone_id", "zone_name"},
	); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var checkpoint RemovalCheckpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return nil, errors.New("decode removal checkpoint")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("removal checkpoint contains trailing JSON")
	}
	if err := checkpoint.Validate(); err != nil {
		return nil, err
	}
	return &checkpoint, nil
}
