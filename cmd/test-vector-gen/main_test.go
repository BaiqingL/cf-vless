package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunWritesDeterministicFixtureJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["protocol"] != "VLESS v0 TCP" {
		t.Fatalf("protocol = %#v", document["protocol"])
	}
}

func TestRunWritesAndChecksFixtureFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixtures", "vless-v0.json")
	var stderr bytes.Buffer
	if code := run([]string{"--output", path}, ioDiscard{}, &stderr); code != 0 {
		t.Fatalf("write code=%d stderr=%q", code, stderr.String())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	stderr.Reset()
	if code := run([]string{"--check", path}, ioDiscard{}, &stderr); code != 0 {
		t.Fatalf("check code=%d stderr=%q", code, stderr.String())
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(content []byte) (int, error) { return len(content), nil }
