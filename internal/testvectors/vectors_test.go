package testvectors

import (
	"encoding/hex"
	"testing"
)

func TestGenerateCanonicalVLESSV0TCPVectors(t *testing.T) {
	t.Parallel()

	suite, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if suite.UpstreamCommit != XrayCommit {
		t.Fatalf("commit = %q", suite.UpstreamCommit)
	}
	if suite.ResponseHeaderHex != "0000" {
		t.Fatalf("response = %q", suite.ResponseHeaderHex)
	}
	if len(suite.Cases) != 3 {
		t.Fatalf("cases = %d", len(suite.Cases))
	}

	wantHeaders := map[string]string{
		"domain": "0000112233445566778899aabbccddeeff000101bb020b6578616d706c652e636f6d",
		"ipv4":   "0000112233445566778899aabbccddeeff0001005001cb007107",
		"ipv6":   "0000112233445566778899aabbccddeeff000120fb0320010db8000000000000000000000001",
	}
	for _, vector := range suite.Cases {
		if vector.RequestHeaderHex != wantHeaders[vector.Name] {
			t.Errorf("%s header = %q", vector.Name, vector.RequestHeaderHex)
		}
		header, err := hex.DecodeString(vector.RequestHeaderHex)
		if err != nil {
			t.Fatalf("%s header hex: %v", vector.Name, err)
		}
		wire, err := hex.DecodeString(vector.WireHex)
		if err != nil {
			t.Fatalf("%s wire hex: %v", vector.Name, err)
		}
		if len(header) != vector.HeaderBytes {
			t.Errorf("%s header bytes = %d, want %d", vector.Name, vector.HeaderBytes, len(header))
		}
		for _, fragmentation := range vector.Fragmentations {
			total := 0
			for _, size := range fragmentation.ChunkSizes {
				if size <= 0 {
					t.Errorf("%s/%s has non-positive chunk", vector.Name, fragmentation.Name)
				}
				total += size
			}
			if total != len(wire) {
				t.Errorf("%s/%s covers %d bytes, want %d", vector.Name, fragmentation.Name, total, len(wire))
			}
		}
	}
}

func TestMarshalIsDeterministicAndEndsWithNewline(t *testing.T) {
	t.Parallel()

	first, err := Marshal()
	if err != nil {
		t.Fatal(err)
	}
	second, err := Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("fixture output is not deterministic")
	}
	if len(first) == 0 || first[len(first)-1] != '\n' {
		t.Fatal("fixture JSON must end with a newline")
	}
}
