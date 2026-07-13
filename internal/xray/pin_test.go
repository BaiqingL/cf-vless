package xray

import (
	"testing"

	"github.com/BaiqingL/cf-vless/internal/testvectors"
)

func TestFixtureAndBuilderPinsMatch(t *testing.T) {
	t.Parallel()
	if testvectors.XrayCommit != PinnedCommit || testvectors.XrayTag != PinnedTag {
		t.Fatalf("fixture pin %s/%s differs from builder pin %s/%s", testvectors.XrayCommit, testvectors.XrayTag, PinnedCommit, PinnedTag)
	}
}
