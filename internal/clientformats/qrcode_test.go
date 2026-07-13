package clientformats

import (
	"bytes"
	"image/png"
	"strings"
	"testing"

	"github.com/liyue201/goqr"
)

func TestQRCodePNGIsASecretSizedPNG(t *testing.T) {
	cfg := deployment()
	encoded, err := QRCodePNG(cfg)
	if err != nil {
		t.Fatalf("QRCodePNG() error = %v", err)
	}
	image, err := png.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("png.Decode() error = %v", err)
	}
	if got := image.Bounds().Dx(); got != qrCodePixels {
		t.Fatalf("QR width = %d, want %d", got, qrCodePixels)
	}
	if got := image.Bounds().Dy(); got != qrCodePixels {
		t.Fatalf("QR height = %d, want %d", got, qrCodePixels)
	}
	if len(encoded) < 512 {
		t.Fatalf("QR PNG unexpectedly small: %d bytes", len(encoded))
	}
	want, err := VLESSURI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := goqr.Recognize(image)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("decode QR payload = %d results, %v", len(decoded), err)
	}
	if string(decoded[0].Payload) != want {
		t.Fatalf("QR payload does not equal the generated VLESS URI")
	}
}

func TestQRCodeRoundTripsMaximumValidatedPathAndDisplayName(t *testing.T) {
	cfg := deployment()
	cfg.DisplayName = strings.Repeat("x", 256)
	cfg.Credentials.Current.Path = "/" + strings.Repeat("p", 128)
	encoded, err := QRCodePNG(cfg)
	if err != nil {
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := goqr.Recognize(image)
	if err != nil || len(decoded) != 1 {
		t.Fatalf("decode maximum QR payload = %d results, %v", len(decoded), err)
	}
	want, err := VLESSURI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded[0].Payload) != want {
		t.Fatal("maximum QR payload did not round trip")
	}
}
