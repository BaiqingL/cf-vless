package clientformats

import (
	"errors"

	"github.com/BaiqingL/cf-vless/internal/config"
	qrcode "github.com/skip2/go-qrcode"
)

const qrCodePixels = 512

// QRCodePNG renders the exact UTF-8 VLESS URI as a QR code. The PNG contains
// the current UUID bearer credential and must be handled like every other
// generated client secret.
func QRCodePNG(deployment config.Deployment) ([]byte, error) {
	uri, err := VLESSURI(deployment)
	if err != nil {
		return nil, err
	}
	encoded, err := qrcode.Encode(uri, qrcode.Medium, qrCodePixels)
	if err != nil {
		return nil, errors.New("encode VLESS QR code")
	}
	return encoded, nil
}
