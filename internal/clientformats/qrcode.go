package clientformats

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"image"
	"image/gif"

	"github.com/BaiqingL/cf-vless/internal/config"
	qrcode "github.com/skip2/go-qrcode"
)

const (
	qrCodePixels        = 512
	singBoxQRModuleSize = 8
	qrsURLPrefix        = "https://qrss.netlify.app/#"
	qrsSliceSize        = 500
	qrsFrameDelay       = 10 // hundredths of a second (10 FPS)
)

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

// SingBoxQRCodeGIF renders an animated QRS profile for the official sing-box
// clients. Unlike a normal QR containing raw JSON, QRS is understood by the
// clients' profile scanner and carries the complete local TUN configuration.
func SingBoxQRCodeGIF(deployment config.Deployment) ([]byte, error) {
	singBox, err := SingBoxJSON(deployment)
	if err != nil {
		return nil, err
	}
	return singBoxQRCodeGIF(deployment.DisplayName, singBox)
}

func singBoxQRCodeGIF(displayName string, singBoxJSON []byte) ([]byte, error) {
	profile, err := encodeSingBoxProfile(displayName, singBoxJSON)
	if err != nil {
		return nil, err
	}
	wrapper, err := wrapQRSFile(profile)
	if err != nil {
		return nil, err
	}

	var compressed bytes.Buffer
	zWriter := zlib.NewWriter(&compressed)
	if _, err := zWriter.Write(wrapper); err != nil {
		return nil, errors.New("compress sing-box QRS profile")
	}
	if err := zWriter.Close(); err != nil {
		return nil, errors.New("finish sing-box QRS profile compression")
	}
	if compressed.Len() == 0 {
		return nil, errors.New("sing-box QRS profile compression returned no data")
	}

	// Degree-one source blocks form a deterministic fountain-code stream. The
	// animation loops, so a scanner that misses a frame can collect it on the
	// next pass. The official header is little-endian: degree, indices, block
	// count, compressed byte count, checksum, then block data.
	compressedData := compressed.Bytes()
	blockCount := (len(compressedData) + qrsSliceSize - 1) / qrsSliceSize
	checksum := crc32.ChecksumIEEE(wrapper) ^ uint32(blockCount)
	animation := &gif.GIF{LoopCount: 0}
	for index := 0; index < blockCount; index++ {
		block := make([]byte, qrsSliceSize)
		start := index * qrsSliceSize
		copy(block, compressedData[start:min(start+qrsSliceSize, len(compressedData))])
		payload := make([]byte, 20+len(block))
		binary.LittleEndian.PutUint32(payload[0:4], 1)
		binary.LittleEndian.PutUint32(payload[4:8], uint32(index))
		binary.LittleEndian.PutUint32(payload[8:12], uint32(blockCount))
		binary.LittleEndian.PutUint32(payload[12:16], uint32(len(compressedData)))
		binary.LittleEndian.PutUint32(payload[16:20], checksum)
		copy(payload[20:], block)

		content := qrsURLPrefix + base64.StdEncoding.EncodeToString(payload)
		code, err := qrcode.New(content, qrcode.Low)
		if err != nil {
			return nil, errors.New("encode sing-box QRS frame")
		}
		frame, ok := code.Image(-singBoxQRModuleSize).(*image.Paletted)
		if !ok {
			return nil, errors.New("render sing-box QRS frame")
		}
		animation.Image = append(animation.Image, frame)
		animation.Delay = append(animation.Delay, qrsFrameDelay)
	}
	var encoded bytes.Buffer
	if err := gif.EncodeAll(&encoded, animation); err != nil {
		return nil, errors.New("encode sing-box QRS animation")
	}
	return encoded.Bytes(), nil
}

func encodeSingBoxProfile(displayName string, singBoxJSON []byte) ([]byte, error) {
	var profile bytes.Buffer
	profile.WriteByte(3) // libbox MessageTypeProfileContent
	profile.WriteByte(1) // profile format version
	gWriter := gzip.NewWriter(&profile)
	if err := writeProfileString(gWriter, displayName); err != nil {
		return nil, err
	}
	if err := binary.Write(gWriter, binary.BigEndian, int32(0)); err != nil { // ProfileTypeLocal
		return nil, errors.New("encode sing-box profile type")
	}
	if err := writeProfileString(gWriter, string(singBoxJSON)); err != nil {
		return nil, err
	}
	if err := gWriter.Close(); err != nil {
		return nil, errors.New("finish sing-box profile compression")
	}
	return profile.Bytes(), nil
}

func writeProfileString(writer *gzip.Writer, value string) error {
	var length [binary.MaxVarintLen64]byte
	count := binary.PutUvarint(length[:], uint64(len(value)))
	if _, err := writer.Write(length[:count]); err != nil {
		return errors.New("encode sing-box profile string length")
	}
	if _, err := writer.Write([]byte(value)); err != nil {
		return errors.New("encode sing-box profile string")
	}
	return nil
}

func wrapQRSFile(profile []byte) ([]byte, error) {
	metadata, err := json.Marshal(struct {
		Filename    string `json:"filename"`
		ContentType string `json:"contentType"`
	}{
		Filename:    "sing-box.bpf",
		ContentType: "application/octet-stream",
	})
	if err != nil {
		return nil, errors.New("encode sing-box QRS metadata")
	}
	wrapped := make([]byte, 8+len(metadata)+len(profile))
	binary.BigEndian.PutUint32(wrapped[0:4], uint32(len(metadata)))
	copy(wrapped[4:], metadata)
	offset := 4 + len(metadata)
	binary.BigEndian.PutUint32(wrapped[offset:offset+4], uint32(len(profile)))
	copy(wrapped[offset+4:], profile)
	return wrapped, nil
}
