package clientformats

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"image/gif"
	"image/png"
	"io"
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

func TestSingBoxQRCodeGIFRoundTripsOfficialQRSProfile(t *testing.T) {
	cfg := deployment()
	encoded, err := SingBoxQRCodeGIF(cfg)
	if err != nil {
		t.Fatalf("SingBoxQRCodeGIF() error = %v", err)
	}
	animation, err := gif.DecodeAll(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("gif.DecodeAll() error = %v", err)
	}
	if len(animation.Image) < 2 || len(animation.Image) != len(animation.Delay) {
		t.Fatalf("sing-box QRS frame count = %d, delays = %d", len(animation.Image), len(animation.Delay))
	}
	if animation.LoopCount != 0 {
		t.Fatalf("sing-box QRS loop count = %d, want continuous", animation.LoopCount)
	}
	for index, frame := range animation.Image {
		if frame.Bounds().Dx() < 700 || frame.Bounds().Dx()%singBoxQRModuleSize != 0 || frame.Bounds().Dy() != frame.Bounds().Dx() {
			t.Fatalf("sing-box QRS frame %d bounds = %v", index, frame.Bounds())
		}
		if animation.Delay[index] != qrsFrameDelay {
			t.Fatalf("sing-box QRS frame %d delay = %d", index, animation.Delay[index])
		}
	}

	want, err := SingBoxJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	name, got := decodeSingBoxQRS(t, animation)
	if name != cfg.DisplayName {
		t.Fatalf("sing-box QRS profile name = %q, want %q", name, cfg.DisplayName)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("sing-box QRS profile does not contain the generated configuration")
	}
}

func TestSingBoxQRCodeGIFRoundTripsMaximumValidatedProfile(t *testing.T) {
	cfg := deployment()
	cfg.DisplayName = strings.Repeat("x", 256)
	cfg.Credentials.Current.Path = "/" + strings.Repeat("p", 128)
	encoded, err := SingBoxQRCodeGIF(cfg)
	if err != nil {
		t.Fatalf("SingBoxQRCodeGIF() error = %v", err)
	}
	animation, err := gif.DecodeAll(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	name, got := decodeSingBoxQRS(t, animation)
	want, err := SingBoxJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if name != cfg.DisplayName || !bytes.Equal(got, want) {
		t.Fatal("maximum sing-box QRS profile did not round trip")
	}
}

func decodeSingBoxQRS(t *testing.T, animation *gif.GIF) (string, []byte) {
	t.Helper()
	var blockCount, compressedSize int
	var checksum uint32
	var blocks [][]byte
	for frameIndex, frame := range animation.Image {
		decoded, err := goqr.Recognize(frame)
		if err != nil || len(decoded) != 1 {
			t.Fatalf("decode sing-box QRS frame %d = %d results, %v", frameIndex, len(decoded), err)
		}
		content := string(decoded[0].Payload)
		if !strings.HasPrefix(content, qrsURLPrefix) {
			t.Fatalf("sing-box QRS frame %d is not an official QRS URL", frameIndex)
		}
		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(content, qrsURLPrefix))
		if err != nil {
			t.Fatalf("decode QRS frame %d base64: %v", frameIndex, err)
		}
		if len(payload) != 20+qrsSliceSize || binary.LittleEndian.Uint32(payload[0:4]) != 1 {
			t.Fatalf("sing-box QRS frame %d has an invalid degree or size", frameIndex)
		}
		index := int(binary.LittleEndian.Uint32(payload[4:8]))
		currentBlockCount := int(binary.LittleEndian.Uint32(payload[8:12]))
		currentCompressedSize := int(binary.LittleEndian.Uint32(payload[12:16]))
		currentChecksum := binary.LittleEndian.Uint32(payload[16:20])
		if frameIndex == 0 {
			blockCount = currentBlockCount
			compressedSize = currentCompressedSize
			checksum = currentChecksum
			blocks = make([][]byte, blockCount)
		}
		if currentBlockCount != blockCount || currentCompressedSize != compressedSize || currentChecksum != checksum || index < 0 || index >= blockCount || blocks[index] != nil {
			t.Fatalf("sing-box QRS frame %d has inconsistent metadata", frameIndex)
		}
		blocks[index] = append([]byte(nil), payload[20:]...)
	}
	if len(blocks) != len(animation.Image) {
		t.Fatalf("QRS block count = %d, frames = %d", len(blocks), len(animation.Image))
	}
	compressed := make([]byte, 0, len(blocks)*qrsSliceSize)
	for index, block := range blocks {
		if block == nil {
			t.Fatalf("QRS block %d is missing", index)
		}
		compressed = append(compressed, block...)
	}
	if compressedSize <= 0 || compressedSize > len(compressed) {
		t.Fatalf("QRS compressed size = %d, available = %d", compressedSize, len(compressed))
	}
	zReader, err := zlib.NewReader(bytes.NewReader(compressed[:compressedSize]))
	if err != nil {
		t.Fatalf("open QRS zlib stream: %v", err)
	}
	wrapper, err := io.ReadAll(zReader)
	if err != nil {
		t.Fatalf("read QRS zlib stream: %v", err)
	}
	if err := zReader.Close(); err != nil {
		t.Fatalf("close QRS zlib stream: %v", err)
	}
	if want := crc32.ChecksumIEEE(wrapper) ^ uint32(blockCount); checksum != want {
		t.Fatalf("QRS checksum = %08x, want %08x", checksum, want)
	}

	if len(wrapper) < 8 {
		t.Fatal("QRS file wrapper is truncated")
	}
	metadataSize := int(binary.BigEndian.Uint32(wrapper[0:4]))
	if metadataSize > len(wrapper)-8 {
		t.Fatal("QRS metadata length is invalid")
	}
	var metadata struct {
		Filename    string `json:"filename"`
		ContentType string `json:"contentType"`
	}
	if err := json.Unmarshal(wrapper[4:4+metadataSize], &metadata); err != nil {
		t.Fatalf("decode QRS metadata: %v", err)
	}
	if metadata.Filename != "sing-box.bpf" || metadata.ContentType != "application/octet-stream" {
		t.Fatalf("unexpected QRS metadata: %#v", metadata)
	}
	offset := 4 + metadataSize
	profileSize := int(binary.BigEndian.Uint32(wrapper[offset : offset+4]))
	profile := wrapper[offset+4:]
	if profileSize != len(profile) {
		t.Fatalf("QRS profile size = %d, actual = %d", profileSize, len(profile))
	}
	return decodeSingBoxProfile(t, profile)
}

func decodeSingBoxProfile(t *testing.T, profile []byte) (string, []byte) {
	t.Helper()
	if len(profile) < 2 || profile[0] != 3 || profile[1] != 1 {
		t.Fatal("invalid libbox profile header")
	}
	gReader, err := gzip.NewReader(bytes.NewReader(profile[2:]))
	if err != nil {
		t.Fatalf("open libbox profile: %v", err)
	}
	content, err := io.ReadAll(gReader)
	if err != nil {
		t.Fatalf("read libbox profile: %v", err)
	}
	if err := gReader.Close(); err != nil {
		t.Fatalf("close libbox profile: %v", err)
	}
	reader := bytes.NewReader(content)
	nameSize, err := binary.ReadUvarint(reader)
	if err != nil {
		t.Fatalf("read libbox profile name size: %v", err)
	}
	name := make([]byte, nameSize)
	if _, err := io.ReadFull(reader, name); err != nil {
		t.Fatalf("read libbox profile name: %v", err)
	}
	var profileType int32
	if err := binary.Read(reader, binary.BigEndian, &profileType); err != nil || profileType != 0 {
		t.Fatalf("libbox profile type = %d, error = %v", profileType, err)
	}
	configSize, err := binary.ReadUvarint(reader)
	if err != nil {
		t.Fatalf("read libbox config size: %v", err)
	}
	configuration := make([]byte, configSize)
	if _, err := io.ReadFull(reader, configuration); err != nil {
		t.Fatalf("read libbox config: %v", err)
	}
	if reader.Len() != 0 {
		t.Fatalf("libbox profile has %d trailing bytes", reader.Len())
	}
	return string(name), configuration
}
