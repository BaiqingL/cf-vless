package xray

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/BaiqingL/cf-vless/internal/testvectors"
)

const (
	maxReferenceUpgradeBytes = 16 * 1024
	maxReferenceFrameBytes   = 1024 * 1024
	maxReferenceHeaderBytes  = 512
	maxReferenceCaptures     = 16
)

type capturedVLESSHeader struct {
	header []byte
	err    error
}

// referenceWebSocketObserver consumes a copy of one client-to-server TCP
// stream. It removes the HTTP upgrade and WebSocket masking, then retains only
// the first complete VLESS request header. The observed credential,
// destination, and application payload are never written to disk.
type referenceWebSocketObserver struct {
	report       func(capturedVLESSHeader)
	buffer       []byte
	vlessBytes   []byte
	upgradeFound bool
	finished     bool
}

func (observer *referenceWebSocketObserver) Write(chunk []byte) (int, error) {
	if observer.finished {
		return len(chunk), nil
	}
	observer.buffer = append(observer.buffer, chunk...)
	observer.consume()
	// Observation must never interfere with the transparent proxy. Parse
	// failures are reported through report while the original bytes continue.
	return len(chunk), nil
}

func (observer *referenceWebSocketObserver) consume() {
	if !observer.upgradeFound {
		boundary := bytes.Index(observer.buffer, []byte("\r\n\r\n"))
		if boundary < 0 {
			if len(observer.buffer) > maxReferenceUpgradeBytes {
				observer.fail(errors.New("Xray client WebSocket upgrade exceeds capture limit"))
			}
			return
		}
		requestHeader := observer.buffer[:boundary+4]
		lowerHeader := bytes.ToLower(requestHeader)
		if !bytes.HasPrefix(requestHeader, []byte("GET ")) ||
			!bytes.Contains(lowerHeader, []byte("upgrade: websocket")) {
			observer.fail(errors.New("Xray client did not send a WebSocket upgrade"))
			return
		}
		observer.buffer = observer.buffer[boundary+4:]
		observer.upgradeFound = true
	}

	for !observer.finished {
		if len(observer.buffer) < 2 {
			return
		}
		first, second := observer.buffer[0], observer.buffer[1]
		if first&0x70 != 0 {
			observer.fail(errors.New("captured Xray WebSocket frame uses unsupported RSV bits"))
			return
		}
		opcode := first & 0x0f
		if second&0x80 == 0 {
			observer.fail(errors.New("captured client WebSocket frame is not masked"))
			return
		}
		payloadBytes := uint64(second & 0x7f)
		headerBytes := 2
		switch payloadBytes {
		case 126:
			if len(observer.buffer) < 4 {
				return
			}
			payloadBytes = uint64(binary.BigEndian.Uint16(observer.buffer[2:4]))
			headerBytes = 4
		case 127:
			if len(observer.buffer) < 10 {
				return
			}
			payloadBytes = binary.BigEndian.Uint64(observer.buffer[2:10])
			headerBytes = 10
		}
		if payloadBytes > maxReferenceFrameBytes {
			observer.fail(errors.New("captured Xray WebSocket frame exceeds capture limit"))
			return
		}
		frameBytes := headerBytes + 4 + int(payloadBytes)
		if len(observer.buffer) < frameBytes {
			return
		}
		mask := observer.buffer[headerBytes : headerBytes+4]
		payload := observer.buffer[headerBytes+4 : frameBytes]
		observer.buffer = observer.buffer[frameBytes:]

		if opcode != 0x0 && opcode != 0x2 {
			// Control frames do not contribute to the VLESS byte stream.
			if opcode&0x8 != 0 {
				continue
			}
			observer.fail(errors.New("captured Xray WebSocket data frame is not binary"))
			return
		}
		remaining := maxReferenceHeaderBytes - len(observer.vlessBytes)
		if remaining <= 0 {
			observer.fail(errors.New("captured VLESS request header exceeds capture limit"))
			return
		}
		if len(payload) < remaining {
			remaining = len(payload)
		}
		for index := 0; index < remaining; index++ {
			observer.vlessBytes = append(observer.vlessBytes, payload[index]^mask[index%4])
		}

		shape, complete, err := parseCapturedVLESSHeader(observer.vlessBytes)
		if err != nil {
			observer.fail(err)
			return
		}
		if complete {
			header := append([]byte(nil), observer.vlessBytes[:shape.headerBytes]...)
			observer.finished = true
			observer.buffer = nil
			observer.vlessBytes = nil
			observer.report(capturedVLESSHeader{header: header})
			return
		}
	}
}

func (observer *referenceWebSocketObserver) fail(err error) {
	observer.finished = true
	observer.buffer = nil
	observer.vlessBytes = nil
	observer.report(capturedVLESSHeader{err: err})
}

type capturedVLESSShape struct {
	headerBytes       int
	optionLength      int
	commandOffset     int
	portOffset        int
	addressTypeOffset int
	destinationOffset int
	destinationBytes  int
}

func parseCapturedVLESSHeader(header []byte) (capturedVLESSShape, bool, error) {
	if len(header) < 18 {
		return capturedVLESSShape{}, false, nil
	}
	optionLength := int(header[17])
	commandOffset := 18 + optionLength
	if commandOffset+4 > maxReferenceHeaderBytes {
		return capturedVLESSShape{}, false, errors.New("captured VLESS option length exceeds header limit")
	}
	if len(header) < commandOffset+4 {
		return capturedVLESSShape{}, false, nil
	}
	portOffset := commandOffset + 1
	addressTypeOffset := portOffset + 2
	destinationOffset := addressTypeOffset + 1
	destinationBytes := 0
	switch header[addressTypeOffset] {
	case 1:
		destinationBytes = 4
	case 2:
		if len(header) < destinationOffset+1 {
			return capturedVLESSShape{}, false, nil
		}
		destinationBytes = 1 + int(header[destinationOffset])
		if destinationBytes == 1 {
			return capturedVLESSShape{}, false, errors.New("captured VLESS domain is empty")
		}
	case 3:
		destinationBytes = 16
	default:
		return capturedVLESSShape{}, false, errors.New("captured VLESS address type is unsupported")
	}
	headerBytes := destinationOffset + destinationBytes
	if headerBytes > maxReferenceHeaderBytes {
		return capturedVLESSShape{}, false, errors.New("captured VLESS request header exceeds capture limit")
	}
	if len(header) < headerBytes {
		return capturedVLESSShape{}, false, nil
	}
	return capturedVLESSShape{
		headerBytes:       headerBytes,
		optionLength:      optionLength,
		commandOffset:     commandOffset,
		portOffset:        portOffset,
		addressTypeOffset: addressTypeOffset,
		destinationOffset: destinationOffset,
		destinationBytes:  destinationBytes,
	}, true, nil
}

// sanitizeCapturedVLESSHeader replaces every credential and destination byte
// with its canonical fixture counterpart after verifying that all structural
// fields have the same shape. Callers must not log the unsanitized input.
func sanitizeCapturedVLESSHeader(captured, canonical []byte) ([]byte, error) {
	capturedShape, capturedComplete, err := parseCapturedVLESSHeader(captured)
	if err != nil || !capturedComplete || capturedShape.headerBytes != len(captured) {
		return nil, errors.New("captured VLESS request is not one complete header")
	}
	canonicalShape, canonicalComplete, err := parseCapturedVLESSHeader(canonical)
	if err != nil || !canonicalComplete || canonicalShape.headerBytes != len(canonical) {
		return nil, errors.New("canonical VLESS fixture is not one complete header")
	}
	if capturedShape.headerBytes != canonicalShape.headerBytes ||
		capturedShape.optionLength != canonicalShape.optionLength ||
		capturedShape.commandOffset != canonicalShape.commandOffset ||
		capturedShape.addressTypeOffset != canonicalShape.addressTypeOffset ||
		capturedShape.destinationBytes != canonicalShape.destinationBytes ||
		captured[0] != canonical[0] ||
		captured[capturedShape.commandOffset] != canonical[canonicalShape.commandOffset] ||
		captured[capturedShape.addressTypeOffset] != canonical[canonicalShape.addressTypeOffset] ||
		!bytes.Equal(captured[18:capturedShape.commandOffset], canonical[18:canonicalShape.commandOffset]) {
		return nil, errors.New("captured VLESS request shape differs from canonical fixture")
	}

	sanitized := append([]byte(nil), captured...)
	copy(sanitized[1:17], canonical[1:17])
	copy(sanitized[capturedShape.portOffset:capturedShape.portOffset+2], canonical[canonicalShape.portOffset:canonicalShape.portOffset+2])
	copy(sanitized[capturedShape.destinationOffset:capturedShape.headerBytes], canonical[canonicalShape.destinationOffset:canonicalShape.headerBytes])
	return sanitized, nil
}

type loopbackCaptureProxy struct {
	listener net.Listener
	target   string
	result   chan capturedVLESSHeader
	wait     sync.WaitGroup
}

func newLoopbackCaptureProxy(target string) (*loopbackCaptureProxy, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	proxy := &loopbackCaptureProxy{
		listener: listener,
		target:   target,
		result:   make(chan capturedVLESSHeader, maxReferenceCaptures),
	}
	proxy.wait.Add(1)
	go proxy.accept()
	return proxy, nil
}

func (proxy *loopbackCaptureProxy) Port() uint16 {
	return uint16(proxy.listener.Addr().(*net.TCPAddr).Port)
}

func (proxy *loopbackCaptureProxy) Await(ctx context.Context) ([]byte, error) {
	select {
	case result := <-proxy.result:
		return result.header, result.err
	case <-ctx.Done():
		return nil, errors.New("timed out waiting for captured Xray VLESS header")
	}
}

func (proxy *loopbackCaptureProxy) Close() error {
	err := proxy.listener.Close()
	proxy.wait.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (proxy *loopbackCaptureProxy) accept() {
	defer proxy.wait.Done()
	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			return
		}
		proxy.wait.Add(1)
		go proxy.forward(client)
	}
}

func (proxy *loopbackCaptureProxy) forward(client net.Conn) {
	defer proxy.wait.Done()
	upstream, err := net.DialTimeout("tcp4", proxy.target, 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	observer := &referenceWebSocketObserver{report: proxy.report}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, io.TeeReader(client, observer))
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func (proxy *loopbackCaptureProxy) report(result capturedVLESSHeader) {
	// Observation must never backpressure the transparent connection. The
	// Stage-1 gate consumes its three expected results synchronously; the
	// bounded slack only prevents later HTTP probes from blocking on reports
	// that the gate intentionally does not retain.
	select {
	case proxy.result <- result:
	default:
	}
}

func canonicalVLESSCase(t *testing.T, name string) (testvectors.Vector, []byte) {
	t.Helper()
	suite, err := testvectors.Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range suite.Cases {
		if vector.Name != name {
			continue
		}
		header, err := hex.DecodeString(vector.RequestHeaderHex)
		if err != nil {
			t.Fatal(err)
		}
		return vector, header
	}
	t.Fatal("canonical VLESS fixture is missing")
	return testvectors.Vector{}, nil
}

func TestReferenceWebSocketObserverExtractsSplitMaskedVLESSHeader(t *testing.T) {
	t.Parallel()
	_, canonical := canonicalVLESSCase(t, "ipv4")
	result := make(chan capturedVLESSHeader, 1)
	observer := &referenceWebSocketObserver{report: func(captured capturedVLESSHeader) { result <- captured }}
	wire := append([]byte("GET /reference HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), maskedBinaryFrame(canonical)...)
	for _, value := range wire {
		if _, err := observer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	captured := <-result
	if captured.err != nil {
		t.Fatal(captured.err)
	}
	if !bytes.Equal(captured.header, canonical) {
		t.Fatal("captured header differs from the safe canonical test input")
	}
}

func TestSanitizeCapturedVLESSHeaderReplacesCredentialAndEveryAddressType(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ipv4", "domain", "ipv6"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, canonical := canonicalVLESSCase(t, name)
			shape, complete, err := parseCapturedVLESSHeader(canonical)
			if err != nil || !complete {
				t.Fatal("canonical VLESS fixture is malformed")
			}
			captured := append([]byte(nil), canonical...)
			for index := 1; index < 17; index++ {
				captured[index] = byte(0xa0 + index)
			}
			captured[shape.portOffset], captured[shape.portOffset+1] = 0x9c, 0x40
			destinationStart := shape.destinationOffset
			if name == "domain" {
				// Preserve the domain-length byte so only secret destination
				// content, rather than the public wire shape, differs.
				destinationStart++
			}
			for index := destinationStart; index < shape.headerBytes; index++ {
				captured[index] = byte('a' + index%26)
			}
			sanitized, err := sanitizeCapturedVLESSHeader(captured, canonical)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sanitized, canonical) {
				t.Fatal("sanitized capture differs from canonical fixture")
			}
		})
	}
}

func TestLoopbackCaptureProxyQueuesSequentialHeaders(t *testing.T) {
	t.Parallel()
	_, ipv4 := canonicalVLESSCase(t, "ipv4")
	_, domain := canonicalVLESSCase(t, "domain")
	proxy := &loopbackCaptureProxy{result: make(chan capturedVLESSHeader, maxReferenceCaptures)}
	proxy.report(capturedVLESSHeader{header: ipv4})
	proxy.report(capturedVLESSHeader{header: domain})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := proxy.Await(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxy.Await(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, ipv4) || !bytes.Equal(second, domain) {
		t.Fatal("sequential capture order differs from real connection order")
	}
}

func maskedBinaryFrame(payload []byte) []byte {
	var mask uint32 = 0x10203040
	frame := []byte{0x82}
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 0xffff:
		frame = append(frame, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 0x80|127, 0, 0, 0, 0, byte(uint64(len(payload))>>24), byte(uint64(len(payload))>>16), byte(uint64(len(payload))>>8), byte(len(payload)))
	}
	maskBytes := []byte{byte(mask >> 24), byte(mask >> 16), byte(mask >> 8), byte(mask)}
	frame = append(frame, maskBytes...)
	for index, value := range payload {
		frame = append(frame, value^maskBytes[index%4])
	}
	return frame
}
