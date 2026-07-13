package xray

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// DialContextFunc matches net.Dialer's context-aware function and can be
// installed directly on http.Transport.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// SOCKS5Dialer implements the no-auth CONNECT subset used by the local Xray
// SOCKS inbound. Domain names are sent to Xray without local resolution.
type SOCKS5Dialer struct {
	ProxyAddress string
	Timeout      time.Duration
}

func (dialer SOCKS5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer.ProxyAddress == "" {
		return nil, errors.New("SOCKS proxy address is required")
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("SOCKS dialer supports TCP only")
	}
	timeout := dialer.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", dialer.ProxyAddress)
	if err != nil {
		return nil, errors.New("connect to local Xray SOCKS listener")
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = connection.Close()
		}
	}()
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, errors.New("set SOCKS handshake deadline")
	}
	if err := writeAll(connection, []byte{5, 1, 0}); err != nil {
		return nil, errors.New("write SOCKS greeting")
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil || greeting[0] != 5 || greeting[1] != 0 {
		return nil, errors.New("Xray rejected SOCKS authentication")
	}
	request, err := socksConnectRequest(address)
	if err != nil {
		return nil, err
	}
	if err := writeAll(connection, request); err != nil {
		return nil, errors.New("write SOCKS connect request")
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil || header[0] != 5 {
		return nil, errors.New("read SOCKS connect response")
	}
	if header[1] != 0 {
		return nil, errors.New("Xray SOCKS connect failed")
	}
	if err := discardSOCKSAddress(connection, header[3]); err != nil {
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, errors.New("clear SOCKS handshake deadline")
	}
	succeeded = true
	return connection, nil
}

func socksConnectRequest(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, errors.New("destination address is invalid")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("destination port is invalid")
	}
	request := []byte{5, 1, 0}
	if parsed := net.ParseIP(host); parsed != nil {
		if ipv4 := parsed.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, parsed.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("destination hostname is too long")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	return request, nil
}

func discardSOCKSAddress(reader io.Reader, addressType byte) error {
	length := 0
	switch addressType {
	case 1:
		length = 4
	case 3:
		value := make([]byte, 1)
		if _, err := io.ReadFull(reader, value); err != nil {
			return errors.New("read SOCKS response domain length")
		}
		length = int(value[0])
	case 4:
		length = 16
	default:
		return errors.New("SOCKS response address type is invalid")
	}
	if _, err := io.CopyN(io.Discard, reader, int64(length+2)); err != nil {
		return errors.New("read SOCKS response address")
	}
	return nil
}

func writeAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func stringPort(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}
