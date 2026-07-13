package xray

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5DialerSendsDomainWithoutLocalResolution(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requested := make(chan string, 1)
	go serveOneSOCKSEcho(t, listener, requested)

	dialer := SOCKS5Dialer{ProxyAddress: listener.Addr().String(), Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(context.Background(), "tcp", "does-not-resolve.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("response = %q", response)
	}
	if got := <-requested; got != "does-not-resolve.invalid:443" {
		t.Fatalf("requested = %q", got)
	}
}

func serveOneSOCKSEcho(t *testing.T, listener net.Listener, requested chan<- string) {
	t.Helper()
	connection, err := listener.Accept()
	if err != nil {
		return
	}
	defer connection.Close()
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		t.Errorf("greeting: %v", err)
		return
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		t.Errorf("greeting response: %v", err)
		return
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		t.Errorf("request header: %v", err)
		return
	}
	if header[3] != 3 {
		t.Errorf("address type = %d", header[3])
		return
	}
	length := make([]byte, 1)
	if _, err := io.ReadFull(connection, length); err != nil {
		t.Errorf("domain length: %v", err)
		return
	}
	domain := make([]byte, int(length[0]))
	if _, err := io.ReadFull(connection, domain); err != nil {
		t.Errorf("domain: %v", err)
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		t.Errorf("port: %v", err)
		return
	}
	requested <- net.JoinHostPort(string(domain), stringPort(binary.BigEndian.Uint16(portBytes)))
	if _, err := connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
		t.Errorf("connect response: %v", err)
		return
	}
	_, _ = io.Copy(connection, connection)
}
