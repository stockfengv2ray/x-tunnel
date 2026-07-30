package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

func TestParseSOCKS5Addr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		host     string
		username string
		password string
		wantErr  bool
	}{
		{name: "authenticated", addr: "socks5://admin:admin@warp-go.railway.internal:40000", host: "warp-go.railway.internal:40000", username: "admin", password: "admin"},
		{name: "escaped credentials", addr: "socks5://a%40b:p%3Ass@example.test:1080", host: "example.test:1080", username: "a@b", password: "p:ss"},
		{name: "ipv6", addr: "socks5://[2001:db8::1]:1080", host: "[2001:db8::1]:1080"},
		{name: "missing scheme", addr: "example.test:1080", wantErr: true},
		{name: "wrong scheme", addr: "http://example.test:1080", wantErr: true},
		{name: "missing port", addr: "socks5://example.test", wantErr: true},
		{name: "incomplete auth", addr: "socks5://admin@example.test:1080", wantErr: true},
		{name: "path", addr: "socks5://example.test:1080/path", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := parseSOCKS5Addr(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSOCKS5Addr(%q) unexpectedly succeeded: %#v", tt.addr, config)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSOCKS5Addr(%q): %v", tt.addr, err)
			}
			if config.Host != tt.host || config.Username != tt.username || config.Password != tt.password {
				t.Fatalf("unexpected config: %#v", config)
			}
			parsedAgain, err := parseSOCKS5Addr(canonicalSOCKS5Addr(config))
			if err != nil || *parsedAgain != *config {
				t.Fatalf("canonical round trip failed: config=%#v parsed=%#v err=%v", config, parsedAgain, err)
			}
		})
	}
}

func TestResolveStreamRouteIsPerStream(t *testing.T) {
	defaultProxy := &SOCKS5Config{Host: "default.internal:1080"}
	kind, target, config, err := resolveStreamRoute(streamKindTCP, "example.com:443", defaultProxy)
	if err != nil || kind != streamKindTCP || target != "example.com:443" || config != defaultProxy {
		t.Fatalf("default route mismatch: kind=%d target=%q config=%#v err=%v", kind, target, config, err)
	}

	const workers = 64
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			proxyHost := fmt.Sprintf("proxy-%d.internal:1080", i)
			proxyURL := "socks5://user:pass@" + proxyHost
			wireTarget, err := encodeProxyStreamTarget(proxyURL, "target.example:443")
			if err != nil {
				errCh <- err
				return
			}
			kind, target, config, err := resolveStreamRoute(streamKindTCPProxy, wireTarget, defaultProxy)
			if err != nil {
				errCh <- err
				return
			}
			if kind != streamKindTCP || target != "target.example:443" || config.Host != proxyHost {
				errCh <- fmt.Errorf("route %d leaked state: kind=%d target=%q config=%#v", i, kind, target, config)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildSOCKS5UDPPacketDataKeepsDomain(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	packet, err := buildSOCKS5UDPPacketData("dns.example:53", payload)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := append([]byte{0, 0, 0, 3, byte(len("dns.example"))}, []byte("dns.example")...)
	wantPrefix = append(wantPrefix, 0, 53)
	if !bytes.Equal(packet[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected SOCKS5 UDP header: %x", packet)
	}
	if !bytes.Equal(packet[len(wantPrefix):], payload) {
		t.Fatalf("unexpected SOCKS5 UDP payload: %x", packet)
	}
}

func TestDialViaSOCKS5Authenticated(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	serverErr := make(chan error, 1)
	go serveOneMockSOCKS5(proxyListener, targetListener.Addr().String(), "admin", "admin", serverErr)

	config := &SOCKS5Config{Host: proxyListener.Addr().String(), Username: "admin", Password: "admin"}
	conn, err := dialViaSocks5(config, "tcp", targetListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	message := []byte("x-tunnel proxy test")
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, message) {
		t.Fatalf("unexpected echo: %q", reply)
	}
	_ = conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestProxyStreamEndToEnd(t *testing.T) {
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	proxyErr := make(chan error, 1)
	go serveOneMockSOCKS5(proxyListener, targetListener.Addr().String(), "admin", "admin", proxyErr)

	serverConn, clientConn := net.Pipe()
	serverMux, err := smux.Server(serverConn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverMux.Close()
	clientMux, err := smux.Client(clientConn, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientMux.Close()

	handlerErr := make(chan error, 1)
	go func() {
		stream, err := serverMux.AcceptStream()
		if err != nil {
			handlerErr <- err
			return
		}
		session := &ClientSession{clientID: "integration-client"}
		handleSmuxStream(session, &WSChannel{id: 1, session: session}, stream)
		handlerErr <- nil
	}()

	stream, err := clientMux.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "socks5://admin:admin@" + proxyListener.Addr().String()
	wireTarget, err := encodeProxyStreamTarget(proxyURL, targetListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSmuxOpenHeader(stream, streamKindTCPProxy, IPStrategyDefault, wireTarget); err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	message := []byte("per-stream proxy route")
	if _, err := stream.Write(message); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(message))
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, message) {
		t.Fatalf("unexpected proxy stream echo: %q", reply)
	}
	_ = stream.Close()
	if err := <-handlerErr; err != nil {
		t.Fatal(err)
	}
	if err := <-proxyErr; err != nil {
		t.Fatal(err)
	}
}

func serveOneMockSOCKS5(listener net.Listener, wantTarget, username, password string, result chan<- error) {
	result <- func() error {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		defer client.Close()

		header := make([]byte, 2)
		if _, err := io.ReadFull(client, header); err != nil {
			return err
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(client, methods); err != nil {
			return err
		}
		if header[0] != 5 || !bytes.Contains(methods, []byte{2}) {
			return fmt.Errorf("client did not offer username/password auth: %x %x", header, methods)
		}
		if _, err := client.Write([]byte{5, 2}); err != nil {
			return err
		}

		if _, err := io.ReadFull(client, header); err != nil {
			return err
		}
		user := make([]byte, int(header[1]))
		if _, err := io.ReadFull(client, user); err != nil {
			return err
		}
		passwordLen := []byte{0}
		if _, err := io.ReadFull(client, passwordLen); err != nil {
			return err
		}
		pass := make([]byte, int(passwordLen[0]))
		if _, err := io.ReadFull(client, pass); err != nil {
			return err
		}
		if header[0] != 1 || string(user) != username || string(pass) != password {
			return fmt.Errorf("unexpected credentials: version=%d user=%q pass=%q", header[0], user, pass)
		}
		if _, err := client.Write([]byte{1, 0}); err != nil {
			return err
		}

		request := make([]byte, 4)
		if _, err := io.ReadFull(client, request); err != nil {
			return err
		}
		if request[0] != 5 || request[1] != 1 {
			return fmt.Errorf("unexpected CONNECT request: %x", request)
		}
		target, err := readTestSOCKS5Address(client, request[3])
		if err != nil {
			return err
		}
		if target != wantTarget {
			return fmt.Errorf("CONNECT target=%q, want %q", target, wantTarget)
		}

		upstream, err := net.Dial("tcp", target)
		if err != nil {
			return err
		}
		defer upstream.Close()
		if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return err
		}
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.(*net.TCPConn).CloseWrite()
			close(copyDone)
		}()
		_, _ = io.Copy(client, upstream)
		<-copyDone
		return nil
	}()
}

func readTestSOCKS5Address(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(r, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 4:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("unknown ATYP %d", atyp)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(strings.TrimSpace(host), fmt.Sprint(port)), nil
}
