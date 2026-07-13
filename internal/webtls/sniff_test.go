package webtls

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
)

func TestLooksLikePlainHTTP(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"GET /foo HTTP/1.1\r\n", true},
		{"POST /api HTTP/1.1", true},
		{"HEAD / HTTP/1.1", true},
		{"PUT /x HTTP/1.1", true},
		{string([]byte{0x16, 0x03, 0x01, 0x00}), false}, // TLS handshake record
		{"ab", false},                                  // too short
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikePlainHTTP([]byte(c.in)); got != c.want {
			t.Errorf("looksLikePlainHTTP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripCRLF(t *testing.T) {
	if got := stripCRLF("evil\r\nX-Injected: yes"); got != "evilX-Injected: yes" {
		t.Errorf("stripCRLF did not remove CRLF: %q", got)
	}
}

// TestRedirectPlainHTTPRedirectsPlainRequest exercises the real network
// path: a plain HTTP client hitting a RedirectPlainHTTP-wrapped listener
// gets a 301 to the https equivalent, not a hang or a raw TLS error.
func TestRedirectPlainHTTPRedirectsPlainRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := RedirectPlainHTTP(ln)
	defer wrapped.Close()

	go func() {
		c, err := wrapped.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // triggers the lazy sniff -> writes redirect, closes conn
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET /foo?x=1 HTTP/1.1\r\nHost: example.com:8080\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "https://example.com:8080/foo?x=1" {
		t.Errorf("Location = %q, want https://example.com:8080/foo?x=1", loc)
	}
}

// TestRedirectPlainHTTPPassesThroughNonHTTP confirms a connection that
// doesn't look like plaintext HTTP (e.g. a TLS handshake) is handed through
// byte-for-byte, unmodified.
func TestRedirectPlainHTTPPassesThroughNonHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := RedirectPlainHTTP(ln)
	defer wrapped.Close()

	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	done := make(chan string, 1)
	go func() {
		c, err := wrapped.Accept()
		if err != nil {
			done <- ""
			return
		}
		buf := make([]byte, len(payload))
		n, _ := io.ReadFull(c, buf)
		done <- string(buf[:n])
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := <-done
	if got != string(payload) {
		t.Errorf("passthrough payload = %q, want %q (must be byte-identical for a real TLS handshake)", got, string(payload))
	}
}

func TestStripCRLFNoOpOnCleanInput(t *testing.T) {
	if got := stripCRLF("example.com:8080"); got != "example.com:8080" {
		t.Errorf("stripCRLF altered clean input: %q", got)
	}
}
