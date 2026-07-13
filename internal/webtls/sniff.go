package webtls

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// httpMethodPrefixes are the first 4 bytes of common HTTP request methods --
// used to detect a plaintext HTTP request arriving on the TLS listener, the
// same heuristic crypto/tls itself uses internally to produce its terse
// "Client sent an HTTP request to an HTTPS server" diagnostic. Intercepting
// it here lets the panel answer with a proper redirect instead of that raw
// text (which is what a browser/admin actually hits if they type http://
// instead of https:// -- self-signed-by-default means this is a real,
// expected first-contact mistake, not a rare edge case).
var httpMethodPrefixes = []string{"GET ", "HEAD", "POST", "PUT ", "DELE", "OPTI", "TRAC", "PATC", "CONN"}

// RedirectPlainHTTP wraps a listener so a connection that turns out to be a
// plaintext HTTP request gets a friendly 301 redirect to the same URL over
// https instead of the bare TLS handshake failure. Connections that DO look
// like a TLS handshake are handed through completely unmodified.
//
// The actual sniff happens lazily, on the conn's first Read (called from
// within the per-connection goroutine Go's http.Server/crypto/tls already
// spawn) -- NOT inside Accept() itself. Peeking synchronously inside
// Accept() would serialize the whole listener behind whatever the current
// connection is doing (a client that opens a socket and sends nothing would
// stall every other client's Accept() too), which is strictly worse than
// the stdlib's own lazy-handshake behavior this wrapper needs to preserve.
func RedirectPlainHTTP(ln net.Listener) net.Listener {
	return &sniffListener{ln}
}

type sniffListener struct{ net.Listener }

func (l *sniffListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c}, nil
}

type sniffConn struct {
	net.Conn
	once  sync.Once
	br    *bufio.Reader
	isTLS bool
}

func (c *sniffConn) sniff() {
	c.br = bufio.NewReader(c.Conn)
	// Bound only the initial peek, not the connection's whole lifetime --
	// a real (if slow) TLS handshake has no stricter deadline than before.
	_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	peek, _ := c.br.Peek(4)
	c.isTLS = !looksLikePlainHTTP(peek)
	_ = c.Conn.SetReadDeadline(time.Time{})
	if !c.isTLS {
		respondPlainHTTPRedirect(c.Conn, c.br) // writes the redirect and closes c.Conn
	}
}

func (c *sniffConn) Read(p []byte) (int, error) {
	c.once.Do(c.sniff)
	if !c.isTLS {
		return 0, io.EOF // already answered + closed in sniff(); nothing left to hand to TLS
	}
	return c.br.Read(p)
}

func looksLikePlainHTTP(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	s := string(b[:4])
	for _, p := range httpMethodPrefixes {
		if s == p {
			return true
		}
	}
	return false
}

// stripCRLF defends against header/response-splitting: Host and the
// request path are client-controlled, and this handler hand-builds a raw
// HTTP response (not via net/http's own header-writing, which already
// guards against this) -- cheap insurance even though Go's request parser
// shouldn't hand back literal CR/LF in these fields to begin with.
func stripCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "")
}

func respondPlainHTTPRedirect(c net.Conn, br *bufio.Reader) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))

	host, path := "this server", "/"
	if req, err := http.ReadRequest(br); err == nil {
		if req.Host != "" {
			host = stripCRLF(req.Host)
		}
		path = stripCRLF(req.URL.RequestURI())
	}

	target := "https://" + host + path
	body := fmt.Sprintf(
		"<html><body>Этот сервер работает только по HTTPS. <a href=\"%s\">%s</a></body></html>",
		html.EscapeString(target), html.EscapeString(target),
	)
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "HTTP/1.1 301 Moved Permanently\r\n"+
		"Location: %s\r\n"+
		"Content-Type: text/html; charset=utf-8\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n%s", target, len(body), body)
}
