package api

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestClientIPIgnoresXFFByDefault(t *testing.T) {
	s := &Server{} // trustProxy false
	r := &http.Request{
		RemoteAddr: "203.0.113.9:5555",
		Header:     http.Header{"X-Forwarded-For": {"1.2.3.4"}},
	}
	if got := s.clientIP(r); got != "203.0.113.9" {
		t.Errorf("untrusted proxy: want socket addr 203.0.113.9, got %q (XFF must be ignored)", got)
	}
}

func TestClientIPHonorsXFFWhenTrusted(t *testing.T) {
	s := &Server{}
	s.SetTrustProxy(true)
	r := &http.Request{
		RemoteAddr: "203.0.113.9:5555",
		Header:     http.Header{"X-Forwarded-For": {"1.2.3.4, 10.0.0.1"}},
	}
	if got := s.clientIP(r); got != "1.2.3.4" {
		t.Errorf("trusted proxy: want first XFF hop 1.2.3.4, got %q", got)
	}
}

func TestIsSecureDirectTLS(t *testing.T) {
	s := &Server{} // trustProxy false
	r := &http.Request{RemoteAddr: "203.0.113.9:5555", TLS: &tls.ConnectionState{}}
	if !s.isSecure(r) {
		t.Error("r.TLS set should always report secure, regardless of trustProxy")
	}
}

func TestIsSecureIgnoresForwardedProtoByDefault(t *testing.T) {
	s := &Server{} // trustProxy false
	r := &http.Request{RemoteAddr: "203.0.113.9:5555", Header: http.Header{"X-Forwarded-Proto": {"https"}}}
	if s.isSecure(r) {
		t.Error("untrusted proxy: X-Forwarded-Proto must be ignored when trustProxy is off")
	}
}

func TestIsSecureHonorsForwardedProtoWhenTrusted(t *testing.T) {
	s := &Server{}
	s.SetTrustProxy(true)
	secure := &http.Request{RemoteAddr: "203.0.113.9:5555", Header: http.Header{"X-Forwarded-Proto": {"https"}}}
	if !s.isSecure(secure) {
		t.Error("trusted proxy: X-Forwarded-Proto: https should report secure")
	}
	insecure := &http.Request{RemoteAddr: "203.0.113.9:5555", Header: http.Header{"X-Forwarded-Proto": {"http"}}}
	if s.isSecure(insecure) {
		t.Error("trusted proxy: X-Forwarded-Proto: http should report insecure")
	}
	missing := &http.Request{RemoteAddr: "203.0.113.9:5555", Header: http.Header{}}
	if s.isSecure(missing) {
		t.Error("trusted proxy with no header at all should default to insecure, not secure")
	}
}
