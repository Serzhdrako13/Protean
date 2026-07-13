package xray

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseClientLink parses a client share-link (as issued by a foreign server's
// panel) into a RelaySpec, so an operator can set up a foreign egress relay
// (#67) by pasting the link rather than re-entering every parameter. Supports
// the dialable strategies: VLESS+Reality, VLESS/TLS (tcp/grpc), Trojan, SS.
func ParseClientLink(link string) (RelaySpec, error) {
	link = strings.TrimSpace(link)
	switch {
	case strings.HasPrefix(link, "vless://"):
		return parseVLESS(link)
	case strings.HasPrefix(link, "trojan://"):
		return parseTrojan(link)
	case strings.HasPrefix(link, "ss://"):
		return parseSS(link)
	default:
		return RelaySpec{}, fmt.Errorf("unsupported link scheme (want vless/trojan/ss)")
	}
}

func parseVLESS(link string) (RelaySpec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return RelaySpec{}, err
	}
	q := u.Query()
	port := portFromHost(u.Host)
	p := Params{
		pUUID: u.User.Username(),
		pPort: strconv.Itoa(port),
		pSNI:  q.Get("sni"),
	}
	spec := RelaySpec{Host: hostOnly(u.Host), Params: p}
	security := q.Get("security")
	network := q.Get("type")
	switch {
	case security == "reality":
		spec.Strategy = "reality-vless-tcp"
		p[pRealityPub] = q.Get("pbk")
		p[pShortID] = q.Get("sid")
	case network == "grpc":
		spec.Strategy = "vless-grpc-tls"
		p[pDomain] = q.Get("sni")
		p[pGRPCService] = q.Get("serviceName")
	default:
		spec.Strategy = "vless-vision-tls"
		p[pDomain] = q.Get("sni")
	}
	if spec.Params[pUUID] == "" {
		return RelaySpec{}, fmt.Errorf("vless link missing uuid")
	}
	return spec, nil
}

func parseTrojan(link string) (RelaySpec, error) {
	u, err := url.Parse(link)
	if err != nil {
		return RelaySpec{}, err
	}
	q := u.Query()
	return RelaySpec{
		Strategy: "trojan-tcp-tls",
		Host:     hostOnly(u.Host),
		Params: Params{
			pPassword: u.User.Username(),
			pPort:     strconv.Itoa(portFromHost(u.Host)),
			pDomain:   q.Get("sni"),
		},
	}, nil
}

func parseSS(link string) (RelaySpec, error) {
	// ss://base64(method:password)@host:port#name  (SIP002)
	rest := strings.TrimPrefix(link, "ss://")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndexByte(rest, '@')
	if at < 0 {
		return RelaySpec{}, fmt.Errorf("ss link missing '@'")
	}
	userinfo, hostport := rest[:at], rest[at+1:]
	dec, err := decodeMaybe(userinfo)
	if err != nil {
		return RelaySpec{}, fmt.Errorf("ss userinfo: %w", err)
	}
	method, pw, ok := strings.Cut(dec, ":")
	if !ok {
		return RelaySpec{}, fmt.Errorf("ss userinfo not method:password")
	}
	return RelaySpec{
		Strategy: "shadowsocks-2022",
		Host:     hostOnly(hostport),
		Params: Params{
			pSSMethod: method,
			pPassword: pw,
			pPort:     strconv.Itoa(portFromHost(hostport)),
		},
	}, nil
}

// decodeMaybe tries base64 (raw-url then std); returns the input unchanged if
// it's already plain "method:password".
func decodeMaybe(s string) (string, error) {
	if strings.Contains(s, ":") {
		return s, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b), nil
	}
	return "", fmt.Errorf("not base64 and not method:password")
}

func hostOnly(hostport string) string {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

func portFromHost(hostport string) int {
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		if n, err := strconv.Atoi(hostport[i+1:]); err == nil {
			return n
		}
	}
	return 443
}
