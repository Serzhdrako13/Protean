package ikev2

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// uuidFrom derives a stable RFC-4122-shaped UUID string from a seed, so
// re-downloading a client's profile yields the same identifiers (idempotent
// installs on the device).
func uuidFrom(seed string) string {
	h := sha256.Sum256([]byte(seed))
	// Set version (4) and variant bits for a well-formed UUID.
	h[6] = (h[6] & 0x0f) | 0x40
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// mobileConfigParams builds an Apple .mobileconfig (an XML property list) that
// bundles the client PKCS#12 and an IKEv2 VPN payload authenticating with it.
type mobileConfigParams struct {
	CN       string
	ServerID string
	P12      []byte
	P12Pass  string
}

func (m mobileConfigParams) build() []byte {
	certUUID := uuidFrom(m.CN + "|cert")
	vpnUUID := uuidFrom(m.CN + "|vpn")
	topUUID := uuidFrom(m.CN + "|top")
	p12b64 := base64.StdEncoding.EncodeToString(m.P12)
	name := html.EscapeString("Protean VPN (" + m.CN + ")")
	cn := html.EscapeString(m.CN)
	srv := html.EscapeString(m.ServerID)

	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	w(`<?xml version="1.0" encoding="UTF-8"?>`)
	w(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`)
	w(`<plist version="1.0">`)
	w(`<dict>`)
	w(`  <key>PayloadContent</key>`)
	w(`  <array>`)
	// PKCS#12 certificate payload.
	w(`    <dict>`)
	w(`      <key>PayloadType</key><string>com.apple.security.pkcs12</string>`)
	w(`      <key>PayloadVersion</key><integer>1</integer>`)
	w(`      <key>PayloadIdentifier</key><string>com.wgpanel.` + cn + `.credential</string>`)
	w(`      <key>PayloadUUID</key><string>` + certUUID + `</string>`)
	w(`      <key>PayloadDisplayName</key><string>` + cn + ` certificate</string>`)
	w(`      <key>Password</key><string>` + html.EscapeString(m.P12Pass) + `</string>`)
	w(`      <key>PayloadContent</key>`)
	w(`      <data>` + p12b64 + `</data>`)
	w(`    </dict>`)
	// IKEv2 VPN payload referencing the credential above.
	w(`    <dict>`)
	w(`      <key>PayloadType</key><string>com.apple.vpn.managed</string>`)
	w(`      <key>PayloadVersion</key><integer>1</integer>`)
	w(`      <key>PayloadIdentifier</key><string>com.wgpanel.` + cn + `.vpn</string>`)
	w(`      <key>PayloadUUID</key><string>` + vpnUUID + `</string>`)
	w(`      <key>PayloadDisplayName</key><string>` + name + `</string>`)
	w(`      <key>UserDefinedName</key><string>` + name + `</string>`)
	w(`      <key>VPNType</key><string>IKEv2</string>`)
	w(`      <key>IKEv2</key>`)
	w(`      <dict>`)
	w(`        <key>RemoteAddress</key><string>` + srv + `</string>`)
	w(`        <key>RemoteIdentifier</key><string>` + srv + `</string>`)
	w(`        <key>LocalIdentifier</key><string>` + cn + `</string>`)
	w(`        <key>AuthenticationMethod</key><string>Certificate</string>`)
	w(`        <key>PayloadCertificateUUID</key><string>` + certUUID + `</string>`)
	w(`        <key>ExtendedAuthEnabled</key><integer>0</integer>`)
	w(`        <key>OnDemandEnabled</key><integer>0</integer>`)
	w(`      </dict>`)
	w(`    </dict>`)
	w(`  </array>`)
	w(`  <key>PayloadDisplayName</key><string>` + name + `</string>`)
	w(`  <key>PayloadIdentifier</key><string>com.wgpanel.` + cn + `</string>`)
	w(`  <key>PayloadUUID</key><string>` + topUUID + `</string>`)
	w(`  <key>PayloadType</key><string>Configuration</string>`)
	w(`  <key>PayloadVersion</key><integer>1</integer>`)
	w(`</dict>`)
	w(`</plist>`)
	return []byte(b.String())
}

// sswanProfile builds a strongSwan Android app .sswan profile (JSON). The p12
// is embedded base64; the app prompts for the import password.
func sswanProfile(cn, serverID string, p12 []byte) ([]byte, error) {
	profile := map[string]any{
		"uuid": uuidFrom(cn + "|sswan"),
		"name": "Protean VPN (" + cn + ")",
		"type": "ikev2-cert",
		"remote": map[string]any{
			"addr": serverID,
		},
		"local": map[string]any{
			"p12": base64.StdEncoding.EncodeToString(p12),
		},
	}
	out, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return nil, err
	}
	return out, nil
}
