package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestProvisionScriptContent(t *testing.T) {
	script := provisionScript("protean", "/usr/local/lib/protean/protean-installer.sh", "QkFTRTY0", "ssh-ed25519 AAAAKEY panel")

	mustContain := []string{
		"if id -u 'protean' >/dev/null 2>&1;",
		"useradd -m -s /bin/bash 'protean'",
		"echo PROTEAN_USER_CREATED",
		"echo PROTEAN_USER_EXISTED",
		"usermod -L 'protean'",
		"getent passwd 'protean'",
		"grep -qxF 'ssh-ed25519 AAAAKEY panel'",
		"install -d -m 755 /usr/local/lib/protean",
		"protean ALL=(root) NOPASSWD: /usr/local/lib/protean/protean-installer.sh, " +
			"/usr/bin/wg show *, /usr/bin/wg set *, /usr/bin/awg show *, /usr/bin/awg set *, " +
			"/usr/sbin/swanctl --list-sas, /usr/sbin/swanctl --load-all",
		"visudo -cf /etc/sudoers.d/protean",
		"install -d -m 750 -o 'protean'",
		"chown -R 'protean':'protean'",
	}
	for _, want := range mustContain {
		if !strings.Contains(script, want) {
			t.Errorf("provisionScript output missing %q\ngot:\n%s", want, script)
		}
	}
	if strings.Contains(script, "systemctl") {
		t.Errorf("provisionScript must not grant blanket systemctl sudo, got:\n%s", script)
	}
	// A bare `wg-quick`/`awg-quick` grant (no arg restriction) would let
	// anyone with the panel's SSH key run `sudo wg-quick up <any file
	// they control>` -- wg-quick's own PostUp directive then runs as a
	// shell command as root, a straight root shell. internal/vpn/wgfamily
	// never calls wg-quick directly (interface restarts go through
	// `systemctl restart wg-quick@*`, scoped to a fixed unit name), so
	// there's no reason to grant it at all.
	if strings.Contains(script, "wg-quick") {
		t.Errorf("provisionScript must not grant sudo on wg-quick/awg-quick directly, got:\n%s", script)
	}
}

func TestDialKey(t *testing.T) {
	ts := newTestServer(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	host, portStr, _ := net.SplitHostPort(ts.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client, err := dialKey(context.Background(), Config{Host: host, Port: port, User: "root", HostKey: ts.hostAuth}, keyPEM)
	if err != nil {
		t.Fatalf("dialKey: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput("echo hello")
	if err != nil {
		t.Fatalf("CombinedOutput: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("got %q, want hello", out)
	}
}

func TestDialKeyBadKey(t *testing.T) {
	ts := newTestServer(t)
	host, portStr, _ := net.SplitHostPort(ts.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if _, err := dialKey(context.Background(), Config{Host: host, Port: port, User: "root", HostKey: ts.hostAuth}, []byte("not a key")); err == nil {
		t.Fatal("expected an error parsing an invalid key")
	}
}
