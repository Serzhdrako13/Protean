package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testModule() fileModule {
	return fileModule{
		Name: "test-ws-camo", Label: "Test WS camo",
		Cred: "uuid", ClientFormat: "vless", MultiClient: true,
		Params: []fileParamSpec{
			{Key: "port", Label: "Port", Default: "443", Required: true, Type: "int"},
			{Key: "domain", Label: "Domain", Required: true},
		},
		Inbound: map[string]any{
			"listen":   "0.0.0.0",
			"port":     "{{port}}",
			"protocol": "vless",
			"settings": map[string]any{"clients": "{{clients}}", "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "ws", "security": "tls",
				"tlsSettings": map[string]any{"serverName": "{{domain}}"},
			},
		},
		ClientLinkTemplate: "vless://{{uuid}}@{{host}}:{{port}}?sni={{domain}}#{{name}}",
	}
}

func TestFileStrategyBuildInbound(t *testing.T) {
	fs := fileStrategy{def: testModule()}
	p := Params{"port": "8443", "domain": "www.example.com"}
	clients := []Client{{Name: "alice", UUID: "u-1"}, {Name: "bob", UUID: "u-2"}}

	inb, err := fs.BuildInbound(p, clients)
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}
	if inb["port"] != 8443 {
		t.Errorf("port = %v (%T), want int 8443", inb["port"], inb["port"])
	}
	settings, ok := inb["settings"].(map[string]any)
	if !ok {
		t.Fatalf("settings not a map: %#v", inb["settings"])
	}
	clientArr, ok := settings["clients"].([]any)
	if !ok || len(clientArr) != 2 {
		t.Fatalf("clients sentinel not resolved to a 2-element array: %#v", settings["clients"])
	}
	first, _ := clientArr[0].(map[string]any)
	if first["id"] != "u-1" {
		t.Errorf("first client id = %v, want u-1", first["id"])
	}
	stream := inb["streamSettings"].(map[string]any)
	tls := stream["tlsSettings"].(map[string]any)
	if tls["serverName"] != "www.example.com" {
		t.Errorf("serverName = %v, want www.example.com", tls["serverName"])
	}
}

func TestFileStrategyBuildInboundRequiresClients(t *testing.T) {
	fs := fileStrategy{def: testModule()}
	p := Params{"port": "443", "domain": "x"}
	if _, err := fs.BuildInbound(p, nil); err == nil {
		t.Error("expected an error building an inbound with no clients")
	}
}

func TestFileStrategyClientLink(t *testing.T) {
	fs := fileStrategy{def: testModule()}
	p := Params{"port": "443", "domain": "www.example.com"}
	link, err := fs.ClientLink(p, Client{Name: "alice", UUID: "u-1"}, "vpn.example.com")
	if err != nil {
		t.Fatalf("ClientLink: %v", err)
	}
	want := "vless://u-1@vpn.example.com:443?sni=www.example.com#alice"
	if link != want {
		t.Errorf("link = %q, want %q", link, want)
	}
}

func TestFileStrategyClientLinkUnresolvedPlaceholder(t *testing.T) {
	def := testModule()
	def.ClientLinkTemplate = "vless://{{uuid}}@{{host}}:{{port}}?nope={{missing_token}}#{{name}}"
	fs := fileStrategy{def: def}
	p := Params{"port": "443", "domain": "x"}
	if _, err := fs.ClientLink(p, Client{Name: "alice", UUID: "u-1"}, "host"); err == nil {
		t.Error("expected an error for an unresolved placeholder")
	}
}

func writeModuleFile(t *testing.T, dir, filename string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

const validModuleJSON = `{
  "name": "custom-ws",
  "label": "Custom WS",
  "cred": "uuid",
  "client_format": "vless",
  "multi_client": true,
  "params": [{"key": "port", "label": "Port", "default": "443", "required": true, "type": "int"}],
  "inbound": {"listen": "0.0.0.0", "port": "{{port}}", "protocol": "vless",
    "settings": {"clients": "{{clients}}", "decryption": "none"}},
  "client_link_template": "vless://{{uuid}}@{{host}}:{{port}}#{{name}}"
}`

func TestLoadModuleFilesValid(t *testing.T) {
	dir := t.TempDir()
	writeModuleFile(t, dir, "custom-ws.json", validModuleJSON)

	strategies, warnings := loadModuleFiles(dir)
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if len(strategies) != 1 || strategies[0].Name() != "custom-ws" {
		t.Fatalf("expected 1 strategy \"custom-ws\", got %+v", strategies)
	}
}

func TestLoadModuleFilesRejectsCollisionWithCompiled(t *testing.T) {
	dir := t.TempDir()
	collidingJSON := strings.Replace(validModuleJSON, `"custom-ws"`, `"reality-vless-tcp"`, 1)
	writeModuleFile(t, dir, "shadow.json", collidingJSON)

	strategies, warnings := loadModuleFiles(dir)
	if len(strategies) != 0 {
		t.Fatalf("a module colliding with a compiled strategy must not be registered, got %+v", strategies)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "collides") {
		t.Fatalf("expected a collision warning, got %v", warnings)
	}
	// The real compiled strategy must still resolve correctly via Get.
	strat, ok := Get("reality-vless-tcp")
	if !ok || strat.Label() != (realityVlessTCP{}).Label() {
		t.Error("compiled reality-vless-tcp strategy must be unaffected")
	}
}

func TestLoadModuleFilesSkipsMalformedButLoadsOthers(t *testing.T) {
	dir := t.TempDir()
	writeModuleFile(t, dir, "broken.json", `{not valid json`)
	writeModuleFile(t, dir, "custom-ws.json", validModuleJSON)

	strategies, warnings := loadModuleFiles(dir)
	if len(strategies) != 1 || strategies[0].Name() != "custom-ws" {
		t.Fatalf("expected the valid module to still load, got %+v", strategies)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "broken.json") {
		t.Fatalf("expected a warning naming broken.json, got %v", warnings)
	}
}

func TestLoadModuleFilesSkipsExampleAndNonJSON(t *testing.T) {
	dir := t.TempDir()
	writeModuleFile(t, dir, "_example.json.txt", "not a real module")
	writeModuleFile(t, dir, "README.md", "# docs")

	strategies, warnings := loadModuleFiles(dir)
	if len(strategies) != 0 || len(warnings) != 0 {
		t.Fatalf("expected no strategies/warnings from non-module files, got %+v / %v", strategies, warnings)
	}
}

func TestAllAndGetIncludeFileModules(t *testing.T) {
	dir := t.TempDir()
	writeModuleFile(t, dir, "custom-ws.json", validModuleJSON)
	SetModulesDir(dir)
	defer SetModulesDir("")

	if _, ok := Get("custom-ws"); !ok {
		t.Error("Get should find the file-based module")
	}
	found := false
	for _, s := range All() {
		if s.Name() == "custom-ws" {
			found = true
		}
	}
	if !found {
		t.Error("All() should include the file-based module")
	}

	// Editing the directory takes effect immediately -- no caching.
	writeModuleFile(t, dir, "second.json", strings.Replace(validModuleJSON, `"custom-ws"`, `"custom-ws-2"`, 1))
	if _, ok := Get("custom-ws-2"); !ok {
		t.Error("a newly dropped-in module file must be picked up without re-registering")
	}
}

func TestSeedExampleModuleDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := SeedExampleModule(dir); err != nil {
		t.Fatalf("SeedExampleModule: %v", err)
	}
	path := filepath.Join(dir, "_example.json.txt")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected seeded example file: %v", err)
	}
	if err := os.WriteFile(path, []byte("admin edited this"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SeedExampleModule(dir); err != nil {
		t.Fatalf("SeedExampleModule (second call): %v", err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "admin edited this" {
		t.Error("SeedExampleModule must never overwrite an existing file")
	}
}
