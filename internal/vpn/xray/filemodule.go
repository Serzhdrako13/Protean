package xray

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed modules_example.txt
var exampleFS embed.FS

// SeedExampleModule drops the annotated example module file into dir, but
// only if it (or a same-named file) doesn't already exist there -- never
// overwrites an admin's own content. Named ".txt" (not ".json") so
// loadModuleFiles' own extension filter never registers it as a real
// strategy. Safe to call on every startup, non-fatal by design -- mirrors
// internal/vpnsetup.EnsureSeeded exactly.
func SeedExampleModule(dir string) error {
	const name = "_example.json.txt"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	b, err := exampleFS.ReadFile("modules_example.txt")
	if err != nil {
		return err
	}
	// 0666: the panel container runs as root, so a file it creates on a
	// bind-mounted host directory is root-owned there -- world-writable is
	// what lets a non-root host user edit it without sudo (same rationale
	// as vpnsetup.EnsureSeeded; this is documentation/an example, not a
	// secret).
	return os.WriteFile(dst, b, 0o666)
}

// fileModule is the on-disk JSON shape of an admin-authored strategy module
// -- the "modules as data" counterpart to the compiled Strategy types in
// strategies.go. See internal/vpn/xray/modules_example.txt for an annotated
// example.
type fileModule struct {
	Name                string          `json:"name"`
	Label               string          `json:"label"`
	Cred                string          `json:"cred"`          // "uuid" | "password"
	ClientFormat        string          `json:"client_format"` // "vless" | "vmess" | "trojan"
	MultiClient         bool            `json:"multi_client"`
	Params              []fileParamSpec `json:"params"`
	InstanceSecretsSpec []SecretSpec    `json:"instance_secrets"`
	Inbound             map[string]any  `json:"inbound"`
	ClientLinkTemplate  string          `json:"client_link_template"`
}

type fileParamSpec struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
	Secret      bool   `json:"secret"`
	// Type controls how the value is coerced when substituted into the
	// inbound JSON tree: "int" -> a JSON number, "bool" -> a JSON bool,
	// anything else (including empty) -> a JSON string.
	Type string `json:"type"`
}

func (m fileModule) validate() error {
	if m.Name == "" {
		return fmt.Errorf("missing \"name\"")
	}
	if m.Label == "" {
		return fmt.Errorf("missing \"label\"")
	}
	if m.Cred != "uuid" && m.Cred != "password" {
		return fmt.Errorf("\"cred\" must be \"uuid\" or \"password\", got %q", m.Cred)
	}
	switch m.ClientFormat {
	case "vless", "vmess", "trojan":
	default:
		return fmt.Errorf("\"client_format\" must be one of vless/vmess/trojan, got %q", m.ClientFormat)
	}
	if len(m.Inbound) == 0 {
		return fmt.Errorf("missing \"inbound\"")
	}
	for _, s := range m.InstanceSecretsSpec {
		switch s.Kind {
		case "reality_keypair", "short_id", "uuid", "password":
		default:
			return fmt.Errorf("instance_secrets: unknown kind %q", s.Kind)
		}
	}
	return nil
}

// fileStrategy implements Strategy (and InstanceSecrets, when the module
// declares any) by interpreting a parsed fileModule at build time -- no Go
// code needed per module.
type fileStrategy struct{ def fileModule }

func (f fileStrategy) Name() string  { return f.def.Name }
func (f fileStrategy) Label() string { return f.def.Label }

func (f fileStrategy) Params() []ParamSpec {
	out := make([]ParamSpec, 0, len(f.def.Params))
	for _, ps := range f.def.Params {
		out = append(out, ParamSpec{
			Key: ps.Key, Label: ps.Label, Placeholder: ps.Placeholder,
			Default: ps.Default, Required: ps.Required, Secret: ps.Secret,
		})
	}
	return out
}

func (f fileStrategy) Cred() CredKind {
	if f.def.Cred == "password" {
		return CredPassword
	}
	return CredUUID
}

func (f fileStrategy) MultiClient() bool { return f.def.MultiClient }

func (f fileStrategy) InstanceSecrets() []SecretSpec { return f.def.InstanceSecretsSpec }

func (f fileStrategy) paramType(key string) string {
	for _, ps := range f.def.Params {
		if ps.Key == key {
			return ps.Type
		}
	}
	return ""
}

func (f fileStrategy) buildClientArray(clients []Client) ([]any, error) {
	switch f.def.ClientFormat {
	case "vless":
		return VlessClients(clients, ""), nil
	case "vmess":
		return VmessClients(clients), nil
	case "trojan":
		return TrojanClients(clients), nil
	default:
		return nil, fmt.Errorf("module %q: unknown client_format %q", f.def.Name, f.def.ClientFormat)
	}
}

func (f fileStrategy) BuildInbound(p Params, clients []Client) (map[string]any, error) {
	if err := requireParams(p, f.Params()); err != nil {
		return nil, err
	}
	if err := needClients(clients); err != nil {
		return nil, err
	}
	clientArr, err := f.buildClientArray(clients)
	if err != nil {
		return nil, err
	}
	resolved, err := substituteTree(f.def.Inbound, func(token string) (any, bool) {
		if token == "clients" {
			return clientArr, true
		}
		if v, ok := p[token]; ok {
			return coerceParam(v, f.paramType(token)), true
		}
		return nil, false
	})
	if err != nil {
		return nil, fmt.Errorf("module %q: %w", f.def.Name, err)
	}
	m, ok := resolved.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("module %q: \"inbound\" must be a JSON object", f.def.Name)
	}
	return m, nil
}

func (f fileStrategy) ClientLink(p Params, c Client, host string) (string, error) {
	tokens := make(map[string]string, len(p)+3)
	for k, v := range p {
		tokens[k] = v
	}
	tokens["host"] = host
	tokens["name"] = c.Name
	if c.UUID != "" {
		tokens["uuid"] = c.UUID
	}
	if c.Password != "" {
		tokens["password"] = c.Password
	}
	link, err := substituteString(f.def.ClientLinkTemplate, tokens)
	if err != nil {
		return "", fmt.Errorf("module %q: %w", f.def.Name, err)
	}
	return link, nil
}

// --- placeholder substitution ---
//
// Both the inbound JSON tree and the client-link string use the same
// "{{token}}" syntax. The inbound side substitutes whole JSON VALUES (a
// leaf string that is EXACTLY "{{token}}" is replaced by a real typed
// value -- a number, bool, array, or string) rather than templating raw
// text, so a malformed placeholder can never produce invalid JSON: the
// surrounding structure is always valid, only leaf values change.

var wholeTokenRe = regexp.MustCompile(`^\{\{([a-zA-Z0-9_]+)\}\}$`)

// substituteTree deep-copies v, replacing any string leaf that is an exact
// "{{token}}" match via resolve. An unresolved token is an error -- a typo
// in a module file should fail loudly at build time, not silently produce a
// broken config that gets pushed to a live host.
func substituteTree(v any, resolve func(token string) (any, bool)) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			r, err := substituteTree(vv, resolve)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			r, err := substituteTree(vv, resolve)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case string:
		m := wholeTokenRe.FindStringSubmatch(t)
		if m == nil {
			return t, nil
		}
		val, ok := resolve(m[1])
		if !ok {
			return nil, fmt.Errorf("unresolved placeholder {{%s}}", m[1])
		}
		return val, nil
	default:
		return t, nil
	}
}

var tokenRe = regexp.MustCompile(`\{\{([a-zA-Z0-9_]+)\}\}`)

// substituteString replaces every "{{token}}" occurrence in tmpl (a plain
// string, e.g. a share-link template) via a lookup in tokens.
func substituteString(tmpl string, tokens map[string]string) (string, error) {
	var missing string
	out := tokenRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		key := tokenRe.FindStringSubmatch(match)[1]
		v, ok := tokens[key]
		if !ok {
			missing = key
			return match
		}
		return v
	})
	if missing != "" {
		return "", fmt.Errorf("unresolved placeholder {{%s}}", missing)
	}
	return out, nil
}

// coerceParam converts a raw string param value to the JSON-native type its
// ParamSpec declares ("int"/"bool"), falling back to the original string
// (still valid JSON) if the value doesn't actually parse as that type.
func coerceParam(v, typ string) any {
	switch typ {
	case "int":
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	case "bool":
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return v
}

// --- directory loading ---

var (
	modulesDirMu sync.RWMutex
	modulesDir   string
)

// SetModulesDir configures where All/Get look for admin-authored module
// files (in addition to the compile-time registry) -- call once at startup.
// An empty dir (the default) disables file-based modules entirely, at zero
// cost to every existing caller.
func SetModulesDir(dir string) {
	modulesDirMu.Lock()
	modulesDir = dir
	modulesDirMu.Unlock()
}

func currentModulesDir() string {
	modulesDirMu.RLock()
	defer modulesDirMu.RUnlock()
	return modulesDir
}

// loadModuleFiles scans dir for "*.json" files (skipping ones starting with
// "_", reserved for shipped examples) and parses+validates each into a
// fileStrategy. Every failure mode (bad JSON, a missing/invalid field, a
// name colliding with an already-registered COMPILED strategy -- never let
// a file shadow a vetted built-in) is reported as a warning and skipped,
// never treated as fatal: one bad module file must never block the others
// or the panel itself (same tolerant, best-effort style as
// internal/vpnsetup).
func loadModuleFiles(dir string) (strategies []Strategy, warnings []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			warnings = append(warnings, fmt.Sprintf("read %s: %v", dir, err))
		}
		return nil, warnings
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "_") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: read: %v", name, err))
			continue
		}
		var def fileModule
		if err := json.Unmarshal(raw, &def); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: parse: %v", name, err))
			continue
		}
		if err := def.validate(); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if _, ok := registry[def.Name]; ok {
			warnings = append(warnings, fmt.Sprintf("%s: name %q collides with a built-in strategy, skipped", name, def.Name))
			continue
		}
		if seen[def.Name] {
			warnings = append(warnings, fmt.Sprintf("%s: duplicate module name %q, skipped", name, def.Name))
			continue
		}
		seen[def.Name] = true
		strategies = append(strategies, fileStrategy{def: def})
	}
	return strategies, warnings
}

// LoadModulesDir scans dir once and reports how many valid modules were
// found and any warnings, for a one-line startup log. All/Get already scan
// the configured dir (see SetModulesDir/currentModulesDir) on every call
// themselves, so this doesn't register anything on its own -- it exists so
// a bad module is visible in the logs immediately, not just silently
// missing from the strategy list.
func LoadModulesDir(dir string) (loaded int, warnings []string) {
	strategies, warnings := loadModuleFiles(dir)
	return len(strategies), warnings
}
