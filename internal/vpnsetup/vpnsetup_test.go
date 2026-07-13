package vpnsetup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSeededWritesDefaultsButNeverOverwrites(t *testing.T) {
	dir := t.TempDir()

	if err := EnsureSeeded(dir); err != nil {
		t.Fatalf("EnsureSeeded: %v", err)
	}
	ruPath := filepath.Join(dir, "ru.json")
	if _, err := os.Stat(ruPath); err != nil {
		t.Fatalf("expected ru.json to be seeded: %v", err)
	}
	enPath := filepath.Join(dir, "en.json")
	if _, err := os.Stat(enPath); err != nil {
		t.Fatalf("expected en.json to be seeded: %v", err)
	}

	// An admin's edit must survive a second EnsureSeeded call (e.g. next
	// container restart) -- it must never be clobbered back to the default.
	custom := []byte(`{"custom": true}`)
	if err := os.WriteFile(ruPath, custom, 0o644); err != nil {
		t.Fatalf("write custom ru.json: %v", err)
	}
	if err := EnsureSeeded(dir); err != nil {
		t.Fatalf("EnsureSeeded (second call): %v", err)
	}
	got, err := os.ReadFile(ruPath)
	if err != nil {
		t.Fatalf("read ru.json: %v", err)
	}
	if string(got) != string(custom) {
		t.Errorf("ru.json was overwritten; got %q, want the custom content preserved", got)
	}
}

func TestLoadPrefersDirOverEmbeddedDefault(t *testing.T) {
	dir := t.TempDir()
	custom := []byte(`{"custom": true}`)
	if err := os.WriteFile(filepath.Join(dir, "ru.json"), custom, 0o644); err != nil {
		t.Fatalf("write custom ru.json: %v", err)
	}

	got, err := Load(dir, "ru")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != string(custom) {
		t.Errorf("Load(dir, ru) = %q, want the dir's custom content", got)
	}
}

func TestLoadFallsBackToEmbeddedDefaults(t *testing.T) {
	dir := t.TempDir() // empty -- no files at all

	for _, lang := range []string{"ru", "en"} {
		b, err := Load(dir, lang)
		if err != nil {
			t.Fatalf("Load(dir, %s): %v", lang, err)
		}
		if len(b) == 0 {
			t.Errorf("Load(dir, %s) returned empty content", lang)
		}
	}

	// Unrecognized language falls back to the embedded English default,
	// not an error.
	b, err := Load(dir, "fr")
	if err != nil {
		t.Fatalf("Load(dir, fr): %v", err)
	}
	if len(b) == 0 {
		t.Errorf("Load(dir, fr) returned empty content")
	}
}
