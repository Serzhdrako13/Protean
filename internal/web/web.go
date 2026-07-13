// Package web embeds and serves the panel's UI: the React SPA built by
// frontend/ (see frontend/vite.config.ts).
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

// distFS is the built React SPA (frontend/, output by `vite build` straight
// into this directory — see frontend/vite.config.ts). Built by the Docker
// image's node stage before `go build` runs; see repo root Dockerfile.
//
//go:embed dist
var distFS embed.FS

// SPAAssetsHandler serves the SPA's bundled JS/CSS (frontend dist/assets/*,
// hashed filenames) — mount at "/assets/".
func SPAAssetsHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist/assets")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/assets/", http.FileServer(http.FS(sub)))
}

// SPAFontsHandler serves static font files placed under frontend/public/fonts
// (Vite copies frontend/public/* verbatim to the dist root, so these land
// at dist/fonts/*, not dist/assets/* — hence their own handler/prefix) —
// mount at "/fonts/". Without this, requests for e.g. /fonts/*.otf fell
// through to the "GET /" SPA catch-all and got back index.html's markup
// with a 200 instead of the actual font, which made @font-face silently
// fail (wrong content-type, HTML body) instead of erroring visibly.
func SPAFontsHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist/fonts")
	if err != nil {
		panic(err)
	}
	return http.StripPrefix("/fonts/", http.FileServer(http.FS(sub)))
}

// ServeIndexHTML serves the SPA shell (client-side router resolves the rest).
func ServeIndexHTML(w http.ResponseWriter, r *http.Request) { serveDistFile(w, "dist/index.html") }

// ServeLoginHTML serves the SPA's standalone login entry.
func ServeLoginHTML(w http.ResponseWriter, r *http.Request) { serveDistFile(w, "dist/login.html") }

// ServePortalHTML serves the self-service portal's standalone entry (no
// sidebar/admin router at all — a "user"-role account never reaches the
// admin SPA, only this).
func ServePortalHTML(w http.ResponseWriter, r *http.Request) { serveDistFile(w, "dist/portal.html") }

func serveDistFile(w http.ResponseWriter, name string) {
	b, err := distFS.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
