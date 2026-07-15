#!/bin/sh
# internal/web/web.go embeds internal/web/dist at COMPILE time
# (//go:embed dist) -- on a fresh clone, before `npm run build` has ever
# run, that directory doesn't exist, so `go build`/`go test ./...` fail to
# compile at all (not just fail a test). Drop in a minimal stub so the
# package compiles and the two SPA-shell smoke tests
# (internal/api/routes_smoke_test.go) get a trivial real 200 response
# instead of erroring out.
#
# No-op if a real frontend build is already present (checks for
# dist/index.html) -- never overwrites real build output.
set -e
cd "$(dirname "$0")/.."
DIST=internal/web/dist

if [ -f "$DIST/index.html" ]; then
  exit 0
fi

mkdir -p "$DIST/assets" "$DIST/fonts"
touch "$DIST/assets/.gitkeep" "$DIST/fonts/.gitkeep"

for f in index.html login.html portal.html; do
  cat > "$DIST/$f" <<'EOF'
<!doctype html>
<html><body>Frontend not built -- run: cd frontend && npm ci && npm run build</body></html>
EOF
done

echo "Stubbed $DIST (no real frontend build found) -- run 'cd frontend && npm run build' for the real thing."
