// Package version holds Protean's release version, bumped by hand
// alongside the git tag, CHANGELOG.md, and frontend/package.json -- there's
// no build pipeline that injects this via ldflags, so it's a plain
// constant kept in sync manually at release time.
package version

const Version = "0.3.2-alpha"
