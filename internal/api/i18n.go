package api

import (
	"fmt"
	"net/http"
	"strings"
)

// requestLang resolves the caller's language from the Accept-Language
// header -- the frontend's HttpUtil sends its current i18next language on
// every request (see frontend/src/api/http-init.ts) specifically so
// backend-generated strings (API error/success messages) match whatever
// the user has the UI set to, instead of being frozen in whatever language
// the original handler happened to be written in. "ru" is the app's
// default UI language, so it's also the fallback here when the header is
// missing/unrecognized.
func requestLang(r *http.Request) string {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language")))
	if strings.HasPrefix(v, "en") {
		return "en"
	}
	return "ru"
}

// msg picks the string in the request's language from an (english,
// russian) pair -- the convention every api_*.go handler uses at each
// writeErr/writeOKMsg call site instead of a keyed catalog: no key
// management, no separate file to keep in sync, and the translation sits
// textually right next to the string it replaces. Positional args are
// (en, ru), matching this codebase's source-comment convention of English
// prose with Russian UI strings.
func msg(r *http.Request, en, ru string) string {
	if requestLang(r) == "en" {
		return en
	}
	return ru
}

// msgf is msg with Sprintf-style formatting for messages that embed a
// value (e.g. a username, count, or duration).
func msgf(r *http.Request, enFmt, ruFmt string, args ...any) string {
	if requestLang(r) == "en" {
		return fmt.Sprintf(enFmt, args...)
	}
	return fmt.Sprintf(ruFmt, args...)
}
