package api

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"protean/internal/auth"
	"protean/internal/vpn/clientconfig"
)

// GET /api/csrf — the SPA fetches this once on load and sends the token back
// as the X-CSRF-Token header on every state-changing request. Also doubles
// as the one unauthenticated, always-called-on-boot endpoint every SPA
// entry (admin/login/portal) can use to detect an insecure connection --
// see isSecure and the frontend's InsecureConnectionBanner.
func (s *Server) apiCSRF(w http.ResponseWriter, r *http.Request) {
	token := s.ensureCSRFCookie(w, r)
	writeOK(w, map[string]any{"csrf_token": token, "https": s.isSecure(r)})
}

type apiLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Method: "local" (default, if omitted) or "ldap". "oidc" never goes
	// through this endpoint -- see GET /api/auth/oidc/start.
	Method string `json:"method"`
}

// POST /api/login — mirrors handleLoginSubmit but responds JSON instead of
// redirecting/rendering. needTOTP == true means the password checked out but
// a second call to /api/login/2fa (with the returned pending token) is
// required before a session cookie is issued. LDAP logins never need TOTP
// (see Manager.FinishExternalLogin), so needTOTP is always false for them.
func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	token := s.ensureCSRFCookie(w, r)
	if !s.validCSRF(r, token) {
		writeErr(w, http.StatusForbidden, msg(r, "session expired, reload and try again", "сессия истекла, обновите страницу и попробуйте снова"))
		return
	}
	var req apiLoginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	username := strings.TrimSpace(req.Username)
	ip := s.clientIP(r)

	check, err := s.bruteForce.CheckLogin(r.Context(), ip, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !check.Allowed {
		s.bruteForce.LogRejected(r.Context(), ip, username, check.Reason)
		writeErr(w, http.StatusTooManyRequests, auth.RejectionMessage(check, requestLang(r)))
		return
	}

	var sessionToken string
	var expires time.Time
	var needTOTP bool
	if req.Method == "ldap" {
		sessionToken, expires, err = s.auth.LoginLDAP(r.Context(), username, req.Password)
	} else {
		sessionToken, expires, needTOTP, err = s.auth.Login(r.Context(), username, req.Password)
	}
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountDisabled):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "account_disabled")
			writeErr(w, http.StatusForbidden, msg(r, "this account has been disabled", "эта учётная запись отключена"))
		case errors.Is(err, auth.ErrPortalAccessDenied):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "portal_access_denied")
			writeErr(w, http.StatusForbidden, msg(r, "portal access has been disabled for this account", "доступ к порталу для этой учётной записи отключён"))
		case errors.Is(err, auth.ErrInternalAuthDisabled), errors.Is(err, auth.ErrMethodDisabled):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "method_disabled")
			writeErr(w, http.StatusForbidden, msg(r, "this login method is disabled, use one of the methods offered", "этот способ входа отключён, используйте один из предложенных"))
		case errors.Is(err, auth.ErrNoGroupMatch):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "no_group_match")
			writeErr(w, http.StatusForbidden, msg(r, "account is not a member of any allowed group", "учётная запись не состоит ни в одной из разрешённых групп"))
		default:
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "bad_password")
			writeErr(w, http.StatusUnauthorized, msg(r, "invalid username or password", "неверное имя пользователя или пароль"))
		}
		return
	}
	if needTOTP {
		// Not recorded as a success yet -- the login isn't complete until
		// apiLogin2FA verifies the code; that call records the real outcome.
		writeOK(w, map[string]any{"need_totp": true, "pending": s.pending.Issue(username)})
		return
	}
	_ = s.bruteForce.RecordResult(r.Context(), ip, username, true, "")
	s.setSessionCookie(w, sessionToken, expires)
	writeOK(w, map[string]any{"need_totp": false})
}

type apiLogin2FAReq struct {
	Pending string `json:"pending"`
	Code    string `json:"code"`
}

// POST /api/login/2fa completes a login started by apiLogin when needTOTP.
func (s *Server) apiLogin2FA(w http.ResponseWriter, r *http.Request) {
	token := s.ensureCSRFCookie(w, r)
	if !s.validCSRF(r, token) {
		writeErr(w, http.StatusForbidden, msg(r, "session expired, reload and try again", "сессия истекла, обновите страницу и попробуйте снова"))
		return
	}
	var req apiLogin2FAReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	username, ok := s.pending.Verify(req.Pending)
	if !ok {
		writeErr(w, http.StatusUnauthorized, msg(r, "login timed out, please start over", "время входа истекло, начните заново"))
		return
	}
	ip := s.clientIP(r)

	check, err := s.bruteForce.CheckLogin(r.Context(), ip, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !check.Allowed {
		s.bruteForce.LogRejected(r.Context(), ip, username, check.Reason)
		writeErr(w, http.StatusTooManyRequests, auth.RejectionMessage(check, requestLang(r)))
		return
	}

	sessionToken, expires, err := s.auth.CompleteTOTPLogin(r.Context(), username, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAccountDisabled):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "account_disabled")
			writeErr(w, http.StatusForbidden, msg(r, "this account has been disabled", "эта учётная запись отключена"))
		case errors.Is(err, auth.ErrPortalAccessDenied):
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "portal_access_denied")
			writeErr(w, http.StatusForbidden, msg(r, "portal access has been disabled for this account", "доступ к порталу для этой учётной записи отключён"))
		default:
			_ = s.bruteForce.RecordResult(r.Context(), ip, username, false, "bad_totp")
			writeErr(w, http.StatusUnauthorized, msg(r, "invalid code", "неверный код"))
		}
		return
	}
	_ = s.bruteForce.RecordResult(r.Context(), ip, username, true, "")
	s.setSessionCookie(w, sessionToken, expires)
	writeOK(w, nil)
}

// GET /api/auth/oidc/start -- redirects the browser to the configured
// IdP's authorization endpoint. Reached from both the admin login page and
// the portal's login form (same button, same flow -- the resolved role
// after callback decides which shell the browser ends up in, not which
// page started the flow).
func (s *Server) apiOIDCStart(w http.ResponseWriter, r *http.Request) {
	authURL, err := s.auth.StartOIDC(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "couldn't start OIDC login: %v", "не удалось начать вход через OIDC: %v", err))
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /api/auth/oidc/callback -- the IdP redirects the browser back here
// with ?state&code. A top-level browser navigation, not a fetch() call, so
// failures redirect back to the login page with a marker rather than
// returning a JSON error the SPA would never see.
func (s *Server) apiOIDCCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	sessionToken, expires, err := s.auth.FinishOIDC(r.Context(), state, code)
	if err != nil {
		http.Redirect(w, r, "/login?oidc_error=1", http.StatusFound)
		return
	}
	s.setSessionCookie(w, sessionToken, expires)
	_, _, role, _, _, authErr := s.auth.Authenticate(r.Context(), sessionToken)
	target := "/"
	if authErr == nil && role == "user" {
		target = "/portal"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// POST /api/logout
func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		_ = s.auth.Logout(r.Context(), cookie.Value)
	}
	s.clearSessionCookie(w)
	writeOK(w, nil)
}

type apiAccount struct {
	Username        string `json:"username"`
	TOTPEnabled     bool   `json:"totp_enabled"`
	PasswordExpired bool   `json:"password_expired"`
	// Language is the account's saved UI language preference, empty if
	// never set (frontend falls back to browser/localStorage detection).
	Language string `json:"language,omitempty"`
}

// GET /api/account
func (s *Server) apiAccountGet(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r.Context())
	userID := userIDFromContext(r.Context())
	enabled, _ := s.auth.TOTPEnabled(r.Context(), userID)
	expired := s.isPasswordExpired(r.Context(), passwordChangedAtFromContext(r.Context()))
	u, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiAccount{Username: username, TOTPEnabled: enabled, PasswordExpired: expired, Language: u.Language})
}

var validLanguages = map[string]bool{"ru": true, "en": true}

type apiLanguageReq struct {
	Language string `json:"language"`
}

// PUT /api/account/language — save the account's UI language preference so
// it follows the user across devices/browsers instead of resetting on
// every new machine (previously localStorage-only).
func (s *Server) apiAccountUpdateLanguage(w http.ResponseWriter, r *http.Request) {
	var req apiLanguageReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if !validLanguages[req.Language] {
		writeErr(w, http.StatusBadRequest, msg(r, "unknown language", "неизвестный язык"))
		return
	}
	if err := s.store.UpdateUserLanguage(r.Context(), userIDFromContext(r.Context()), req.Language); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, nil)
}

type apiPasswordReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// POST /api/account — change password.
func (s *Server) apiAccountUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiPasswordReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	err := s.auth.ChangePassword(r.Context(), userIDFromContext(r.Context()), req.CurrentPassword, req.NewPassword)
	var policyErr *auth.PolicyError
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErr(w, http.StatusUnauthorized, msg(r, "current password is incorrect", "текущий пароль указан неверно"))
	case errors.As(err, &policyErr):
		writeErr(w, http.StatusBadRequest, auth.PolicyErrorMessage(err, requestLang(r)))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		writeOKMsg(w, msg(r, "password changed", "пароль изменён"), nil)
	}
}

// POST /api/account/2fa/setup — generates (but doesn't persist) a fresh TOTP
// secret + enrollment QR.
func (s *Server) apiTOTPSetup(w http.ResponseWriter, r *http.Request) {
	username := usernameFromContext(r.Context())
	secret, url, err := auth.GenerateTOTPSecret(username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	png, err := clientconfig.QRPNG(url)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]string{
		"secret": secret,
		"qr_png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

type apiTOTPEnableReq struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// POST /api/account/2fa/enable
func (s *Server) apiTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req apiTOTPEnableReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	username := usernameFromContext(r.Context())
	if err := s.auth.EnableTOTP(r.Context(), userIDFromContext(r.Context()), req.Secret, req.Code); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "code did not verify", "код не подтверждён"))
		return
	}
	s.audit(r.Context(), "account.2fa_enable", username)
	writeOKMsg(w, msg(r, "two-factor authentication enabled", "двухфакторная аутентификация включена"), nil)
}

type apiTOTPDisableReq struct {
	Password string `json:"password"`
}

// POST /api/account/2fa/disable
func (s *Server) apiTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req apiTOTPDisableReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	username := usernameFromContext(r.Context())
	err := s.auth.DisableTOTP(r.Context(), userIDFromContext(r.Context()), req.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErr(w, http.StatusUnauthorized, msg(r, "password is incorrect", "пароль указан неверно"))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		s.audit(r.Context(), "account.2fa_disable", username)
		writeOKMsg(w, msg(r, "two-factor authentication disabled", "двухфакторная аутентификация отключена"), nil)
	}
}
