package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/coder/websocket"

	"protean/internal/console"
	"protean/internal/sshexec"
	"protean/internal/store"
	"protean/internal/vpn"
)

// apiConsoleTarget describes one console-able target for the picker. Target
// is always "server:<id>" -- the panel's own host is just a servers row
// with panel_host set (see 0039_panel_host.sql), distinguished only by Kind
// so the frontend can pin/badge it, not by a separate identifier scheme.
type apiConsoleTarget struct {
	Target string `json:"target"`
	Label  string `json:"label"`
	Kind   string `json:"kind"` // "panel-host" | "node"
}

// GET /api/console/targets
func (s *Server) apiConsoleTargets(w http.ResponseWriter, r *http.Request) {
	if s.console == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "console not configured", "консоль не настроена"))
		return
	}
	list, err := s.store.ListServers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var panelHost, rest []apiConsoleTarget
	for _, srv := range list {
		// Consolable iff enrolled as a VPN node (enabled) or flagged as the
		// panel's own host, regardless of enabled -- a panel-host row must
		// stay reachable even if it carries no (or disabled) VPN instances.
		if !srv.Enabled && !srv.PanelHost {
			continue
		}
		kind := "node"
		if srv.PanelHost {
			kind = "panel-host"
		}
		t := apiConsoleTarget{Target: "server:" + srv.ID, Label: srv.Label, Kind: kind}
		if srv.PanelHost {
			panelHost = append(panelHost, t)
		} else {
			rest = append(rest, t)
		}
	}
	writeOK(w, append(panelHost, rest...))
}

type apiConsoleSessionReq struct {
	Target string `json:"target"`
}

type apiConsoleSessionResp struct {
	Ticket      string `json:"ticket"`
	WSURL       string `json:"ws_url"`
	TargetLabel string `json:"target_label"`
	Kind        string `json:"kind"`
}

// consoleTargetServerID parses "server:<id>" into <id>, the only target
// scheme this feature uses today.
func consoleTargetServerID(target string) (string, bool) {
	id, ok := strings.CutPrefix(target, "server:")
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

// POST /api/console/sessions -- mints a short-lived, single-use ticket
// authorizing the WS upgrade at GET /api/console/ws. Runs behind the normal
// cookie+CSRF check (requireAuthAPI): a WS upgrade itself isn't subject to
// the browser's CORS/preflight protections a fetch() gets, so it
// authenticates via this ticket instead of trusting the session cookie
// alone at the upgrade.
func (s *Server) apiConsoleSessionCreate(w http.ResponseWriter, r *http.Request) {
	if s.console == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "console not configured", "консоль не настроена"))
		return
	}
	var req apiConsoleSessionReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	serverID, ok := consoleTargetServerID(req.Target)
	if !ok {
		writeErr(w, http.StatusBadRequest, msg(r, "invalid target", "неверная цель"))
		return
	}
	srv, err := s.store.GetServer(r.Context(), serverID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !srv.Enabled && !srv.PanelHost {
		writeErr(w, http.StatusForbidden, msg(r, "server is disabled", "сервер отключён"))
		return
	}

	username := usernameFromContext(r.Context())
	ticket, err := s.console.Mint(username, serverID)
	if err != nil {
		if errors.Is(err, console.ErrTooManySessions) {
			writeErr(w, http.StatusTooManyRequests, msg(r, "too many concurrent console sessions", "слишком много одновременных сессий консоли"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "console.open", serverID)

	kind := "node"
	if srv.PanelHost {
		kind = "panel-host"
	}
	writeOK(w, apiConsoleSessionResp{
		Ticket:      ticket,
		WSURL:       "/api/console/ws?ticket=" + ticket,
		TargetLabel: srv.Label,
		Kind:        kind,
	})
}

// consoleShell wraps an *sshexec.Session to also release an ephemeral SSH
// connection (if any) when the console session ends -- see
// servers.Manager.ConsoleClient's doc comment for why a console target
// might not have a pooled client to reuse.
type consoleShell struct {
	*sshexec.Session
	closeClient func()
}

func (s *consoleShell) Close() error {
	err := s.Session.Close()
	s.closeClient()
	return err
}

// wsAdapter adapts *websocket.Conn (github.com/coder/websocket) to
// console.WSConn, keeping internal/console free of a dependency on a
// specific WebSocket library so its bridge stays unit-testable against a
// fake.
type wsAdapter struct{ conn *websocket.Conn }

func (a wsAdapter) Read(ctx context.Context) (console.MessageType, []byte, error) {
	typ, data, err := a.conn.Read(ctx)
	if err != nil {
		return 0, nil, err
	}
	if typ == websocket.MessageBinary {
		return console.MessageBinary, data, nil
	}
	return console.MessageText, data, nil
}

func (a wsAdapter) Write(ctx context.Context, typ console.MessageType, data []byte) error {
	wt := websocket.MessageText
	if typ == console.MessageBinary {
		wt = websocket.MessageBinary
	}
	return a.conn.Write(ctx, wt, data)
}

func (a wsAdapter) Close(reason string) error {
	return a.conn.Close(websocket.StatusNormalClosure, reason)
}

func queryUint16(r *http.Request, key string, fallback uint16) uint16 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 || n > 1<<15 {
		return fallback
	}
	return uint16(n)
}

// serveConsoleBridge is the shared body behind every ticket-authenticated
// WS upgrade this feature offers: consume the ticket, enforce concurrency,
// resolve a client for the target, start whatever session `start` asks for
// (an interactive shell for the console, a single streamed command for
// OS-updates apply -- see StartShell/StartCommand's shared *sshexec.Session
// shape), bridge it to the socket, then release/audit on the way out.
// Deliberately NOT wrapped in requireAuthAPI: it's authenticated by a
// single-use ticket (minted via an authenticated+CSRF-checked REST call)
// instead of the session cookie directly, plus an Origin check at upgrade
// (websocket.Accept's OriginPatterns, extended by CONSOLE_ALLOWED_ORIGINS
// for reverse-proxy deployments) -- a WS handshake isn't covered by the
// browser's CORS/preflight protections a cookie-based fetch gets.
func (s *Server) serveConsoleBridge(
	w http.ResponseWriter, r *http.Request, auditAction string,
	start func(ctx context.Context, client *sshexec.Client, rows, cols uint16) (*sshexec.Session, error),
) {
	if s.console == nil || s.mgr == nil {
		http.Error(w, "console not configured", http.StatusServiceUnavailable)
		return
	}
	tok := r.URL.Query().Get("ticket")
	if tok == "" {
		http.Error(w, "missing ticket", http.StatusUnauthorized)
		return
	}
	username, serverID, err := s.console.Consume(tok)
	if err != nil {
		http.Error(w, "invalid or expired ticket", http.StatusUnauthorized)
		return
	}
	release, err := s.console.Acquire(username)
	if err != nil {
		http.Error(w, "too many concurrent console sessions", http.StatusTooManyRequests)
		return
	}

	rows := queryUint16(r, "rows", 24)
	cols := queryUint16(r, "cols", 80)

	client, closeClient, err := s.mgr.ConsoleClient(r.Context(), serverID)
	if err != nil {
		release()
		http.Error(w, "cannot reach target: "+err.Error(), http.StatusBadGateway)
		return
	}
	sess, err := start(r.Context(), client, rows, cols)
	if err != nil {
		closeClient()
		release()
		http.Error(w, "cannot start session: "+err.Error(), http.StatusBadGateway)
		return
	}
	shell := &consoleShell{Session: sess, closeClient: closeClient}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.consoleAllowedOrigins})
	if err != nil {
		// Accept already wrote the HTTP error response on failure.
		_ = shell.Close()
		release()
		return
	}

	bridge := console.NewBridge(wsAdapter{conn}, shell, s.console.IdleTimeout(), s.console.MaxSession())
	_ = bridge.Run(r.Context())
	release()
	s.audit(r.Context(), auditAction, serverID)
}

// GET /api/console/ws -- the interactive shell.
func (s *Server) apiConsoleWS(w http.ResponseWriter, r *http.Request) {
	s.serveConsoleBridge(w, r, "console.close", func(ctx context.Context, client *sshexec.Client, rows, cols uint16) (*sshexec.Session, error) {
		return client.StartShell(ctx, rows, cols, "")
	})
}

// GET /api/console/updates-ws -- streams a single `updates-apply` run
// instead of an interactive shell, over the identical bridge/ticket
// machinery (see sshexec.Client.StartCommand's doc comment: this is
// exactly the reuse it was added for).
func (s *Server) apiConsoleUpdatesWS(w http.ResponseWriter, r *http.Request) {
	s.serveConsoleBridge(w, r, "updates.apply.done", func(ctx context.Context, client *sshexec.Client, rows, cols uint16) (*sshexec.Session, error) {
		// Pre-flight self-heal: updates-apply streams an interactive PTY
		// session live to the admin's browser, so there's no clean way to
		// retry after the fact the way a plain Run-and-capture call gets
		// from Installer.run() automatically on a stale-script mismatch.
		// Best-effort -- if this itself fails, StartCommand below still
		// runs and surfaces whatever error results in the stream, same as
		// before this existed.
		_ = vpn.NewInstaller(client).EnsureCurrent(ctx)
		return client.StartCommand(ctx, "sudo "+vpn.InstallerPath+" updates-apply", rows, cols)
	})
}

type apiPanelHostResp struct {
	ServerID string `json:"server_id"`
	Label    string `json:"label"`
}

// GET /api/console/panel-host
func (s *Server) apiConsolePanelHostGet(w http.ResponseWriter, r *http.Request) {
	srv, err := s.store.GetPanelHost(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		writeOK(w, nil)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiPanelHostResp{ServerID: srv.ID, Label: srv.Label})
}

type apiPanelHostSetReq struct {
	// ServerID empty clears the panel host; non-empty flags that server.
	// Flagging/clearing is a separate operation from create/update-server
	// -- see store.SetPanelHost's doc comment -- reusing the existing
	// add/edit-server flow for credential entry rather than a second one.
	ServerID string `json:"server_id"`
}

// PUT /api/console/panel-host
func (s *Server) apiConsolePanelHostSet(w http.ResponseWriter, r *http.Request) {
	var req apiPanelHostSetReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.ServerID == "" {
		if err := s.store.ClearPanelHost(r.Context()); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r.Context(), "console.panel_host.clear", "")
		writeOK(w, nil)
		return
	}
	if _, err := s.store.GetServer(r.Context(), req.ServerID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetPanelHost(r.Context(), req.ServerID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "console.panel_host.set", req.ServerID)
	writeOK(w, nil)
}
