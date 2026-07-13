package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"protean/internal/hostboot"
	"protean/internal/sshexec"
	"protean/internal/store"
)

var validServerID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

type apiServer struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SSHUser    string `json:"ssh_user"`
	PublicHost string `json:"public_host"`
	HostKeySet bool   `json:"host_key_set"`
	Enabled    bool   `json:"enabled"`
}

// GET /api/servers
func (s *Server) apiServersList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListServers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiServer, 0, len(list))
	for _, srv := range list {
		out = append(out, apiServer{
			ID: srv.ID, Label: srv.Label, Host: srv.Host, Port: srv.Port,
			SSHUser: srv.SSHUser, PublicHost: srv.PublicHost, HostKeySet: srv.HostKey != "",
			Enabled: srv.Enabled,
		})
	}
	writeOK(w, out)
}

type apiServerCreateReq struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SSHUser    string `json:"ssh_user"` // target service account; blank -> "protean"
	PublicHost string `json:"public_host"`
	HostKey    string `json:"host_key"`

	// Existing-key path: paste a private key for an account that's already
	// fully set up on the host as-is (SSHUser as given, no bootstrap).
	SSHKey string `json:"ssh_key"`

	// Bootstrap path: connect once as BootstrapUser ("root" or an existing
	// sudo user) via BootstrapPassword or BootstrapKey (exactly one),
	// create-or-reuse SSHUser and grant it narrow rights, then discard the
	// credential -- only the panel's own freshly generated key is stored,
	// against SSHUser.
	BootstrapUser     string `json:"bootstrap_user"`
	BootstrapPassword string `json:"bootstrap_password"`
	BootstrapKey      string `json:"bootstrap_key"`
}

// POST /api/servers
func (s *Server) apiServersCreate(w http.ResponseWriter, r *http.Request) {
	var req apiServerCreateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	id := strings.TrimSpace(req.ID)
	if !validServerID.MatchString(id) {
		writeErr(w, http.StatusBadRequest, msg(r, "server id must be a slug: lowercase letters, digits, '-' or '_'", "id сервера должен быть слагом: строчные буквы, цифры, '-' или '_'"))
		return
	}
	port := req.Port
	if port == 0 {
		port = 22
	}
	host := strings.TrimSpace(req.Host)
	sshUser := strings.TrimSpace(req.SSHUser)
	if sshUser == "" {
		sshUser = "protean"
	}
	hostKey := strings.TrimSpace(req.HostKey)

	keyPEM := strings.TrimSpace(req.SSHKey)
	bootstrapUser := strings.TrimSpace(req.BootstrapUser)
	bootstrapKey := strings.TrimSpace(req.BootstrapKey)
	var accountNote string
	switch {
	case keyPEM != "":
		// existing-key path: use as-is, no bootstrap.
	case bootstrapUser != "":
		if host == "" {
			writeErr(w, http.StatusBadRequest, msg(r, "host is required to bootstrap", "для настройки хоста необходим host"))
			return
		}
		if (req.BootstrapPassword == "") == (bootstrapKey == "") {
			writeErr(w, http.StatusBadRequest, msg(r, "provide exactly one of bootstrap_password or bootstrap_key", "укажите ровно одно из bootstrap_password или bootstrap_key"))
			return
		}
		priv, pub, gerr := sshexec.GenerateKeyPair("protean@" + id)
		if gerr != nil {
			writeErr(w, http.StatusInternalServerError, msgf(r, "keygen failed: %v", "не удалось сгенерировать ключ: %v", gerr))
			return
		}
		auth := sshexec.BootstrapAuth{Password: req.BootstrapPassword}
		if bootstrapKey != "" {
			auth = sshexec.BootstrapAuth{KeyPEM: []byte(bootstrapKey)}
		}
		out, berr := sshexec.BootstrapHost(r.Context(), sshexec.Config{
			Host: host, Port: port, User: bootstrapUser, HostKey: hostKey,
		}, auth, sshUser, pub, hostboot.InstallerScript(), hostboot.InstallerPath)
		if berr != nil {
			writeErr(w, http.StatusBadGateway, msgf(r, "host bootstrap failed: %v", "не удалось настроить хост: %v", berr))
			return
		}
		keyPEM = string(priv)
		if strings.Contains(out, "PROTEAN_USER_CREATED") {
			accountNote = msgf(r, "created a new account %q on the host", "на хосте создана новая учётная запись %q", sshUser)
		} else {
			accountNote = msgf(r, "granted rights to the existing account %q on the host", "существующей учётной записи %q на хосте выданы права", sshUser)
		}
	default:
		writeErr(w, http.StatusBadRequest, msg(r, "provide ssh_key or bootstrap_user with bootstrap_password/bootstrap_key", "укажите ssh_key либо bootstrap_user с bootstrap_password/bootstrap_key"))
		return
	}
	if host == "" || sshUser == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "host and ssh_user are required", "host и ssh_user обязательны"))
		return
	}
	sealed, err := s.enc.Seal(keyPEM)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "encrypt key: %v", "не удалось зашифровать ключ: %v", err))
		return
	}
	srv := store.Server{
		ID: id, Label: strings.TrimSpace(req.Label), Host: host, Port: port,
		SSHUser: sshUser, EncKeyPEM: sealed, HostKey: hostKey,
		PublicHost: strings.TrimSpace(req.PublicHost),
	}
	if err := s.store.CreateServer(r.Context(), srv); err != nil {
		writeErr(w, http.StatusInternalServerError, msgf(r, "create failed: %v", "не удалось создать: %v", err))
		return
	}
	s.audit(r.Context(), "server.create", id)
	out := apiServer{
		ID: id, Label: srv.Label, Host: host, Port: port, SSHUser: sshUser,
		PublicHost: srv.PublicHost, HostKeySet: hostKey != "", Enabled: true,
	}
	if s.mgr != nil {
		if err := s.mgr.Rebuild(r.Context(), id); err != nil {
			writeOKMsg(w, msgf(r, "server saved, but connecting failed: %v", "сервер сохранён, но подключиться не удалось: %v", err), out)
			return
		}
	}
	if accountNote != "" {
		writeOKMsg(w, accountNote, out)
		return
	}
	writeOK(w, out)
}

type apiServerUpdateReq struct {
	Label      string `json:"label"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	SSHUser    string `json:"ssh_user"`
	PublicHost string `json:"public_host"`
	HostKey    string `json:"host_key"`
	SSHKey     string `json:"ssh_key"` // optional: blank keeps the existing key
}

// PUT /api/servers/{id}
func (s *Server) apiServersUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.store.GetServer(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
		return
	}
	var req apiServerUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	port := req.Port
	if port == 0 {
		port = existing.Port
	}
	srv := existing
	srv.Label = strings.TrimSpace(req.Label)
	srv.Host = strings.TrimSpace(req.Host)
	srv.Port = port
	srv.SSHUser = strings.TrimSpace(req.SSHUser)
	// Like EncKeyPEM below: an empty field means "keep the existing value",
	// not "clear it" -- the edit form can't round-trip the pinned key (the
	// list endpoint only ever exposes host_key_set, never the key itself),
	// so treating empty as "wipe the pin" silently un-pins the host on any
	// edit that doesn't re-run "Probe" first.
	if hostKey := strings.TrimSpace(req.HostKey); hostKey != "" {
		srv.HostKey = hostKey
	}
	srv.PublicHost = strings.TrimSpace(req.PublicHost)
	if key := strings.TrimSpace(req.SSHKey); key != "" {
		sealed, err := s.enc.Seal(key)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, msgf(r, "encrypt key: %v", "не удалось зашифровать ключ: %v", err))
			return
		}
		srv.EncKeyPEM = sealed
	}
	if srv.Host == "" || srv.SSHUser == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "host and ssh_user are required", "host и ssh_user обязательны"))
		return
	}
	if err := s.store.UpdateServer(r.Context(), srv); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "server.update", id)
	if s.mgr != nil {
		if err := s.mgr.Rebuild(r.Context(), id); err != nil {
			writeOKMsg(w, msgf(r, "server saved, but reconnecting failed: %v", "сервер сохранён, но переподключиться не удалось: %v", err), nil)
			return
		}
	}
	writeOK(w, apiServer{
		ID: id, Label: srv.Label, Host: srv.Host, Port: srv.Port, SSHUser: srv.SSHUser,
		PublicHost: srv.PublicHost, HostKeySet: srv.HostKey != "", Enabled: srv.Enabled,
	})
}

type apiServerEnabledReq struct {
	Enabled bool `json:"enabled"`
}

// POST /api/servers/{id}/enabled — disable/enable a server (backlog item
// 16): disabling drops its live SSH connection/providers from the registry
// immediately but leaves server_instances and every provider-keyed setting
// untouched in the DB; enabling reconnects and re-registers everything
// exactly as it was. Distinct from DELETE, which wipes that data.
func (s *Server) apiServersSetEnabled(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req apiServerEnabledReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.UpdateServerEnabled(r.Context(), id, req.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.mgr != nil {
		if req.Enabled {
			if err := s.mgr.Rebuild(r.Context(), id); err != nil {
				s.audit(r.Context(), "server.enable", id)
				writeOKMsg(w, msgf(r, "server enabled, but connecting failed: %v", "сервер включён, но подключиться не удалось: %v", err), nil)
				return
			}
		} else {
			s.mgr.Remove(id)
		}
	}
	s.audit(r.Context(), "server."+map[bool]string{true: "enable", false: "disable"}[req.Enabled], id)
	writeOK(w, nil)
}

// DELETE /api/servers/{id} — full delete: unlike disabling, this wipes
// every provider-keyed setting/secret/history row for each of this
// server's instances (see store.DeleteProviderData) before dropping the
// server row itself (server_instances cascades via FK automatically).
func (s *Server) apiServersDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	instances, err := s.store.ListServerInstances(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, inst := range instances {
		if err := s.store.DeleteProviderData(ctx, id+":"+inst.LocalName); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	if err := s.store.DeleteServer(ctx, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.mgr != nil {
		s.mgr.Remove(id)
	}
	s.audit(ctx, "server.delete", id)
	writeOK(w, nil)
}

type apiProbeHostKeyReq struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type apiProbeHostKeyResp struct {
	AuthorizedKey string `json:"authorized_key"`
	Fingerprint   string `json:"fingerprint"`
}

// POST /api/ssh/probe-host-key -- fetches the SSH host key currently
// presented at host:port, so an admin can pin it (Servers page's Host key
// field) without ever SSHing in by hand. Host/port are taken from the
// request body, not an existing server row -- this needs to work from the
// create form too, before any server exists.
//
// This is NOT itself a security check: like ssh-keyscan, the connection
// used to fetch the key is exposed to exactly the same MITM risk as any
// other -- the admin still has to confirm the returned fingerprint through
// some independent channel (cloud provider console, direct console
// access, etc.) before trusting it. It just removes the need to run a
// terminal command by hand to get that fingerprint in the first place.
func (s *Server) apiProbeHostKey(w http.ResponseWriter, r *http.Request) {
	var req apiProbeHostKeyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "host is required", "требуется адрес хоста"))
		return
	}
	port := req.Port
	if port == 0 {
		port = 22
	}
	authorizedKey, fingerprint, err := sshexec.ProbeHostKey(r.Context(), host, port, 0)
	if err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "couldn't fetch the host key: %v", "не удалось получить ключ хоста: %v", err))
		return
	}
	s.audit(r.Context(), "server.probe_host_key", host)
	writeOK(w, apiProbeHostKeyResp{AuthorizedKey: authorizedKey, Fingerprint: fingerprint})
}
