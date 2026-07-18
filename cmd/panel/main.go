// Command panel is the Protean web server entrypoint.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"

	"protean/internal/api"
	"protean/internal/auth"
	"protean/internal/config"
	"protean/internal/console"
	"protean/internal/keyrotate"
	"protean/internal/servers"
	"protean/internal/store"
	"protean/internal/vpn"
	"protean/internal/vpn/xray"
	"protean/internal/vpnsetup"
	"protean/internal/webtls"
)

// seedDefaultServer creates a "default" server row from the legacy SSH_* env
// on first run (no servers yet), so an existing single-server deployment keeps
// working after the multi-server migration. No-op if servers already exist or
// no SSH host is configured (fresh multi-server install adds servers via UI).
func seedDefaultServer(ctx context.Context, st *store.Store, enc *auth.Encryptor, cfg config.Config) error {
	if cfg.SSHHost == "" || cfg.SSHKeyPath == "" {
		return nil
	}
	n, err := st.CountServers(ctx)
	if err != nil || n > 0 {
		return err
	}
	keyPEM, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return fmt.Errorf("read SSH key for default server: %w", err)
	}
	sealed, err := enc.Seal(string(keyPEM))
	if err != nil {
		return err
	}
	slog.Info("seeding 'default' server from SSH_* env")
	return st.CreateServer(ctx, store.Server{
		ID: "default", Label: "default", Host: cfg.SSHHost, Port: cfg.SSHPort,
		SSHUser: cfg.SSHUser, EncKeyPEM: sealed, HostKey: cfg.SSHHostKey, PublicHost: cfg.PublicHost,
	})
}

// setupLogging installs a structured slog handler as the process default.
// LOG_LEVEL (debug|info|warn|error) and LOG_FORMAT (text|json) tune it.
func setupLogging() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if strings.EqualFold(os.Getenv("LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// fatal logs a structured error and exits non-zero (startup failures).
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe the running server's /healthz and exit (for container healthchecks)")
	rotateOldKey := flag.String("rotate-key-old", "", "re-encrypt every stored secret: 64-char hex SECRET_KEY currently in use")
	rotateNewKey := flag.String("rotate-key-new", "", "re-encrypt every stored secret: 64-char hex SECRET_KEY to rotate to")
	rotateDryRun := flag.Bool("rotate-key-dry-run", false, "with -rotate-key-old/-new: report what would change, then roll back instead of committing")
	rotateDetect := flag.String("rotate-key-detect", "", "read-only: report whether this 64-char hex key can open the database's sealed secrets, then exit")
	flag.Parse()
	if *healthcheck {
		runHealthcheck()
		return
	}
	if *rotateDetect != "" {
		runRotateKeyDetect(*rotateDetect)
		return
	}
	if *rotateOldKey != "" || *rotateNewKey != "" {
		runRotateKey(*rotateOldKey, *rotateNewKey, *rotateDryRun)
		return
	}

	setupLogging()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		fatal("config", "err", err)
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal("database", "err", err)
	}
	defer st.Close()

	// Refuse to run a second instance against the same DB: the panel's
	// in-process config lock only protects a single process (the login
	// brute-force guard itself is DB-backed now and would be fine shared,
	// but nothing else in this process-wide singleton design is).
	if err := st.AcquireSingletonLock(ctx); err != nil {
		fatal("startup", "err", err)
	}

	if err := store.Migrate(ctx, st); err != nil {
		fatal("migrate", "err", err)
	}

	enc, err := auth.NewEncryptor(cfg.SecretKeyHex)
	if err != nil {
		fatal("encryptor", "err", err)
	}

	authMgr := auth.NewManager(st, cfg.SessionSecret, enc, cfg.EmergencyAdminUsername)
	if cfg.AdminUsername != "" && cfg.AdminPassword != "" {
		if err := authMgr.SeedAdmin(ctx, cfg.AdminUsername, cfg.AdminPassword); err != nil {
			fatal("seed admin", "err", err)
		}
	}
	if cfg.EmergencyAdminUsername != "" && cfg.EmergencyAdminPassword != "" {
		slog.Warn("EMERGENCY_ADMIN_USERNAME/PASSWORD are set -- break-glass admin account is force-enabled and bypasses the internal-auth-disabled toggle; unset both env vars once access is recovered",
			"username", cfg.EmergencyAdminUsername)
		if err := authMgr.SeedEmergencyAdmin(ctx, cfg.EmergencyAdminUsername, cfg.EmergencyAdminPassword); err != nil {
			fatal("seed emergency admin", "err", err)
		}
	}

	csrf := auth.NewCSRF(cfg.SessionSecret)
	pending := auth.NewPendingAuth(cfg.SessionSecret)

	reg := vpn.NewRegistry()
	mgr := servers.NewManager(st, enc, reg, servers.Template{
		WGInterfaces:      cfg.WireGuardInterfaces,
		AWGInterfaces:     cfg.AmneziaWGInterfaces,
		OpenVPNInstance:   cfg.OpenVPNInstance,
		OpenVPNListenPort: cfg.OpenVPNListenPort,
		OpenVPNProto:      cfg.OpenVPNProto,
		OpenVPNServerNet:  cfg.OpenVPNServerNet,
		OpenVPNServerMask: cfg.OpenVPNServerMask,
		IKEv2Pool:         cfg.IKEv2Pool,
		IKEv2DNS:          cfg.IKEv2DNS,
		SSHTimeout:        10 * time.Second,
		SSHCmdTimeout:     cfg.SSHCmdTimeout,
	})
	// Seed a "default" server from the legacy SSH_* env on first run, so an
	// existing single-server install migrates transparently.
	if err := seedDefaultServer(ctx, st, enc, cfg); err != nil {
		fatal("seed default server", "err", err)
	}
	if err := mgr.LoadAll(ctx); err != nil {
		slog.Error("load servers (some may be unavailable)", "err", err)
	}
	defer mgr.CloseAll()

	srv := api.NewServer(reg, st, authMgr, enc, csrf, pending, cfg.MetricsToken)
	srv.SetHostsFunc(func() map[string]api.HostProbe {
		out := map[string]api.HostProbe{}
		for id, c := range mgr.Hosts() {
			out[id] = c
		}
		return out
	})
	srv.SetInstallerFunc(mgr.Installer)
	srv.SetServerManager(mgr)
	srv.SetTrustProxy(cfg.TrustProxy)
	srv.SetCookieInsecure(cfg.CookieInsecure)
	srv.SetConsoleHub(console.NewHub(console.Config{
		IdleTimeout: cfg.ConsoleIdleTimeout,
		MaxSession:  cfg.ConsoleMaxSession,
		MaxPerUser:  cfg.ConsoleMaxPerUser,
		MaxTotal:    cfg.ConsoleMaxTotal,
	}))
	srv.SetConsoleAllowedOrigins(cfg.ConsoleAllowedOrigins)
	srv.StartExpiryWorker(ctx, 5*time.Minute)
	srv.ReconcileState(ctx)        // log DB-vs-host divergences at startup
	srv.ReapplyMeshForwarding(ctx) // cert-provider FORWARD rules don't survive reboot
	srv.StartNotifyWatcher(ctx, time.Minute)
	srv.StartReportWorker(ctx, 10*time.Minute)
	srv.StartTrafficSampler(ctx, cfg.TrafficSampleInterval, cfg.TrafficRetention)
	srv.StartConnectionHistoryPruner(ctx, cfg.ConnectionHistoryRetention)
	srv.StartDataRetentionCleanup(ctx)
	if err := vpnsetup.EnsureSeeded(cfg.VPNSetupContentDir); err != nil {
		slog.Warn("vpn-setup: could not seed content dir, falling back to built-in defaults", "dir", cfg.VPNSetupContentDir, "err", err)
	}
	srv.SetVPNSetupDir(cfg.VPNSetupContentDir)

	if err := xray.SeedExampleModule(cfg.XrayModulesDir); err != nil {
		slog.Warn("xray: could not seed example module", "dir", cfg.XrayModulesDir, "err", err)
	}
	xray.SetModulesDir(cfg.XrayModulesDir)
	if loaded, warnings := xray.LoadModulesDir(cfg.XrayModulesDir); loaded > 0 || len(warnings) > 0 {
		slog.Info("xray: file-based modules loaded", "dir", cfg.XrayModulesDir, "loaded", loaded)
		for _, w := range warnings {
			slog.Warn("xray: module skipped", "dir", cfg.XrayModulesDir, "reason", w)
		}
	}

	// The panel's own web TLS: a self-signed cert is bootstrapped on first
	// ever run and kept forever as a permanent fallback, so the panel is
	// reachable over HTTPS from the very first boot -- no plain-HTTP mode
	// exists except "proxy" (a reverse proxy like Traefik terminates TLS in
	// front; this listener then talks plain HTTP only to that proxy on the
	// private network, which is the normal/expected pattern for that setup).
	tlsMgr := webtls.New(st, enc)
	if err := tlsMgr.Load(ctx); err != nil {
		fatal("tls bootstrap", "err", err)
	}
	go tlsMgr.RunRenewLoop(ctx, time.Hour)
	srv.SetTLSManager(tlsMgr)

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var acmeHTTPServer *http.Server
	status := tlsMgr.GetStatus()
	proxyMode := status.Mode == "proxy"
	if !proxyMode {
		httpServer.TLSConfig = &tls.Config{
			GetCertificate: tlsMgr.GetCertificate,
			// acme.ALPNProto ("acme-tls/1") must be advertised even when
			// ACME isn't the active mode yet -- switching TO acme mode at
			// runtime (internal/api's TLS settings page) reconfigures the
			// certificate source, not this listener, so TLS-ALPN-01 has to
			// already be negotiable without a process restart.
			NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		}
	}
	// ACME HTTP-01 (an explicit admin choice -- TLS-ALPN-01 above is the
	// default and needs no extra port) must answer on port 80 exactly; that's
	// the ACME protocol's requirement, not something this panel can relocate.
	if acmeHandler := tlsMgr.HTTPHandler(nil); acmeHandler != nil {
		acmeHTTPServer = &http.Server{Addr: ":80", Handler: acmeHandler, ReadHeaderTimeout: 10 * time.Second}
	}

	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown", "err", err)
		}
		if acmeHTTPServer != nil {
			if err := acmeHTTPServer.Shutdown(shutdownCtx); err != nil {
				slog.Error("shutdown (acme http-01)", "err", err)
			}
		}
	}()

	if acmeHTTPServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("listening (acme http-01 challenge)", "addr", ":80")
			if err := acmeHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("acme http-01 listener", "err", err)
			}
		}()
	}

	if proxyMode {
		slog.Info("listening (behind reverse proxy, plain HTTP)", "addr", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal("serve", "err", err)
		}
	} else {
		slog.Info("listening (HTTPS)", "addr", cfg.ListenAddr, "tls_mode", status.Mode)
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			fatal("listen", "err", err)
		}
		// Wrapped so a plain-HTTP request on this TLS-only listener (the
		// classic "typed http:// instead of https://" mistake, expected
		// often here since self-signed is the default) gets a 301 redirect
		// to the https URL instead of Go's bare "Client sent an HTTP
		// request to an HTTPS server" diagnostic.
		if err := httpServer.ServeTLS(webtls.RedirectPlainHTTP(ln), "", ""); err != nil && err != http.ErrServerClosed {
			fatal("serve", "err", err)
		}
	}
	wg.Wait()
	// HTTP is down and ctx is cancelled; give background workers a moment to
	// finish their current iteration (e.g. an in-flight write-conf) before exit.
	srv.WaitWorkers(15 * time.Second)
	slog.Info("shutdown complete")
}

// runHealthcheck hits the local server's /healthz and exits non-zero on
// failure, so the distroless image (no curl/shell) can still be
// health-checked by `/panel -healthcheck`.
func runHealthcheck() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	// LISTEN_ADDR may be ":8080" or "0.0.0.0:8080"; probe loopback.
	_, port, ok := strings.Cut(addr, ":")
	if !ok {
		port = "8080"
	}
	// The listener speaks HTTPS by default (self-signed at minimum, see
	// internal/webtls) and only ever plain HTTP in "proxy" mode -- this
	// short-lived exec doesn't know the process's in-memory mode, so try
	// HTTPS first (cert validity doesn't matter for a loopback liveness
	// probe) and fall back to plain HTTP for the proxy-mode case.
	httpsClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback liveness probe only
	}}
	if ok := probe(httpsClient, fmt.Sprintf("https://127.0.0.1:%s/healthz", port)); ok {
		return
	}
	plainClient := &http.Client{Timeout: 4 * time.Second}
	if ok := probe(plainClient, fmt.Sprintf("http://127.0.0.1:%s/healthz", port)); ok {
		return
	}
	fmt.Fprintln(os.Stderr, "healthcheck: neither HTTPS nor plain HTTP responded")
	os.Exit(1)
}

func probe(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// openStoreForRotation opens the store directly off DATABASE_URL (not
// config.Load, which also demands SESSION_SECRET/SECRET_KEY/etc. that a
// key-rotation run has no use for) and takes the same singleton advisory
// lock the running panel holds for its whole lifetime -- so this refuses
// outright if the real panel is up, rather than racing its writes. See
// internal/keyrotate's package doc for why that exclusivity matters.
func openStoreForRotation(ctx context.Context) *store.Store {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fatal("rotate-key: DATABASE_URL is not set")
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		fatal("rotate-key: open database", "err", err)
	}
	if err := st.AcquireSingletonLock(ctx); err != nil {
		fatal("rotate-key: another instance holds the database lock -- stop the running panel first", "err", err)
	}
	if err := store.Migrate(ctx, st); err != nil {
		fatal("rotate-key: migrate", "err", err)
	}
	return st
}

func runRotateKeyDetect(keyHex string) {
	setupLogging()
	ctx := context.Background()
	st := openStoreForRotation(ctx)
	defer st.Close()

	enc, err := auth.NewEncryptor(keyHex)
	if err != nil {
		fatal("rotate-key-detect: invalid key", "err", err)
	}
	result, err := keyrotate.Detect(ctx, st.Pool(), enc)
	if err != nil {
		fatal("rotate-key-detect", "err", err)
	}
	if len(result) == 0 {
		fmt.Println("no populated sealed secrets found to check against")
		return
	}
	opens, total := 0, 0
	for col, ok := range result {
		total++
		mark := "NO"
		if ok {
			opens++
			mark = "yes"
		}
		fmt.Printf("%-40s opens with this key: %s\n", col, mark)
	}
	if opens == total {
		fmt.Println("this key opens every checked column -- it is the database's current key")
	} else if opens == 0 {
		fmt.Println("this key opens NONE of the checked columns -- it is not the database's current key")
	} else {
		fmt.Println("MIXED: this key opens some columns but not others -- the database is not in a consistent single-key state")
		os.Exit(1)
	}
}

func runRotateKey(oldKeyHex, newKeyHex string, dryRun bool) {
	setupLogging()
	if oldKeyHex == "" || newKeyHex == "" {
		fatal("rotate-key: both -rotate-key-old and -rotate-key-new are required")
	}
	oldEnc, err := auth.NewEncryptor(oldKeyHex)
	if err != nil {
		fatal("rotate-key: invalid -rotate-key-old", "err", err)
	}
	newEnc, err := auth.NewEncryptor(newKeyHex)
	if err != nil {
		fatal("rotate-key: invalid -rotate-key-new", "err", err)
	}

	ctx := context.Background()
	st := openStoreForRotation(ctx)
	defer st.Close()

	report, err := keyrotate.Rotate(ctx, st.Pool(), oldEnc, newEnc, dryRun)
	if err != nil {
		fatal("rotate-key: rotation aborted, database unchanged (transaction rolled back)", "err", err)
	}

	for _, c := range report.Columns {
		fmt.Printf("%s.%-24s rewritten=%-4d skipped_empty=%-3d skipped_null=%d\n",
			c.Table, c.Column, c.Rewritten, c.SkippedEmpty, c.SkippedNull)
	}
	if dryRun {
		fmt.Printf("\nDRY RUN: %d secrets would be rewritten; database unchanged (transaction rolled back).\n", report.TotalRewritten())
		return
	}
	fmt.Printf("\nrotation complete: %d secrets rewritten and verified. Update SECRET_KEY in your deployment to the new key before starting the panel again.\n", report.TotalRewritten())
}
