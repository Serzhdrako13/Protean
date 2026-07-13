import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Multi-entry build (index = admin SPA shell, login = standalone login page,
// portal = self-service portal for role=="user" accounts, mirroring 3x-ui's
// own vite.config.js), output straight into the Go module's static dir so
// `go build` embeds it (see internal/web/web.go). Dev server proxies only
// /api (+ /healthz) to the Go backend — the SPA's own login page is the
// separate login.html Vite entry (never the legacy server-rendered
// GET/POST /login), so /login must NOT be proxied or it prefix-shadows
// login.html and Vite 404s trying to serve the entry itself (same reasoning
// applies to /portal vs. portal.html).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, 'src') },
  },
  build: {
    outDir: path.resolve(__dirname, '../internal/web/dist'),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: path.resolve(__dirname, 'index.html'),
        login: path.resolve(__dirname, 'login.html'),
        portal: path.resolve(__dirname, 'portal.html'),
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
      '/healthz': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
});
