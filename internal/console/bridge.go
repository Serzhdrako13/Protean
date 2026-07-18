package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

// Shell is the minimal interactive-session surface the bridge drives --
// satisfied by *sshexec.Session (wrapped, in internal/api, to also release
// any ephemeral SSH connection on Close -- see servers.Manager.ConsoleClient).
// Abstracted so tests can inject a fake shell without a real SSH connection.
type Shell interface {
	Stdin() io.WriteCloser
	Stdout() io.Reader
	Resize(rows, cols uint16) error
	Wait() error
	Close() error
}

// ShellOpener resolves a console target into a live Shell -- the seam
// between the bridge and however a target's SSH client is actually
// obtained (pooled vs. ephemeral).
type ShellOpener interface {
	OpenShell(ctx context.Context, rows, cols uint16) (Shell, error)
}

// MessageType mirrors the WS frame kinds the bridge cares about, kept as
// this package's own small enum so it doesn't need to import a specific
// WebSocket library to stay unit-testable against a fake.
type MessageType int

const (
	MessageText MessageType = iota
	MessageBinary
)

// WSConn is the minimal WebSocket surface the bridge needs. The real
// implementation (internal/api) adapts github.com/coder/websocket to this;
// tests use an in-memory fake.
type WSConn interface {
	Read(ctx context.Context) (MessageType, []byte, error)
	Write(ctx context.Context, typ MessageType, data []byte) error
	Close(reason string) error
}

// Client -> server frames are always JSON text, even for keystrokes --
// xterm's onData already yields strings, and a tiny explicit protocol
// (vs. a raw byte pipe) leaves room for resize/control messages on the
// same socket without a side channel.
type clientFrame struct {
	T    string `json:"t"`           // "i" input | "r" resize
	Data string `json:"d,omitempty"` // t=="i": keystrokes
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

// Server -> client control frames (JSON text); PTY output itself goes out
// as separate binary frames, not wrapped in this envelope.
type serverFrame struct {
	T    string `json:"t"` // "exit" | "err"
	Code int    `json:"code,omitempty"`
	Msg  string `json:"msg,omitempty"`
}

var (
	errIdleTimeout = errors.New("console: idle timeout")
	errMaxDuration = errors.New("console: max session duration reached")
)

// watchdogTick is how often Bridge.watchdog checks the idle/max-duration
// limits. A package-level var, not a constant, so tests can shrink it
// instead of waiting out a real 1s tick per timeout assertion.
var watchdogTick = time.Second

// Bridge pumps bytes between a WebSocket connection and a remote PTY shell
// until either side closes, an error occurs, or a lifecycle limit fires.
// One Bridge per console session.
type Bridge struct {
	ws    WSConn
	shell Shell

	idleTimeout time.Duration
	maxDuration time.Duration

	lastActivity atomic.Int64 // unix nanoseconds
}

func NewBridge(ws WSConn, shell Shell, idleTimeout, maxDuration time.Duration) *Bridge {
	b := &Bridge{ws: ws, shell: shell, idleTimeout: idleTimeout, maxDuration: maxDuration}
	b.lastActivity.Store(time.Now().UnixNano())
	return b
}

// Run blocks until the session ends (WS closed, shell exited, an error, or
// idle/max-duration timeout), then tears down both sides. It always closes
// the Shell before returning; callers own closing/discarding the WSConn
// afterward if their library needs an explicit final step beyond what
// Close does here.
func (b *Bridge) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer b.shell.Close()

	errCh := make(chan error, 3)
	go b.pumpShellToWS(ctx, errCh)
	go b.pumpWSToShell(ctx, errCh)
	go b.watchdog(ctx, errCh)

	err := <-errCh
	cancel()
	_ = b.ws.Close("session ended")
	return err
}

func (b *Bridge) pumpShellToWS(ctx context.Context, errCh chan<- error) {
	buf := make([]byte, 32*1024)
	for {
		n, rerr := b.shell.Stdout().Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			if werr := b.ws.Write(ctx, MessageBinary, chunk); werr != nil {
				errCh <- werr
				return
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				errCh <- b.sendExit()
			} else {
				errCh <- rerr
			}
			return
		}
	}
}

func (b *Bridge) pumpWSToShell(ctx context.Context, errCh chan<- error) {
	for {
		typ, data, err := b.ws.Read(ctx)
		if err != nil {
			errCh <- err
			return
		}
		if typ != MessageText {
			continue // the client never sends binary frames; ignore defensively
		}
		b.lastActivity.Store(time.Now().UnixNano())
		var f clientFrame
		if err := json.Unmarshal(data, &f); err != nil {
			continue // malformed frame: drop it, don't kill the session over it
		}
		switch f.T {
		case "i":
			if _, err := b.shell.Stdin().Write([]byte(f.Data)); err != nil {
				errCh <- err
				return
			}
		case "r":
			if f.Rows > 0 && f.Cols > 0 {
				_ = b.shell.Resize(uint16(f.Rows), uint16(f.Cols))
			}
		}
	}
}

func (b *Bridge) watchdog(ctx context.Context, errCh chan<- error) {
	ticker := time.NewTicker(watchdogTick)
	defer ticker.Stop()
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if b.idleTimeout > 0 {
				last := time.Unix(0, b.lastActivity.Load())
				if time.Since(last) > b.idleTimeout {
					_ = b.sendErr("idle timeout")
					errCh <- errIdleTimeout
					return
				}
			}
			if b.maxDuration > 0 && time.Since(start) > b.maxDuration {
				_ = b.sendErr("max session duration reached")
				errCh <- errMaxDuration
				return
			}
		}
	}
}

func (b *Bridge) sendExit() error {
	code := 0
	if err := b.shell.Wait(); err != nil {
		code = 1
	}
	msg, _ := json.Marshal(serverFrame{T: "exit", Code: code})
	return b.ws.Write(context.Background(), MessageText, msg)
}

func (b *Bridge) sendErr(m string) error {
	msg, _ := json.Marshal(serverFrame{T: "err", Msg: m})
	return b.ws.Write(context.Background(), MessageText, msg)
}
