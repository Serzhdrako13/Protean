package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

// fakeShell is an in-memory Shell -- bridge writes keystrokes into
// stdinW/reads them back via stdinR (test side), and the test writes
// simulated remote output into stdoutW for the bridge to read via
// Stdout(). Closing stdoutW simulates the remote shell exiting (EOF).
type fakeShell struct {
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter

	mu      sync.Mutex
	resizes [][2]uint16
	closed  bool
}

func newFakeShell() *fakeShell {
	sinR, sinW := io.Pipe()
	soutR, soutW := io.Pipe()
	return &fakeShell{stdinR: sinR, stdinW: sinW, stdoutR: soutR, stdoutW: soutW}
}

func (f *fakeShell) Stdin() io.WriteCloser { return f.stdinW }
func (f *fakeShell) Stdout() io.Reader     { return f.stdoutR }

func (f *fakeShell) Resize(rows, cols uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resizes = append(f.resizes, [2]uint16{rows, cols})
	return nil
}

func (f *fakeShell) Wait() error { return nil }

func (f *fakeShell) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	_ = f.stdinW.Close()
	_ = f.stdoutW.Close()
	return nil
}

func (f *fakeShell) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeShell) resizeCalls() [][2]uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][2]uint16(nil), f.resizes...)
}

type wsMsg struct {
	typ  MessageType
	data []byte
}

// fakeWSConn is an in-memory WSConn: the test sends on fromClient to
// simulate a client frame arriving, and reads from toClient to observe
// what the bridge wrote back.
type fakeWSConn struct {
	fromClient chan wsMsg
	toClient   chan wsMsg

	mu          sync.Mutex
	closed      bool
	closeReason string
}

func newFakeWSConn() *fakeWSConn {
	return &fakeWSConn{
		fromClient: make(chan wsMsg, 8),
		toClient:   make(chan wsMsg, 8),
	}
}

func (c *fakeWSConn) Read(ctx context.Context) (MessageType, []byte, error) {
	select {
	case m, ok := <-c.fromClient:
		if !ok {
			return 0, nil, io.EOF
		}
		return m.typ, m.data, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (c *fakeWSConn) Write(ctx context.Context, typ MessageType, data []byte) error {
	select {
	case c.toClient <- wsMsg{typ, append([]byte(nil), data...)}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *fakeWSConn) Close(reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.closeReason = reason
	return nil
}

func (c *fakeWSConn) sendClientFrame(t *testing.T, f clientFrame) {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal client frame: %v", err)
	}
	c.fromClient <- wsMsg{MessageText, b}
}

func (c *fakeWSConn) recvWithin(t *testing.T, d time.Duration) wsMsg {
	t.Helper()
	select {
	case m := <-c.toClient:
		return m
	case <-time.After(d):
		t.Fatalf("timed out waiting for a server->client message")
		return wsMsg{}
	}
}

func TestBridgeInputReachesShellStdin(t *testing.T) {
	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	ws.sendClientFrame(t, clientFrame{T: "i", Data: "echo hi\n"})

	buf := make([]byte, 32)
	n, err := shell.stdinR.Read(buf)
	if err != nil {
		t.Fatalf("read shell stdin: %v", err)
	}
	if got := string(buf[:n]); got != "echo hi\n" {
		t.Fatalf("shell stdin = %q, want %q", got, "echo hi\n")
	}

	_ = shell.Close()
	<-done
}

func TestBridgeResizeReachesShell(t *testing.T) {
	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	ws.sendClientFrame(t, clientFrame{T: "r", Rows: 40, Cols: 100})

	// Resize is applied synchronously in the ws->shell pump; give it a
	// moment to be observed without a fixed sleep turning into flakiness.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(shell.resizeCalls()) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	calls := shell.resizeCalls()
	if len(calls) != 1 || calls[0] != [2]uint16{40, 100} {
		t.Fatalf("resize calls = %v, want one {40,100}", calls)
	}

	_ = shell.Close()
	<-done
}

func TestBridgeShellOutputReachesWSAsBinary(t *testing.T) {
	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	go func() { _, _ = shell.stdoutW.Write([]byte("hello from remote")) }()

	msg := ws.recvWithin(t, time.Second)
	if msg.typ != MessageBinary {
		t.Fatalf("message type = %v, want MessageBinary", msg.typ)
	}
	if string(msg.data) != "hello from remote" {
		t.Fatalf("message data = %q", msg.data)
	}

	_ = shell.Close()
	<-done
}

func TestBridgeRemoteExitSendsExitFrame(t *testing.T) {
	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	// Closing the remote-output side simulates the shell exiting (EOF).
	_ = shell.stdoutW.Close()

	msg := ws.recvWithin(t, time.Second)
	if msg.typ != MessageText {
		t.Fatalf("expected a text control frame, got %v", msg.typ)
	}
	var f serverFrame
	if err := json.Unmarshal(msg.data, &f); err != nil {
		t.Fatalf("unmarshal control frame: %v", err)
	}
	if f.T != "exit" {
		t.Fatalf("control frame t = %q, want %q", f.T, "exit")
	}

	<-done
	if !shell.isClosed() {
		t.Fatal("shell was not closed after Run returned")
	}
}

func TestBridgeIdleTimeout(t *testing.T) {
	old := watchdogTick
	watchdogTick = 5 * time.Millisecond
	defer func() { watchdogTick = old }()

	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 20*time.Millisecond, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	select {
	case err := <-done:
		if !errors.Is(err, errIdleTimeout) {
			t.Fatalf("Run error = %v, want errIdleTimeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not time out on idle")
	}
	if !shell.isClosed() {
		t.Fatal("shell was not closed after idle timeout")
	}
}

func TestBridgeMaxDuration(t *testing.T) {
	old := watchdogTick
	watchdogTick = 5 * time.Millisecond
	defer func() { watchdogTick = old }()

	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 20*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	select {
	case err := <-done:
		if !errors.Is(err, errMaxDuration) {
			t.Fatalf("Run error = %v, want errMaxDuration", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not hit its max duration")
	}
	if !shell.isClosed() {
		t.Fatal("shell was not closed after max duration")
	}
}

func TestBridgeClientDisconnectClosesShell(t *testing.T) {
	shell := newFakeShell()
	ws := newFakeWSConn()
	b := NewBridge(ws, shell, 0, 0)

	done := make(chan error, 1)
	go func() { done <- b.Run(context.Background()) }()

	close(ws.fromClient) // simulates the WS connection dropping

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bridge did not tear down after client disconnect")
	}
	if !shell.isClosed() {
		t.Fatal("shell was not closed after client disconnect")
	}
}
