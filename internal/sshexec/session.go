package sshexec

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// Session is an interactive, PTY-attached remote process -- used by the web
// SSH console (internal/console) and, in future, any feature that streams a
// single long-running command's output the same way (e.g. an OS-update
// apply). Unlike Run, a Session is NOT bounded by Client's CmdTimeout; its
// lifetime is the caller's responsibility (idle/absolute timeouts belong in
// the caller, e.g. internal/console's session hub).
type Session struct {
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout io.Reader
}

// Stdin is the remote process's standard input (keystrokes, for a shell).
func (s *Session) Stdin() io.WriteCloser { return s.stdin }

// Stdout is the remote process's combined stdout+stderr -- a real PTY
// folds both into the one tty device on the remote side, so a single
// reader is the correct shape here, not a design simplification.
func (s *Session) Stdout() io.Reader { return s.stdout }

// Resize notifies the remote PTY of a new terminal size.
func (s *Session) Resize(rows, cols uint16) error {
	return s.sess.WindowChange(int(rows), int(cols))
}

// Wait blocks until the remote process exits.
func (s *Session) Wait() error { return s.sess.Wait() }

// Close ends the session, unblocking any pending Wait.
func (s *Session) Close() error { return s.sess.Close() }

// defaultPtyModes requests standard xterm-family behavior: remote-side echo
// and line discipline, matching what an interactive terminal expects.
var defaultPtyModes = ssh.TerminalModes{
	ssh.ECHO:          1,
	ssh.TTY_OP_ISPEED: 14400,
	ssh.TTY_OP_OSPEED: 14400,
}

func (c *Client) newPtySession(ctx context.Context, term string, rows, cols uint16) (*ssh.Session, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	if term == "" {
		term = "xterm-256color"
	}
	if err := sess.RequestPty(term, int(rows), int(cols), defaultPtyModes); err != nil {
		sess.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}
	return sess, nil
}

func newSession(sess *ssh.Session) (*Session, error) {
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	return &Session{sess: sess, stdin: stdin, stdout: stdout}, nil
}

// StartShell starts the remote user's login shell attached to a PTY of the
// given size -- the web SSH console's entry point. The returned Session
// stays open until Close, the remote shell exits, or the connection drops;
// no CmdTimeout applies.
func (c *Client) StartShell(ctx context.Context, rows, cols uint16, term string) (*Session, error) {
	sess, err := c.newPtySession(ctx, term, rows, cols)
	if err != nil {
		return nil, err
	}
	s, err := newSession(sess)
	if err != nil {
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	return s, nil
}

// StartCommand starts a single remote command attached to a PTY, streamed
// through the identical Session shape StartShell uses -- the reuse hook for
// a later feature that streams one long-running command's output (e.g. an
// OS package upgrade) over the same bridge machinery the console uses.
// Not called anywhere in this codebase yet; always PTY-attached, same as
// StartShell, so stdout/stderr fold into one ordered stream for free.
func (c *Client) StartCommand(ctx context.Context, cmd string, rows, cols uint16) (*Session, error) {
	sess, err := c.newPtySession(ctx, "", rows, cols)
	if err != nil {
		return nil, err
	}
	s, err := newSession(sess)
	if err != nil {
		return nil, err
	}
	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, fmt.Errorf("start %q: %w", cmd, err)
	}
	return s, nil
}
