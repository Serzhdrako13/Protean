package notify

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

// email sends via SMTP. Used mainly for the periodic accumulating report.
type email struct {
	host string // host:port
	user string
	pass string
	from string
	to   []string
}

func newEmail(cfg map[string]string) (Channel, error) {
	if err := require(cfg, "host", "from", "to"); err != nil {
		return nil, err
	}
	return &email{
		host: cfg["host"],
		user: cfg["user"],
		pass: cfg["pass"],
		from: cfg["from"],
		to:   splitList(cfg["to"]),
	}, nil
}

func (e *email) Kind() string { return KindEmail }

func (e *email) Send(ctx context.Context, m Message) error {
	msg := "From: " + e.from + "\r\n" +
		"To: " + strings.Join(e.to, ", ") + "\r\n" +
		"Subject: " + m.Subject + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" +
		m.Body + "\r\n"

	var auth smtp.Auth
	if e.user != "" {
		host := e.host
		if i := strings.LastIndex(host, ":"); i >= 0 {
			host = host[:i]
		}
		auth = smtp.PlainAuth("", e.user, e.pass, host)
	}
	if err := smtp.SendMail(e.host, auth, e.from, e.to, []byte(msg)); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
