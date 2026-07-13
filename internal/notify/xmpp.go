package notify

import (
	"context"
	"fmt"

	xmpp "github.com/xmppo/go-xmpp"
)

// xmppChannel connects, sends one message, and disconnects. A persistent
// connection would be overkill for occasional notifications.
type xmppChannel struct {
	server    string // host:port (optional; derived from JID if empty)
	jid       string // bot account, user@domain
	password  string
	recipient string // JID to message
}

func newXMPP(cfg map[string]string) (Channel, error) {
	if err := require(cfg, "jid", "password", "recipient"); err != nil {
		return nil, err
	}
	return &xmppChannel{
		server:    cfg["server"],
		jid:       cfg["jid"],
		password:  cfg["password"],
		recipient: cfg["recipient"],
	}, nil
}

func (x *xmppChannel) Kind() string { return KindXMPP }

func (x *xmppChannel) Send(ctx context.Context, m Message) error {
	opts := xmpp.Options{
		Host:     x.server,
		User:     x.jid,
		Password: x.password,
		NoTLS:    false,
		StartTLS: true,
	}
	client, err := opts.NewClient()
	if err != nil {
		return fmt.Errorf("xmpp connect: %w", err)
	}
	defer client.Close()

	body := m.Body
	if m.Subject != "" {
		body = m.Subject + "\n" + m.Body
	}
	if _, err := client.Send(xmpp.Chat{Remote: x.recipient, Type: "chat", Text: body}); err != nil {
		return fmt.Errorf("xmpp send: %w", err)
	}
	return nil
}
