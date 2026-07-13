// Package notify delivers panel notifications (VPN events + periodic email
// reports) to a set of channels: Telegram, Mattermost, Rocket.Chat, VoceChat,
// XMPP and email. Channels are configured in the UI and stored (encrypted) in
// the database; this package is transport-only and has no DB dependency.
package notify

import (
	"context"
	"fmt"
)

// Message is a notification to deliver.
type Message struct {
	Subject string
	Body    string
}

// Channel delivers a Message over one transport.
type Channel interface {
	Kind() string
	Send(ctx context.Context, m Message) error
}

// Kinds are the supported channel identifiers.
const (
	KindTelegram   = "telegram"
	KindMattermost = "mattermost"
	KindRocketChat = "rocketchat"
	KindVoceChat   = "vocechat"
	KindXMPP       = "xmpp"
	KindEmail      = "email"
)

// AllKinds lists supported channel kinds in a stable (declaration) order,
// used to render the notifications UI consistently.
func AllKinds() []string {
	return []string{KindTelegram, KindMattermost, KindRocketChat, KindVoceChat, KindXMPP, KindEmail}
}

// New builds a Channel of kind from a config map (the fields each channel
// documents). Returns an error for unknown kinds or missing required fields.
func New(kind string, cfg map[string]string) (Channel, error) {
	switch kind {
	case KindTelegram:
		return newTelegram(cfg)
	case KindMattermost:
		return newWebhookChannel(KindMattermost, cfg)
	case KindRocketChat:
		return newWebhookChannel(KindRocketChat, cfg)
	case KindVoceChat:
		return newVoceChat(cfg)
	case KindXMPP:
		return newXMPP(cfg)
	case KindEmail:
		return newEmail(cfg)
	default:
		return nil, fmt.Errorf("unknown channel kind %q", kind)
	}
}

func require(cfg map[string]string, keys ...string) error {
	for _, k := range keys {
		if cfg[k] == "" {
			return fmt.Errorf("missing required field %q", k)
		}
	}
	return nil
}
