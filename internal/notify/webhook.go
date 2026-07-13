package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpClient is shared by the webhook-style channels.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// postJSON sends a JSON body and treats any 2xx as success.
func postJSON(ctx context.Context, url string, headers map[string]string, payload any) error {
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return nil
}

func fullText(m Message) string {
	if m.Subject == "" {
		return m.Body
	}
	return "*" + m.Subject + "*\n" + m.Body
}

// webhookChannel covers Mattermost and Rocket.Chat incoming webhooks, which
// both accept {"text": "..."} at a configured URL.
type webhookChannel struct {
	kind string
	url  string
}

func newWebhookChannel(kind string, cfg map[string]string) (Channel, error) {
	if err := require(cfg, "url"); err != nil {
		return nil, err
	}
	return &webhookChannel{kind: kind, url: cfg["url"]}, nil
}

func (c *webhookChannel) Kind() string { return c.kind }
func (c *webhookChannel) Send(ctx context.Context, m Message) error {
	return postJSON(ctx, c.url, nil, map[string]string{"text": fullText(m)})
}

// telegram sends via the Bot API.
type telegram struct {
	token  string
	chatID string
}

func newTelegram(cfg map[string]string) (Channel, error) {
	if err := require(cfg, "token", "chat_id"); err != nil {
		return nil, err
	}
	return &telegram{token: cfg["token"], chatID: cfg["chat_id"]}, nil
}

func (t *telegram) Kind() string { return KindTelegram }
func (t *telegram) Send(ctx context.Context, m Message) error {
	url := "https://api.telegram.org/bot" + t.token + "/sendMessage"
	return postJSON(ctx, url, nil, map[string]string{
		"chat_id": t.chatID,
		"text":    fullText(m),
	})
}

// voceChat posts to a VoceChat bot "send to user/group" endpoint. The full
// endpoint URL and the bot API key are configured; the body is plain text.
type voceChat struct {
	url    string
	apiKey string
}

func newVoceChat(cfg map[string]string) (Channel, error) {
	if err := require(cfg, "url", "api_key"); err != nil {
		return nil, err
	}
	return &voceChat{url: cfg["url"], apiKey: cfg["api_key"]}, nil
}

func (v *voceChat) Kind() string { return KindVoceChat }
func (v *voceChat) Send(ctx context.Context, m Message) error {
	// VoceChat bot endpoints take a text/plain body with an x-api-key header.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader([]byte(fullText(m))))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("x-api-key", v.apiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("vocechat: HTTP %d: %s", resp.StatusCode, body)
	}
	return nil
}
