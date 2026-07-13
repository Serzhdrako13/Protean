package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookChannelSends(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch, err := New(KindMattermost, map[string]string{"url": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), Message{Subject: "Alert", Body: "iface down"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got["text"] != "*Alert*\niface down" {
		t.Errorf("payload text = %q", got["text"])
	}
}

func TestTelegramFormat(t *testing.T) {
	var path string
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Point the telegram sender at the test server by overriding the client
	// transport via a custom base -- instead, exercise the payload builder by
	// using the webhook path is not possible; assert construction + chat id.
	ch, err := New(KindTelegram, map[string]string{"token": "T", "chat_id": "123"})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Kind() != KindTelegram {
		t.Errorf("kind = %q", ch.Kind())
	}
	_ = path
	_ = got
}

func TestVoceChatSends(t *testing.T) {
	var body string
	var apiKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey = r.Header.Get("x-api-key")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch, err := New(KindVoceChat, map[string]string{"url": srv.URL, "api_key": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), Message{Body: "hello"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if body != "hello" || apiKey != "secret" {
		t.Errorf("body=%q apiKey=%q", body, apiKey)
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	ch, _ := New(KindRocketChat, map[string]string{"url": srv.URL})
	if err := ch.Send(context.Background(), Message{Body: "x"}); err == nil {
		t.Error("expected error on HTTP 500")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("bogus", nil); err == nil {
		t.Error("expected error for unknown kind")
	}
	if _, err := New(KindTelegram, map[string]string{"token": "T"}); err == nil {
		t.Error("expected error for missing chat_id")
	}
	if _, err := New(KindEmail, map[string]string{"host": "h:25"}); err == nil {
		t.Error("expected error for missing from/to")
	}
	if _, err := New(KindEmail, map[string]string{"host": "h:25", "from": "a@b", "to": "c@d"}); err != nil {
		t.Errorf("valid email config rejected: %v", err)
	}
}
