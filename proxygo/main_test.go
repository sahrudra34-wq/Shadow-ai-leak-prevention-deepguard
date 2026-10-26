package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAIHostMatching(t *testing.T) {
	cases := map[string]bool{
		"chatgpt.com:443":       true,
		"api.chatgpt.com":       true,
		"claude.ai":             true,
		"api.anthropic.com:443": true,
		"github.com":            false,
		"bing.com":              false,
		"example.com":           false,
	}
	for host, want := range cases {
		if got := isAIHost(host); got != want {
			t.Fatalf("isAIHost(%q)=%v want %v", host, got, want)
		}
	}
}

func TestPromptRequestHeuristic(t *testing.T) {
	cases := []struct {
		name, path, ct, body string
		want                 bool
	}{
		{"chat conversation send", "/backend-api/conversation", "application/json", `{"action":"next","messages":[{"role":"user","content":"hello"}]}`, true},
		{"chat conversation draft", "/backend-api/conversation", "application/json", `{"messages":[{"role":"user","content":"still typing"}]}`, false},
		{"chat conversation prepare", "/backend-api/f/conversation/prepare", "application/json", `{"action":"next","messages":[{"role":"user","content":"prepare"}]}`, false},
		{"generic profile", "/api/profile", "application/json", `{"name":"Rudra"}`, false},
		{"analytics", "/api/events", "application/json", `{"event":"page_view"}`, false},
		{"text prompt", "/v1/chat/completions", "text/plain", "hello", true},
		{"binary upload", "/v1/upload", "multipart/form-data", "binary", false},
	}
	for _, tc := range cases {
		u, _ := url.Parse("https://chatgpt.com" + tc.path)
		r := &http.Request{Method: http.MethodPost, URL: u, Header: make(http.Header)}
		r.Header.Set("Content-Type", tc.ct)
		if got := isPromptRequest(r, []byte(tc.body)); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestChatGPTOnlyScansAfterSendAction(t *testing.T) {
	draft := []byte(`{"messages":[{"author":{"role":"user"},"content":{"content_type":"text","parts":["email=draft@example.com"]}}]}`)
	if isPromptRequest(mustRequest("https://chatgpt.com/backend-api/f/conversation", "application/json"), draft) {
		t.Fatal("ChatGPT draft was incorrectly classified as a sent prompt")
	}
	sent := []byte(`{"action":"next","messages":[{"author":{"role":"user"},"content":{"content_type":"text","parts":["email=sent@example.com"]}}]}`)
	if !isPromptRequest(mustRequest("https://chatgpt.com/backend-api/f/conversation", "application/json"), sent) {
		t.Fatal("ChatGPT sent prompt was not classified")
	}
}

func TestProviderPromptRequestHeuristics(t *testing.T) {
	cases := []struct {
		name, rawURL, ct, body string
		want                   bool
	}{
		{"Claude API send", "https://api.anthropic.com/v1/messages", "application/json; charset=utf-8", `{"model":"claude-opus-5","messages":[{"role":"user","content":"email=rahul@example.com"}]}`, true},
		{"Claude API model list", "https://api.anthropic.com/v1/models", "application/json", `{"messages":[{"role":"user","content":"email=rahul@example.com"}]}`, false},
		{"Claude web message endpoint", "https://claude.ai/api/chat/completion", "application/json", `{"messages":[{"role":"user","content":"password=TestPassword123!"}]}`, true},
		{"Claude web page API", "https://claude.ai/api/organizations", "application/json", `{"messages":[{"role":"user","content":"password=TestPassword123!"}]}`, false},
	}
	for _, tc := range cases {
		u, _ := url.Parse(tc.rawURL)
		r := &http.Request{Method: http.MethodPost, URL: u, Header: make(http.Header)}
		r.Header.Set("Content-Type", tc.ct)
		if got := isPromptRequest(r, []byte(tc.body)); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestGzipRequestDecodeRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"prompt":"email=a@b.com"}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	plain, encode, err := decodeRequestBody(buf.Bytes(), "gzip")
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"prompt":"email=a@b.com"}` {
		t.Fatalf("unexpected plain body: %s", plain)
	}
	out, err := encode([]byte(`{"prompt":"email=[REDACTED]"}`))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"prompt":"email=[REDACTED]"}` {
		t.Fatalf("unexpected round trip: %s", got)
	}
}

func TestExtractsLatestUserPromptOnly(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"system secret password=old"},{"role":"user","content":"first safe prompt"},{"role":"assistant","content":"answer"},{"role":"user","content":"latest api_key=sk-test-1234567890abcdef"}]}`)
	got, ok := extractPromptText(body)
	if !ok || got != "latest api_key=sk-test-1234567890abcdef" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}

func TestRedactJSONPreservesRequestShape(t *testing.T) {
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"email=test@example.com api_key=sk-test-1234567890abcdef"}]}]}`)
	prompt, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected prompt")
	}
	redacted := "email=[REDACTED_BY_DEEPGUARD] api_key=[REDACTED_BY_DEEPGUARD]"
	out, err := redactPromptBody(body, prompt, redacted, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatalf("invalid JSON after redaction: %v", err)
	}
	if string(out) == string(body) {
		t.Fatal("request was not redacted")
	}
	if !bytes.Contains(out, []byte(`[REDACTED_BY_DEEPGUARD]`)) {
		t.Fatal("redacted marker missing")
	}
	if bytes.Contains(out, []byte("sk-test-1234567890abcdef")) {
		t.Fatal("secret still present")
	}
}

func TestChatGPTAuthorUserPromptAndRedaction(t *testing.T) {
	body := []byte(`{"action":"next","messages":[{"id":"x","author":{"role":"user"},"content":{"content_type":"text","parts":["Email: rahul@example.com\nPhone: +91-9876543210\nAPI_KEY: test_api_key_987654321"]}}]}`)
	if !isPromptRequest(mustRequest("https://chatgpt.com/backend-api/conversation", "application/json"), body) {
		t.Fatal("ChatGPT author.role=user request was not detected")
	}
	prompt, ok := extractPromptText(body)
	if !ok || !strings.Contains(prompt, "rahul@example.com") {
		t.Fatalf("prompt extraction failed: %q", prompt)
	}
	redacted := strings.ReplaceAll(prompt, "rahul@example.com", "[REDACTED_BY_DEEPGUARD]")
	redacted = strings.ReplaceAll(redacted, "+91-9876543210", "[REDACTED_BY_DEEPGUARD]")
	redacted = strings.ReplaceAll(redacted, "test_api_key_987654321", "[REDACTED_BY_DEEPGUARD]")
	out, err := redactPromptBody(body, prompt, redacted, "application/json")
	if err != nil || bytes.Contains(out, []byte("rahul@example.com")) || bytes.Contains(out, []byte("9876543210")) || bytes.Contains(out, []byte("test_api_key_987654321")) {
		t.Fatalf("ChatGPT payload was not safely redacted: %s", out)
	}
}

func mustRequest(rawURL, ct string) *http.Request {
	u, _ := url.Parse(rawURL)
	r := &http.Request{Method: http.MethodPost, URL: u, Header: make(http.Header)}
	r.Header.Set("Content-Type", ct)
	return r
}
