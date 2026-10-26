package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	listenPort = flag.Int("port", 47822, "proxy listen port")
	caDir      = flag.String("ca-dir", "", "CA storage directory")
	apiURL     = flag.String("api", "http://127.0.0.1:47821/api/inspect", "DeepGuard inspection API")
)

// Only destinations that are actual AI services are eligible for TLS inspection.
// Static/CDN/identity/telemetry domains stay as normal tunnels unless they are
// explicitly added later after a real prompt path is verified.
var aiHosts = []string{
	"chatgpt.com", "chat.openai.com", "api.openai.com",
	"claude.ai", "api.anthropic.com",
	"copilot.microsoft.com", "copilot.com",
	"perplexity.ai",
	"cursor.com", "codeium.com", "windsurf.com", "githubcopilot.com",
}

func isAIHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.Split(host, ":")[0]))
	for _, d := range aiHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// isPromptRequest prevents normal page/background traffic from being sent to the
// DLP engine. It deliberately uses conservative heuristics: JSON/text requests
// on known AI hosts are inspected only when the URL/body looks prompt-like.
func isPromptRequest(r *http.Request, body []byte) bool {
	if r == nil || (r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch) {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "" && ct != "application/json" && ct != "text/plain" && ct != "application/x-www-form-urlencoded" && ct != "application/graphql" {
		return false
	}
	if len(body) == 0 || len(body) > 16<<20 {
		return false
	}

	path := strings.ToLower(r.URL.Path)
	// Claude's official Messages API is POST /v1/messages. It carries the
	// actual user turn in messages[].role/content, so this is safe to inspect
	// without scanning page-load traffic. Claude Desktop commonly reaches the
	// same Anthropic endpoint.
	if isClaudeAPIHost(r.URL.Hostname()) && strings.HasPrefix(path, "/v1/messages") {
		return hasUserTurn(body)
	}

	// Claude Web uses internal /api/* endpoints that can change over time.
	// Keep the matcher narrow: only message/chat/completion/send/conversation
	// paths with an extractable user prompt are eligible. Other page traffic
	// continues untouched.
	if isClaudeWebHost(r.URL.Hostname()) && strings.Contains(path, "/api/") {
		claudePath := strings.Contains(path, "message") || strings.Contains(path, "completion") ||
			strings.Contains(path, "conversation") || strings.Contains(path, "chat") ||
			strings.Contains(path, "send") || strings.Contains(path, "prompt") || strings.Contains(path, "stream")
		if claudePath {
			prompt, ok := extractPromptText(body)
			return ok && looksLikeUserPrompt(prompt) && (hasUserTurn(body) || looksPromptMarkedBody(body))
		}
	}

	lower := strings.ToLower(string(body))

	// ChatGPT Web has a particularly important distinction: the composer can
	// generate background/draft requests while the user is still typing. The
	// real message-send request uses the conversation endpoint with
	// action="next". Only that request is eligible for DLP on the ChatGPT web
	// domains. This prevents a typed draft from appearing as a protection event.
	if isChatGPTHost(r.URL.Hostname()) && strings.HasPrefix(path, "/backend-api/") {
		if strings.HasPrefix(path, "/backend-api/f/conversation/prepare") || strings.HasPrefix(path, "/backend-api/conversation/prepare") {
			return false
		}
		if path == "/backend-api/f/conversation" || path == "/backend-api/f/conversation/" ||
			path == "/backend-api/conversation" || path == "/backend-api/conversation/" {
			return hasJSONAction(body, "next") && hasUserTurn(body)
		}
		// Do not let a generic user-role object elsewhere on chatgpt.com trigger
		// DLP. Profile, sync, history, moderation and UI calls are not sends.
		return false
	}

	// For API-style AI endpoints, user-role messages are sufficient evidence
	// because these endpoints are specifically designed to submit completions.
	explicitPromptPath := strings.Contains(path, "/chat/completions") ||
		strings.Contains(path, "/responses") ||
		strings.Contains(path, "/messages") ||
		strings.Contains(path, "/completions")

	if explicitPromptPath && (hasUserTurn(body) || strings.Contains(lower, `"prompt"`) || strings.Contains(lower, `"input"`)) {
		return true
	}
	if explicitPromptPath && ct == "text/plain" {
		return strings.TrimSpace(string(body)) != ""
	}
	return false
}

func isChatGPTHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.Split(host, ":")[0]))
	return h == "chatgpt.com" || strings.HasSuffix(h, ".chatgpt.com") || h == "chat.openai.com" || strings.HasSuffix(h, ".chat.openai.com")
}

func isClaudeAPIHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.Split(host, ":")[0]))
	return h == "api.anthropic.com" || strings.HasSuffix(h, ".api.anthropic.com")
}

func isClaudeWebHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(strings.Split(host, ":")[0]))
	return h == "claude.ai" || strings.HasSuffix(h, ".claude.ai")
}

func looksPromptMarkedBody(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, marker := range []string{"\"prompt\"", "\"input\"", "\"message\"", "\"content\"", "\"text\"", "f.req="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hasJSONAction(body []byte, want string) bool {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(x any) bool {
		switch t := x.(type) {
		case map[string]any:
			for k, v := range t {
				if strings.EqualFold(k, "action") {
					if value, ok := v.(string); ok && strings.EqualFold(strings.TrimSpace(value), want) {
						return true
					}
				}
				if walk(v) {
					return true
				}
			}
		case []any:
			for _, v := range t {
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

func hasUserTurn(body []byte) bool {
	var root any
	if json.Unmarshal(body, &root) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(x any) bool {
		switch t := x.(type) {
		case map[string]any:
			if role, ok := t["role"].(string); ok && (strings.EqualFold(role, "user") || strings.EqualFold(role, "human")) {
				return true
			}
			if author, ok := t["author"].(map[string]any); ok {
				if role, ok := author["role"].(string); ok && (strings.EqualFold(role, "user") || strings.EqualFold(role, "human")) {
					return true
				}
			}
			for _, v := range t {
				if walk(v) {
					return true
				}
			}
		case []any:
			for _, v := range t {
				if walk(v) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

func looksLikeJSON(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 2 {
		return false
	}
	return (strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")) ||
		(strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"))
}

func looksLikeUserPrompt(s string) bool {
	x := strings.TrimSpace(s)
	if len(x) < 3 || len(x) > 100000 {
		return false
	}
	// Protocol/session values and UI metadata are not prompts.
	if looksLikeJSON(x) || strings.HasPrefix(x, "http://") || strings.HasPrefix(x, "https://") {
		return false
	}
	if strings.Count(x, "\n") == 0 && !strings.ContainsAny(x, " \t?!.,:;()[]{}") {
		return false
	}
	return true
}

var inspectClient = &http.Client{Timeout: 2200 * time.Millisecond}

type decision struct {
	Action          string `json:"action"`
	RedactedContent string `json:"redactedContent"`
	RiskScore       int    `json:"riskScore"`
	FindingCount    int    `json:"findingCount"`
	IsPrompt        bool   `json:"isPrompt"`
	PromptHash      string `json:"promptHash"`
}

func promptHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// extractPromptText extracts only user-facing prompt/message text from common
// AI request JSON shapes. We deliberately do not scan the entire request body:
// browser metadata, IDs, telemetry and tool state are not user prompts.
func extractTextValue(v any) string {
	var parts []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				parts = append(parts, t)
			}
		case map[string]any:
			// Providers commonly wrap text in {type:"text", text:"..."}.
			if text, ok := t["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
				return
			}
			if content, ok := t["content"]; ok {
				walk(content)
				return
			}
			if partsVal, ok := t["parts"]; ok {
				walk(partsVal)
				return
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(v)
	return strings.Join(parts, "\n")
}

func extractPromptText(body []byte) (string, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || len(trimmed) > 16<<20 {
		return "", false
	}

	var root any
	if json.Unmarshal(trimmed, &root) == nil {
		var latest string
		var findTurns func(any)
		findTurns = func(x any) {
			switch t := x.(type) {
			case map[string]any:
				for k, val := range t {
					lk := strings.ToLower(k)
					if lk == "messages" || lk == "conversation" || lk == "turns" {
						if arr, ok := val.([]any); ok {
							for _, item := range arr {
								if obj, ok := item.(map[string]any); ok {
									role, _ := obj["role"].(string)
									role = strings.ToLower(strings.TrimSpace(role))
									if role == "user" || role == "human" {
										for _, key := range []string{"content", "message", "text", "parts"} {
											if v, ok := obj[key]; ok {
												if text := extractTextValue(v); text != "" {
													latest = text
												}
											}
										}
									}
								}
							}
						}
					}
					findTurns(val)
				}
			case []any:
				for _, item := range t {
					findTurns(item)
				}
			}
		}
		findTurns(root)
		if strings.TrimSpace(latest) != "" {
			return latest, true
		}

		var candidates []string
		var findKeys func(any)
		findKeys = func(x any) {
			switch t := x.(type) {
			case map[string]any:
				for k, val := range t {
					lk := strings.ToLower(k)
					if lk == "prompt" || lk == "input" || lk == "instructions" || lk == "query" || lk == "message" || lk == "content" || lk == "text" || lk == "parts" {
						if str, ok := val.(string); ok && strings.TrimSpace(str) != "" {
							candidates = append(candidates, str)
							continue
						}
					}
					findKeys(val)
				}
			case []any:
				for _, item := range t {
					findKeys(item)
				}
			}
		}
		findKeys(root)
		if len(candidates) > 0 {
			return candidates[len(candidates)-1], true
		}
	}

	text := strings.TrimSpace(string(trimmed))
	if text != "" && len(text) < 100000 {
		return text, true
	}
	return "", false
}

// redactPromptBody keeps the original request schema intact for structured provider APIs.

func redactPromptBody(body []byte, originalPrompt, redactedPrompt string, contentType string) ([]byte, error) {
	if originalPrompt == "" || redactedPrompt == "" || originalPrompt == redactedPrompt {
		return body, nil
	}
	trimmed := bytes.TrimSpace(body)
	var root any
	if json.Unmarshal(trimmed, &root) == nil {
		changed := false
		var walk func(any, string) any
		walk = func(x any, role string) any {
			switch t := x.(type) {
			case string:
				if (role == "user" || role == "human") && strings.Contains(t, originalPrompt) {
					changed = true
					return strings.ReplaceAll(t, originalPrompt, redactedPrompt)
				}
				return t
			case map[string]any:
				localRole := role
				if r, ok := t["role"].(string); ok {
					localRole = strings.ToLower(strings.TrimSpace(r))
				}
				if author, ok := t["author"].(map[string]any); ok {
					if r, ok := author["role"].(string); ok {
						localRole = strings.ToLower(strings.TrimSpace(r))
					}
				}
				for k, val := range t {
					lk := strings.ToLower(k)
					if str, ok := val.(string); ok {
						keyPrompt := lk == "prompt" || lk == "input" || lk == "query" || lk == "text" || lk == "message" || lk == "content"
						if (localRole == "user" || localRole == "human" || keyPrompt) && strings.Contains(str, originalPrompt) {
							t[k] = strings.ReplaceAll(str, originalPrompt, redactedPrompt)
							changed = true
							continue
						}
					}
					t[k] = walk(val, localRole)
				}
				return t
			case []any:
				for i, item := range t {
					t[i] = walk(item, role)
				}
				return t
			default:
				return x
			}
		}
		root = walk(root, "")
		if changed {
			return json.Marshal(root)
		}
	}

	raw := string(body)
	encodedOriginal := url.QueryEscape(originalPrompt)
	encodedRedacted := url.QueryEscape(redactedPrompt)
	if strings.Contains(raw, encodedOriginal) {
		return []byte(strings.ReplaceAll(raw, encodedOriginal, encodedRedacted)), nil
	}
	if strings.Contains(raw, originalPrompt) {
		return []byte(strings.ReplaceAll(raw, originalPrompt, redactedPrompt)), nil
	}
	return body, nil
}

func inspect(body []byte, host, appName string, prompt string) decision {
	data := map[string]any{
		"content": prompt, "destination": host, "app": appName, "channel": "live-network", "isPrompt": true,
		"promptHash": promptHash([]byte(prompt)),
	}
	payload, _ := json.Marshal(data)
	req, err := http.NewRequest(http.MethodPost, *apiURL, bytes.NewReader(payload))
	if err != nil {
		return decision{Action: "block", IsPrompt: true}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := inspectClient.Do(req)
	if err != nil {
		return decision{Action: "block", IsPrompt: true}
	}
	defer resp.Body.Close()
	var d decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || d.Action == "" {
		return decision{Action: "block", IsPrompt: true}
	}
	return d
}
func redactBody(body []byte, redacted string) []byte {
	if redacted == "" || redacted == string(body) {
		return body
	}
	return []byte(redacted)
}

func decodeRequestBody(body []byte, encoding string) ([]byte, func([]byte) ([]byte, error), error) {
	enc := strings.ToLower(strings.TrimSpace(strings.Split(encoding, ";")[0]))
	switch enc {
	case "", "identity":
		return body, func(b []byte) ([]byte, error) { return b, nil }, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		plain, err := io.ReadAll(io.LimitReader(zr, 16<<20))
		_ = zr.Close()
		if err != nil {
			return nil, nil, err
		}
		return plain, func(b []byte) ([]byte, error) {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			if _, err := zw.Write(b); err != nil {
				_ = zw.Close()
				return nil, err
			}
			if err := zw.Close(); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported request content-encoding: %s", enc)
	}
}

type certAuthority struct {
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	mu    sync.Mutex
	cache map[string]tls.Certificate
}

func loadOrCreateCA(dir string) (*certAuthority, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, "ca-cert.cer"), filepath.Join(dir, "ca-key.pem")
	if certBytes, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err2 := os.ReadFile(keyPath); err2 == nil {
			certDER := certBytes
			if block, _ := pem.Decode(certBytes); block != nil {
				certDER = block.Bytes
			}
			if keyBlock, _ := pem.Decode(keyPEM); keyBlock != nil {
				cert, e1 := x509.ParseCertificate(certDER)
				key, e2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if e1 == nil && e2 == nil {
					return &certAuthority{cert: cert, key: key, cache: map[string]tls.Certificate{}}, nil
				}
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "DeepGuard Local Inspection CA", Organization: []string{"DeepGuard"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, der, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &certAuthority{cert: cert, key: key, cache: map[string]tls.Certificate{}}, nil
}

func (ca *certAuthority) leaf(host string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	ca.cache[host] = cert
	return cert, nil
}

type proxy struct {
	ca        *certAuthority
	transport *http.Transport
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.forward(w, r)
}

func (p *proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking unavailable", 500)
		return
	}
	clientConn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\nProxy-Agent: DeepGuard\r\n\r\n")
	_ = rw.Flush()
	if !isAIHost(host) {
		dst, err := net.DialTimeout("tcp", host, 10*time.Second)
		if err != nil {
			_ = clientConn.Close()
			return
		}
		tunnelHTTP1(clientConn, dst)
		return
	}
	cert, err := p.ca.leaf(strings.Split(host, ":")[0])
	if err != nil {
		_ = clientConn.Close()
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := tlsClient.Handshake(); err != nil {
		_ = clientConn.Close()
		return
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { p.inspectAndForward(w, req, host) }), ReadHeaderTimeout: 15 * time.Second}
	_ = srv.Serve(&singleConnListener{conn: tlsClient})
}

func (p *proxy) forward(w http.ResponseWriter, r *http.Request) {
	if r.URL.Scheme == "" || r.URL.Host == "" {
		http.Error(w, "Bad proxy request", 400)
		return
	}
	host := r.URL.Host
	if isAIHost(host) {
		p.inspectAndForward(w, r, host)
		return
	}
	r.RequestURI = ""
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Upstream request failed", 502)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func (p *proxy) inspectAndForward(w http.ResponseWriter, r *http.Request, host string) {
	if r.URL.Scheme == "" {
		r.URL.Scheme = "https"
	}
	if r.URL.Host == "" {
		r.URL.Host = host
	}

	// GET/HEAD/DELETE and non-prompt POSTs are passed through unchanged.
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		r.RequestURI = ""
		resp, err := p.transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "Upstream request failed", 502)
			return
		}
		defer resp.Body.Close()
		copyResponse(w, resp)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, "Request body read failed", 400)
		return
	}
	_ = r.Body.Close()
	plain, encode, err := decodeRequestBody(body, r.Header.Get("Content-Encoding"))
	if err != nil { // We cannot safely inspect this prompt payload.
		w.Header().Set("X-DeepGuard-Inspection", "unsupported-content-encoding")
		http.Error(w, "DeepGuard BLOCK: request encoding could not be inspected safely.", 415)
		return
	}

	prompt, isPrompt := "", false
	if isPromptRequest(r, plain) {
		prompt, isPrompt = extractPromptText(plain)
	}
	if !isPrompt {
		// Fast path: normal AI page traffic, assets, telemetry, OPTIONS, streaming
		// setup and other non-prompt calls never reach the DLP API or event log.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Length", fmt.Sprint(len(body)))
		r.RequestURI = ""
		resp, err := p.transport.RoundTrip(r)
		if err != nil {
			http.Error(w, "Upstream request failed", 502)
			return
		}
		defer resp.Body.Close()
		copyResponse(w, resp)
		return
	}

	appName := r.Header.Get("User-Agent")
	if appName == "" {
		appName = "Unknown AI client"
	}
	d := inspect(plain, host, appName, prompt)
	action := strings.ToLower(strings.TrimSpace(d.Action))
	w.Header().Set("X-DeepGuard-Action", action)
	w.Header().Set("X-DeepGuard-Prompt", "true")
	w.Header().Set("X-DeepGuard-Risk", fmt.Sprint(d.RiskScore))
	w.Header().Set("X-DeepGuard-Findings", fmt.Sprint(d.FindingCount))
	if action == "block" {
		w.Header().Set("X-DeepGuard-Blocked", "true")
		http.Error(w, "DeepGuard BLOCK: sensitive content detected before the AI request was sent.", 403)
		return
	}

	if action == "redact" {
		redactedPlain, err := redactPromptBody(plain, prompt, d.RedactedContent, r.Header.Get("Content-Type"))
		if err != nil {
			http.Error(w, "DeepGuard REDACT failed", 502)
			return
		}
		redacted, err := encode(redactedPlain)
		if err != nil {
			http.Error(w, "DeepGuard REDACT failed", 502)
			return
		}
		body = redacted
		if r.Header.Get("Content-Encoding") == "" {
			r.Header.Del("Content-Encoding")
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	r.RequestURI = ""
	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		http.Error(w, "Upstream request failed", 502)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func copyResponse(w http.ResponseWriter, r *http.Response) {
	// Hop-by-hop headers are managed by net/http and must not be copied through.
	hop := map[string]bool{"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "TE": true, "Trailer": true, "Upgrade": true}
	for k, v := range r.Header {
		if hop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, x := range v {
			w.Header().Add(k, x)
		}
	}
	w.WriteHeader(r.StatusCode)
	_, _ = io.Copy(w, r.Body)
}

func tunnelHTTP1(client, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	go func() { _, _ = io.Copy(upstream, client) }()
	_, _ = io.Copy(client, upstream)
}

type singleConnListener struct {
	conn net.Conn
	used bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, io.EOF
	}
	l.used = true
	return l.conn, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func main() {
	flag.Parse()
	if *caDir == "" {
		*caDir = filepath.Join(os.TempDir(), "DeepGuardCA")
	}
	ca, err := loadOrCreateCA(*caDir)
	if err != nil {
		log.Fatal(err)
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 20, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	p := &proxy{ca: ca, transport: tr}
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", *listenPort), Handler: p, ReadHeaderTimeout: 20 * time.Second, IdleTimeout: 90 * time.Second}
	log.Printf("DeepGuard Go network agent listening on 127.0.0.1:%d", *listenPort)
	log.Fatal(srv.ListenAndServe())
}
