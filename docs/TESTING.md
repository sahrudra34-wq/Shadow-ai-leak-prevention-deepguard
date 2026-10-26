# DeepGuard OneApp v5.3 Testing

## 1. Local tests

```powershell
npm test
cd proxygo
go test ./...
```

Expected: all Node and Go tests pass.

## 2. Startup

Run:

```powershell
npm start
```

DeepGuard starts the local proxy and installs an local Windows proxy automatically. Normal internet traffic remains DIRECT. Diagnostics also run in the background. The **Recheck** button is optional.

Expected dashboard health:

- Proxy: `ACTIVE`
- local Windows proxy: `ACTIVE`
- CA: `TRUSTED`
- TLS Inspection: `WORKING`

## 3. Scan-on-send test

Open ChatGPT Web.

1. Type a sensitive test prompt.
2. Do not send it.
3. Confirm that Live Protection Events stays unchanged.
4. Send the prompt.
5. Confirm exactly one prompt event appears.

This verifies that typing/draft traffic is ignored and the actual send request is inspected.

## 4. DLP behavior

Use fake values:

```text
Name: Rahul Sharma
Email: rahul@example.com
Phone: +91-9876543210
Password: Rahul@2026
API_KEY: test_api_key_987654321
```

Expected: `REDACT`.

Use a fake private-key header or fake database URL to test `BLOCK`.

There is no finding-count-based limit. Many ordinary findings are still redacted.

## 6. Claude Desktop

Restart Claude Desktop after DeepGuard is already protected, then send a fake sensitive prompt. The Anthropic Messages API path `/v1/messages` is explicitly recognized.

If no event appears while browser tests work, inspect whether the Claude build uses the Windows proxy and accepts the DeepGuard CA. Do not disable certificate pinning or other application security controls.

## 7. What counts as success

- A typed but unsent prompt creates **no** live event.
- A submitted safe prompt creates one `ALLOW` event.
- A submitted sensitive prompt creates one `REDACT`/`WARN`/`BLOCK` event as determined by policy.
- Background requests do not inflate the counters.
- Redaction preserves the provider request structure.
