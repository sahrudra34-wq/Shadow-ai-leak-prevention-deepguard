# DeepGuard OneApp v5.5.7

DeepGuard is a Windows-first desktop AI DLP agent. It protects supported AI websites and desktop AI applications through a local Go HTTPS proxy and a local JavaScript DLP engine. No browser extension is required.

## What this build fixes

- **Prompt-only inspection:** typing, drafts, page-load traffic, telemetry and background requests are ignored.
- **Scan on Send:** ChatGPT web is restricted to the real conversation `action="next"` request, so typing in the composer is not treated as a submitted prompt.
- **Claude coverage:** dedicated handling for Anthropic `POST /v1/messages` requests plus narrow Claude Web `/api/*` message/completion paths.
- **Structured redaction:** the original provider request structure is preserved instead of replacing the whole body with plain text.
- **All findings are redacted:** there is no 7-finding or other arbitrary finding-count limit.
- **Normal sensitive data:** PII, passwords and API-key-like values normally use `REDACT`.
- **Critical secrets:** private keys, AWS keys and database URLs remain `BLOCK`.
- **Live events:** every real submitted prompt is recorded, including `ALLOW`, while background traffic is not recorded.
- **Diagnostics:** the Run checks button is manual and read-only while protection is OFF. It never starts the proxy by itself.
- **Protection switch:** the dashboard has a real ON/OFF switch. Protection starts OFF. ON first verifies the local proxy and HTTPS inspection, then changes Windows networking. OFF restores the previous Windows proxy settings before stopping the agent.
- **Safe Windows routing:** the app uses only a temporary local manual proxy at `127.0.0.1:47822` while protection is ON. No PAC/setup script is installed. Protected AI hosts are inspected; other traffic is tunneled normally. If the proxy process unexpectedly exits, DeepGuard automatically restores direct networking.

## Architecture

```text
Browser / supported desktop AI app
              |
              v
       Windows local inspection proxy
       (AI hosts -> local proxy; everything else -> DIRECT)
              |
              v
     DeepGuard Go HTTPS proxy
              |
        Prompt extraction
              |
              v
       JavaScript DLP engine
              |
        Risk + policy engine
              |
       ALLOW / WARN / REDACT / BLOCK
              |
              v
          AI provider
```

## Main technologies

- **Electron + JavaScript:** desktop UI and application lifecycle
- **HTML/CSS:** dashboard UI
- **Go:** local HTTP CONNECT + TLS MITM proxy
- **JavaScript:** DLP rules, normalization, risk scoring and redaction
- **JSON:** policy and configuration
- **Windows registry:** temporary user-proxy configuration and CA trust

## Important desktop-app limitation

A generic user-space MITM proxy can inspect an application only when that application uses the Windows/system proxy path and accepts the DeepGuard CA. An application that bypasses the proxy, uses custom networking/QUIC, or uses certificate pinning can remain outside generic inspection. DeepGuard does not disable or bypass those security controls.

For Claude Desktop specifically, the Anthropic Messages API uses `POST /v1/messages` with user-role messages, which DeepGuard now has a dedicated detector for. If the installed Claude Desktop build does not send that traffic through the Windows proxy or does not trust the DeepGuard CA, the proxy cannot see the prompt.

## Install / run

Requirements:

- Windows 10/11
- Node.js 20+
- Bundled `proxygo/deepguard-proxy.exe`

```powershell
npm install
npm test
npm start
```

Protection is OFF when the app opens. Turn it ON to start verified protection. Turn it OFF to restore the normal Windows network path. Diagnostics never enable protection.

After the first proxy/CA setup, restart Chrome/Edge so old connections are recreated. If an older DeepGuard build left **Use setup script** enabled, start v5.5.7 and use **Repair network** once; the old DeepGuard PAC is removed automatically.

## Test prompts

Use fake values only:

```text
Name: Rahul Sharma
Email: rahul@example.com
Phone: +91-9876543210
Password: Rahul@2026
API_KEY: test_api_key_987654321
```

Expected behavior:

| Test | Expected action |
|---|---|
| Normal prompt | ALLOW |
| Name/email/phone/password/API key | REDACT |
| Prompt injection/source-code indicator | WARN |
| Private key/AWS key/database URL | BLOCK |
| 8+ ordinary findings | REDACT, not count-based BLOCK |

## Provider tests

### ChatGPT Web

1. Start DeepGuard.
2. Turn Protection ON and wait until the dashboard shows the proxy as active.
3. Open/restart Chrome.
4. Open ChatGPT.
5. Type the test prompt but do not send it — **no Live Protection Event should appear**.
6. Send it — **one prompt event** should appear.

### Claude Desktop

1. Start DeepGuard.
2. Fully quit Claude Desktop.
3. Start Claude Desktop again after DeepGuard protection is active.
4. Send the fake test prompt.
5. Check Live Protection Events.

If Chrome/ChatGPT is observed but Claude Desktop produces no event, the most useful check is whether Claude Desktop is using a different network/trust path. A generic proxy cannot force inspection of traffic that never reaches it.

## Tests included

```powershell
npm test
cd proxygo
go test ./...
```

The test suite covers DLP rules, redaction, finding-count behavior, ChatGPT send-vs-draft filtering, Claude API/web detection, gzip handling and request-shape preservation.
### v5.5.7 fixes
- **No PAC/setup-script mode:** DeepGuard now uses only the manual local proxy `127.0.0.1:47822`; it never installs the old `127.0.0.1:47821/deepguard.pac` setup script.
- **Windows proxy repair:** stale DeepGuard PAC/manual settings are detected and removed; AutoDetect is disabled while protection is ON and the previous value is restored on OFF.
- **Faster switch:** removed the repeated 3.5-second registry + PowerShell verification loop; enable/disable now performs one bounded registry verification after the WinINet refresh.
- **Repair network button:** the dashboard can restore the normal Windows network path if an older build left proxy settings behind.

### v5.4.0 fixes
- Live event counters deduplicate exact provider retries for 3 seconds using destination + client + prompt hash, so ALLOWED/REDACTED/BLOCKED counts reflect submitted prompts instead of immediate network retries.



## Safe Windows proxy mode

While protection is ON, Windows sends traffic through the temporary local proxy at `127.0.0.1:47822`. The Go agent tunnels ordinary traffic normally and only performs TLS inspection for configured AI hosts. The Go agent tunnels ordinary traffic normally and inspects configured AI hosts. No PAC/setup script is installed by DeepGuard. This prevents ordinary websites, Windows services, downloads, and unrelated applications from depending on a PAC. On shutdown, the original Windows proxy configuration is restored.
