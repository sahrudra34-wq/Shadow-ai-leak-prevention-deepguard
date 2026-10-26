const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const net = require('net');
const tls = require('tls');
const { spawn, execFile } = require('child_process');
const { createHash } = require('crypto');
const { Notification } = require('electron');
const StoreModule = require('electron-store');
const Store = StoreModule.default || StoreModule;
const log = require('electron-log');
const { scanPrompt, redactText } = require('../core/dlp');
const POLICY = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config', 'policy.json'), 'utf8')); }
  catch { return { blockScore: 98, redactScore: 10, warnScore: 94, failClosed: true }; }
})();

const PROXY_PORT = 47822;
const API_PORT = 47821;
const WINDOWS_PROXY_REFRESH_TIMEOUT = 2500;
const PROXY_HOST = '127.0.0.1';
const LOCAL_PROXY = `${PROXY_HOST}:${PROXY_PORT}`;
// DeepGuard uses a normal local Windows HTTP proxy while protection is ON.
// It deliberately does NOT install a PAC/setup script. The Go agent tunnels
// non-AI traffic directly and only MITM-inspects configured AI hosts.
const RUNTIME_DIR = path.join(app.getPath('userData'), 'runtime');
const CA_DIR = path.join(RUNTIME_DIR, 'ca');
const CA_CERT = path.join(CA_DIR, 'ca-cert.cer');
const PROXY_BINARY = process.platform === 'win32'
  ? path.join(__dirname, '..', 'proxygo', 'deepguard-proxy.exe')
  : path.join(__dirname, '..', 'proxygo', 'deepguard-proxy');
const store = new Store({ name: 'deepguard-settings', defaults: {
  proxyPort: PROXY_PORT,
  autoProxy: false,
  protectionEnabled: false,
  originalWindowsProxy: null,
  originalQuicPolicies: null,
  proxyOwner: false
}});

let mainWindow = null;
let proxyProcess = null;
let server = null;
let proxyReady = false;
let windowsProxyConfigured = false;
let caTrusted = false;
let proxyError = '';
let proxyLastLog = '';
let bootstrapStatus = '';
let originalWindowsProxy = null;
let originalQuicPolicies = null;
let proxyStartPromise = null;
let proxyConfigurePromise = null;
let protectionOp = 0;
let apiReady = false;
let shuttingDown = false;
const events = [];
const MAX_EVENTS = 200;
const promptCache = new Map();
const PROMPT_DEDUP_MS = 3000;

function hashPrompt(content) {
  return createHash('sha256').update(String(content || '')).digest('hex');
}

function cachedResult(key) {
  const hit = promptCache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > PROMPT_DEDUP_MS) { promptCache.delete(key); return null; }
  return hit.result;
}

function cacheResult(key, result) {
  promptCache.set(key, { at: Date.now(), result });
  if (promptCache.size > 200) {
    const first = promptCache.keys().next().value;
    if (first) promptCache.delete(first);
  }
}

function addEvent(e) {
  events.unshift({ id: Date.now() + Math.random(), time: new Date().toISOString(), ...e });
  if (events.length > MAX_EVENTS) events.pop();
  mainWindow?.webContents.send('events:update', events.slice(0, 100));
}
function send(res, code, payload) {
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
}
function status() {
  const enabled = !!store.get('protectionEnabled', store.get('autoProxy'));
  return {
    protected: enabled,
    enabled,
    active: enabled && !!(proxyReady && windowsProxyConfigured && caTrusted),
    proxy: proxyReady && !!proxyProcess,
    proxyPort: store.get('proxyPort'),
    proxyMode: 'Local inspection proxy',
    pacUrl: '',
    windowsProxy: windowsProxyConfigured,
    caTrusted,
    api: apiReady,
    platform: process.platform,
    proxyError,
    proxyLastLog,
    bootstrapStatus
  };
}
function broadcastStatus() { mainWindow?.webContents.send('status:update', status()); }

async function createServer() {
  if (server) return true;
  server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'GET' && req.url === '/api/status') return send(res, 200, status());
    if (req.method === 'GET' && req.url === '/api/events') return send(res, 200, { events });
    if (req.method === 'POST' && (req.url === '/api/scan' || req.url === '/api/inspect')) return body(req, data => handleScan(data, res));
    send(res, 404, { error: 'not_found' });
  });
  await new Promise((resolve, reject) => {
    const onError = err => { server?.removeListener('listening', onListening); server = null; apiReady = false; reject(err); };
    const onListening = () => { server?.removeListener('error', onError); apiReady = true; resolve(); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(API_PORT, PROXY_HOST);
  });
  return true;
}
function body(req, cb) {
  let raw = '';
  req.on('data', c => {
    raw += c;
    if (raw.length > 5_000_000) req.destroy();
  });
  req.on('end', () => {
    try { cb(JSON.parse(raw || '{}')); } catch { cb({}); }
  });
}
function detectSource(value) {
  const ua = String(value || '');
  if (/Electron|Tauri|DeepGuardDesktop|DesktopApp/i.test(ua)) return 'Desktop application';
  if (/Chrome\/|Edg\/|Firefox\/|Safari\//i.test(ua)) return 'Browser';
  if (ua) return 'Application / unknown client';
  return 'Unknown client';
}

function friendlyAppName(value) {
  const ua = String(value || '');
  if (/Electron/i.test(ua)) return 'Desktop AI app';
  if (/Edg\//i.test(ua)) return 'Microsoft Edge';
  if (/Chrome\//i.test(ua)) return 'Google Chrome';
  if (/Firefox\//i.test(ua)) return 'Firefox';
  if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) return 'Safari';
  return ua ? ua.slice(0, 80) : 'Unknown AI client';
}

function handleScan(data, res) {
  const content = String(data?.content || '');
  const destination = String(data?.destination || 'unknown').toLowerCase();
  const channel = data?.channel || 'live';
  const isPrompt = data?.isPrompt !== false;
  // Live proxy traffic must explicitly identify itself as a real prompt.
  // This prevents telemetry/background API calls from inflating the dashboard.
  if (channel === 'live-network' && !isPrompt) {
    return send(res, 200, { action: 'allow', riskScore: 0, findingCount: 0, findings: [], isPrompt: false, recorded: false });
  }

  const cacheKey = `${destination}|${friendlyAppName(data?.app)}|${hashPrompt(content)}`;
  const cached = channel === 'live-network' ? cachedResult(cacheKey) : null;
  const result = cached || scanPrompt(content, { destination, channel, blockScore: POLICY.blockScore, redactScore: POLICY.redactScore, warnScore: POLICY.warnScore });
  const duplicate = channel === 'live-network' && !!cached;
  if (!cached && channel === 'live-network') cacheResult(cacheKey, result);

  const action = result.action;
  const finalResult = { ...result, action, isPrompt, recorded: false, policyOverride: '', redactedContent: action === 'redact' ? redactText(content) : undefined };

  // A single submitted prompt can cause provider retries/background follow-up
  // requests. Exact destination + client + prompt-hash deduplication keeps the
  // counters tied to submitted prompts rather than network retry noise.
  if (isPrompt && !duplicate) {
    // Record only real submitted prompts. Safe prompts are kept too, so
    // SCANNED reflects the number of prompts actually sent, while page-load,
    // typing/draft, telemetry and other background traffic stays invisible.
    addEvent({ app: friendlyAppName(data?.app), source: detectSource(data?.app), destination, risk: result.riskScore, action, findings: result.findingCount, reason: result.action, channel: 'prompt' });
    finalResult.recorded = true;
    if ((action === 'block' || action === 'redact') && Notification.isSupported()) {
      try {
        const source = detectSource(data?.app);
        const title = action === 'block' ? 'DeepGuard blocked a prompt' : 'DeepGuard redacted a prompt';
        const bodyText = action === 'block'
          ? `${source} • ${friendlyAppName(data?.app)} → ${destination} • Risk ${result.riskScore}/100`
          : `${source} • ${friendlyAppName(data?.app)} → ${destination} • ${result.findingCount} sensitive value(s) removed`;
        new Notification({ title, body: bodyText, silent: false }).show();
      } catch {}
    }
  }
  send(res, 200, finalResult);
}

function waitForPort(port, host, timeoutMs = 5000) {
  return new Promise(resolve => {
    const started = Date.now();
    let done = false;
    const finish = value => { if (!done) { done = true; resolve(value); } };
    const attempt = () => {
      if (done) return;
      if (Date.now() - started >= timeoutMs) return finish(false);
      const socket = net.createConnection({ port, host });
      socket.setTimeout(700);
      socket.once('connect', () => { socket.destroy(); finish(true); });
      socket.once('timeout', () => { socket.destroy(); setTimeout(attempt, 120); });
      socket.once('error', () => { socket.destroy(); setTimeout(attempt, 180); });
    };
    attempt();
  });
}

function probeProxyTls(timeoutMs = 8000) {
  return new Promise(resolve => {
    let settled = false;
    const finish = value => { if (!settled) { settled = true; try { socket.destroy(); } catch {} resolve(value); } };
    const socket = net.createConnection({ host: PROXY_HOST, port: PROXY_PORT });
    const timer = setTimeout(() => finish({ ok: false, error: 'Proxy TLS probe timed out.' }), timeoutMs);
    const fail = error => { clearTimeout(timer); finish({ ok: false, error: error?.message || String(error) }); };
    socket.once('error', fail);
    socket.once('connect', () => {
      socket.write('CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\nProxy-Connection: keep-alive\r\n\r\n');
    });
    let header = '';
    const onData = chunk => {
      header += chunk.toString('latin1');
      const at = header.indexOf('\r\n\r\n');
      if (at === -1) return;
      socket.removeListener('data', onData);
      if (!/^HTTP\/1\.1 200 /i.test(header)) {
        clearTimeout(timer); return finish({ ok: false, error: `Proxy CONNECT failed: ${header.split('\\r\\n')[0] || 'unknown response'}` });
      }
      const secure = tls.connect({ socket, servername: 'chatgpt.com', rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
      secure.once('secureConnect', () => {
        clearTimeout(timer);
        const cert = secure.getPeerCertificate(true) || {};
        const subject = cert.subject?.CN || '';
        const issuer = cert.issuer?.O || cert.issuer?.CN || '';
        const ok = /chatgpt\.com$/i.test(subject) && /DeepGuard/i.test(`${issuer} ${cert.issuer?.CN || ''}`);
        finish({ ok, subject, issuer, error: ok ? '' : 'TLS handshake succeeded but the certificate did not look like a DeepGuard inspection certificate.' });
      });
      secure.once('error', fail);
    };
    socket.on('data', onData);
  });
}

async function probeProxyHttp(timeoutMs = 12000) {
  return new Promise(resolve => {
    let settled = false;
    const finish = value => { if (!settled) { settled = true; try { socket.destroy(); } catch {} resolve(value); } };
    const socket = net.createConnection({ host: PROXY_HOST, port: PROXY_PORT });
    const timer = setTimeout(() => finish({ ok: false, error: 'HTTPS probe timed out.' }), timeoutMs);
    const fail = error => { clearTimeout(timer); finish({ ok: false, error: error?.message || String(error) }); };
    socket.once('error', fail);
    socket.once('connect', () => {
      socket.write('CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\nProxy-Connection: keep-alive\r\n\r\n');
    });
    let header = '';
    const onData = chunk => {
      header += chunk.toString('latin1');
      const at = header.indexOf('\r\n\r\n');
      if (at === -1) return;
      socket.removeListener('data', onData);
      if (!/^HTTP\/1\.1 200 /i.test(header)) {
        clearTimeout(timer); return finish({ ok: false, error: `Proxy CONNECT failed: ${header.split('\r\n')[0] || 'unknown response'}` });
      }
      const secure = tls.connect({ socket, servername: 'chatgpt.com', rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] });
      secure.once('secureConnect', () => {
        secure.write('GET /robots.txt HTTP/1.1\r\nHost: chatgpt.com\r\nConnection: close\r\nUser-Agent: DeepGuard-Diagnostics/5.5.7\r\nAccept: */*\r\n\r\n');
      });
      let responseHead = '';
      secure.on('data', chunk => {
        responseHead += chunk.toString('latin1');
        const end = responseHead.indexOf('\r\n');
        if (end !== -1) {
          clearTimeout(timer);
          const statusLine = responseHead.slice(0, end);
          const match = statusLine.match(/^HTTP\/1\.[01] (\d{3})/i);
          finish({ ok: !!match, statusCode: match ? Number(match[1]) : 0, statusLine });
        }
      });
      secure.once('error', fail);
      secure.once('end', () => { if (!settled) fail(new Error('HTTPS probe ended without an HTTP response.')); });
    };
    socket.on('data', onData);
  });
}

async function readWindowsInternetSettings() {
  if (process.platform !== 'win32') return null;
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const r = await runCommand('reg.exe', ['QUERY', key], { timeout: 2500 });
  if (!r.ok) return null;
  const text = String(r.stdout || '');
  const get = name => {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const m = text.match(new RegExp('^\\s*' + escaped + '\\s+REG_\\w+\\s+([^\\r\\n]+)$', 'im'));
    return m ? m[1].trim() : '';
  };
  const dword = name => {
    const value = get(name);
    if (!value) return null;
    if (/^0x/i.test(value)) return parseInt(value, 16);
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  };
  return {
    Enabled: dword('ProxyEnable') ?? 0,
    Server: get('ProxyServer'),
    Override: get('ProxyOverride'),
    AutoConfigURL: get('AutoConfigURL'),
    AutoDetect: dword('AutoDetect')
  };
}

function normalizeProxyServer(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\s+/g, '');
}

function proxyServerContainsLocal(value) {
  const normalized = normalizeProxyServer(value);
  const target = LOCAL_PROXY.toLowerCase();
  if (normalized === target) return true;
  const entries = normalized.split(';').map(x => x.trim()).filter(Boolean);
  if (!entries.length) return false;
  return entries.every(entry => {
    const rhs = entry.includes('=') ? entry.split('=').slice(1).join('=') : entry;
    return rhs === target;
  });
}

async function checkWindowsProxyActual() {
  const x = await readWindowsInternetSettings();
  if (!x) return false;
  // Windows can prefer auto-detection/PAC before the manual proxy. DeepGuard
  // therefore disables both while ON and verifies both are really off.
  return Number(x.Enabled || 0) === 1 &&
    proxyServerContainsLocal(x.Server) &&
    Number(x.AutoDetect ?? 0) === 0 &&
    !String(x.AutoConfigURL || '').trim();
}

function isDeepGuardOwnedWindowsSettings(x) {
  if (!x) return false;
  const server = String(x.Server || '').trim().toLowerCase();
  const pac = String(x.AutoConfigURL || '').trim().toLowerCase();
  return pac.includes('deepguard') || pac.includes('127.0.0.1:47821') ||
    pac.includes('localhost:47821') || server === LOCAL_PROXY.toLowerCase() ||
    server.includes('127.0.0.1:47822') || server.includes('localhost:47822');
}

function directWindowsSettings(autoDetect = 1) {
  return { Enabled: 0, Server: '', Override: '', AutoConfigURL: '', AutoDetect: Number(autoDetect) ? 1 : 0 };
}

async function checkLegacyDeepGuardManualProxy() {
  const x = await readWindowsInternetSettings();
  return isDeepGuardOwnedWindowsSettings(x) && Number(x.Enabled) === 1;
}

async function waitForWindowsProxyState(expected, timeoutMs = 600) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const actual = await checkWindowsProxyActual();
    if (actual === expected) return true;
    await new Promise(r => setTimeout(r, 100));
  }
  return (await checkWindowsProxyActual()) === expected;
}

async function recoverStaleProxy() {
  if (process.platform !== 'win32') return;
  const current = await readWindowsInternetSettings();
  if (!current) return;
  const stale = isDeepGuardOwnedWindowsSettings(current) || store.get('proxyOwner');
  if (!stale) return;

  const saved = store.get('originalWindowsProxy');
  const restore = saved && typeof saved === 'object' && !isDeepGuardOwnedWindowsSettings(saved)
    ? saved
    : directWindowsSettings();
  proxyError = 'Cleaning up the previous DeepGuard network session…';
  broadcastStatus();
  await setWindowsUserProxy(false, restore);

  const savedQuic = store.get('originalQuicPolicies');
  if (savedQuic && !originalQuicPolicies) originalQuicPolicies = Array.isArray(savedQuic) ? savedQuic : [savedQuic];
  await restoreBrowserQuicPolicy();
  store.set('proxyOwner', false);
  store.delete('originalWindowsProxy');
  windowsProxyConfigured = false;
  proxyError = '';
}

async function checkCaTrustActual() {
  if (process.platform !== 'win32') return caTrusted;
  const r = await runCommand('certutil.exe', ['-user', '-store', 'Root', 'DeepGuard Local Inspection CA'], { timeout: 5000 });
  return r.ok && /DeepGuard Local Inspection CA/i.test(`${r.stdout}\n${r.stderr}`);
}

async function killStaleDeepGuardProxy() {
  if (process.platform !== 'win32') return;
  // Only target DeepGuard's own bundled executable. This is used only when
  // 47822 is occupied before this app has started its own child process.
  await runCommand('taskkill.exe', ['/IM', 'deepguard-proxy.exe', '/F', '/T'], { timeout: 4000 });
  await new Promise(r => setTimeout(r, 150));
}

async function startProxy() {
  if (proxyProcess && proxyReady) return true;
  if (proxyStartPromise) return proxyStartPromise;

  proxyStartPromise = (async () => {
    proxyError = '';
    proxyLastLog = '';
    proxyReady = false;
    bootstrapStatus = 'Starting DeepGuard network agent…';
    broadcastStatus();

    if (process.platform === 'win32' && !fs.existsSync(PROXY_BINARY)) {
      proxyError = `Bundled network agent not found: ${PROXY_BINARY}`;
      bootstrapStatus = 'DeepGuard network agent is missing from the installation.';
      broadcastStatus();
      return false;
    }

    // A crashed/older DeepGuard session can leave 47822 occupied. Never put
    // Windows onto a proxy port until we know this exact agent owns the port.
    if (await waitForPort(PROXY_PORT, PROXY_HOST, 250)) {
      await killStaleDeepGuardProxy();
      if (await waitForPort(PROXY_PORT, PROXY_HOST, 500)) {
        proxyError = `Port ${PROXY_PORT} is already in use. Close the other DeepGuard instance and try again.`;
        bootstrapStatus = 'Protection could not start safely; the proxy port is occupied.';
        broadcastStatus();
        return false;
      }
    }

    fs.mkdirSync(CA_DIR, { recursive: true });
    const child = spawn(PROXY_BINARY, [
      '--port', String(PROXY_PORT),
      '--ca-dir', CA_DIR,
      '--api', `http://${PROXY_HOST}:${API_PORT}/api/inspect`
    ], {
      cwd: path.dirname(PROXY_BINARY),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env }
    });
    proxyProcess = child;

    child.stdout.on('data', d => {
      const msg = d.toString().trim();
      if (!msg) return;
      proxyLastLog = msg.slice(-1200);
      log.info('[go-proxy]', msg);
      broadcastStatus();
    });
    child.stderr.on('data', d => {
      const msg = d.toString().trim();
      if (!msg) return;
      proxyLastLog = msg.slice(-1600);
      proxyError = msg;
      log.warn('[go-proxy]', msg);
      broadcastStatus();
    });
    child.on('error', err => {
      proxyError = err?.message || String(err);
      proxyReady = false;
      broadcastStatus();
    });
    child.on('exit', code => {
      const unexpected = !shuttingDown && !!store.get('protectionEnabled');
      if (code !== 0 && !proxyError) proxyError = `Network agent exited with code ${code}. ${proxyLastLog}`;
      proxyReady = false;
      if (proxyProcess === child) proxyProcess = null;
      broadcastStatus();
      // Fail safe: if the local proxy dies while Windows is pointed at it,
      // immediately restore direct networking instead of leaving Chrome with
      // ERR_PROXY_CONNECTION_FAILED.
      if (unexpected) {
        setTimeout(async () => {
          if (!store.get('protectionEnabled') || shuttingDown) return;
          store.set('protectionEnabled', false);
          store.set('autoProxy', false);
          const restored = await restoreWindowsProxy(true);
          windowsProxyConfigured = false;
          bootstrapStatus = restored
            ? 'Protection stopped safely because the network agent exited. Normal internet restored.'
            : 'Protection stopped, but Windows proxy restoration needs attention.';
          broadcastStatus();
        }, 0);
      }
    });

    proxyReady = await waitForPort(PROXY_PORT, PROXY_HOST, 2500);
    if (!proxyReady) {
      proxyError = proxyError || `DeepGuard network agent did not listen on 127.0.0.1:${PROXY_PORT}.`;
      try { child.kill(); } catch {}
      if (proxyProcess === child) proxyProcess = null;
      broadcastStatus();
      return false;
    }

    for (let i = 0; i < 40 && !fs.existsSync(CA_CERT); i++) await new Promise(r => setTimeout(r, 250));
    if (!fs.existsSync(CA_CERT)) {
      proxyError = 'Network agent is listening, but its local CA certificate was not created.';
      try { child.kill(); } catch {}
      if (proxyProcess === child) proxyProcess = null;
      proxyReady = false;
      broadcastStatus();
      return false;
    }

    // Prove the proxy can actually establish an HTTPS inspection connection
    // BEFORE changing the Windows proxy. This prevents browser-wide
    // ERR_PROXY_CONNECTION_FAILED when the local agent is unhealthy.
    const tlsCheck = await probeProxyTls(2500);
    if (!tlsCheck.ok) {
      proxyError = tlsCheck.error || 'Local HTTPS inspection probe failed.';
      try { child.kill(); } catch {}
      if (proxyProcess === child) proxyProcess = null;
      proxyReady = false;
      broadcastStatus();
      return false;
    }

    bootstrapStatus = 'Network protection ready.';
    broadcastStatus();
    return true;
  })();

  try { return await proxyStartPromise; }
  finally { proxyStartPromise = null; }
}


function runCommand(file, args, options = {}) {
  return new Promise(resolve => {
    execFile(file, args, { windowsHide: true, timeout: options.timeout || 120000, cwd: options.cwd }, (error, stdout, stderr) => {
      resolve({ ok: !error, stdout: String(stdout || ''), stderr: String(stderr || ''), error });
    });
  });
}
async function readCurrentWindowsProxy() {
  if (process.platform !== 'win32') return;
  if (originalWindowsProxy) return;
  const saved = store.get('originalWindowsProxy');
  if (saved && typeof saved === 'object' && !isDeepGuardOwnedWindowsSettings(saved)) {
    originalWindowsProxy = saved;
    return;
  }
  const x = await readWindowsInternetSettings();
  if (x && !isDeepGuardOwnedWindowsSettings(x)) {
    originalWindowsProxy = x;
    store.set('originalWindowsProxy', x);
  } else if (!x) {
    originalWindowsProxy = directWindowsSettings();
    store.set('originalWindowsProxy', originalWindowsProxy);
  }
}

async function queryQuicPolicy(root, name) {
  const r = await runCommand('reg.exe', ['QUERY', root, '/v', 'QuicAllowed'], { timeout: 3000 });
  if (!r.ok) return { Name: name, Exists: false, Value: null };
  const m = String(r.stdout).match(/QuicAllowed\s+REG_DWORD\s+0x([0-9a-f]+)/i);
  return { Name: name, Exists: !!m, Value: m ? parseInt(m[1], 16) : null };
}

async function configureBrowserQuicPolicy() { return true; }
async function restoreBrowserQuicPolicy() { return true; }

async function refreshWinInetProxy() {
  if (process.platform !== 'win32') return { ok: true };
  // Registry is the source of truth for WinINet proxy settings. The two
  // InternetSetOption notifications make already-running WinINet clients
  // re-read the settings without waiting for a long PowerShell round-trip.
  const ps = `
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DGWinInet {
  [DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int length);
}
'@;
    [DGWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null;
    [DGWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null;
  `;
  return runCommand('powershell.exe', ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command', ps], { timeout: WINDOWS_PROXY_REFRESH_TIMEOUT });
}

async function readWindowsProxyViaPowerShell() {
  if (process.platform !== 'win32') return null;
  const ps = `
    $p='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';
    $x=Get-ItemProperty -Path $p -ErrorAction Stop;
    [pscustomobject]@{Enabled=[int]$x.ProxyEnable;Server=[string]$x.ProxyServer;Override=[string]$x.ProxyOverride;AutoConfigURL=[string]$x.AutoConfigURL} | ConvertTo-Json -Compress
  `;
  const r = await runCommand('powershell.exe', ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command', ps], { timeout: 5000 });
  if (!r.ok) return null;
  try { return JSON.parse(String(r.stdout || '').trim()); } catch { return null; }
}

async function setWindowsUserProxy(enabled, settings = null) {
  if (process.platform !== 'win32') return false;

  let old = settings || directWindowsSettings();
  if (!enabled && isDeepGuardOwnedWindowsSettings(old)) {
    const current = await readWindowsInternetSettings();
    old = directWindowsSettings(current?.AutoDetect ?? 1);
  }

  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
  const write = async (name, type, value) => {
    const r = await runCommand('reg.exe', ['ADD', key, '/v', name, '/t', type, '/d', String(value), '/f'], { timeout: 2500 });
    if (!r.ok) throw new Error(r.stderr || r.stdout || `reg.exe failed for ${name}`);
  };
  const remove = async name => {
    const r = await runCommand('reg.exe', ['DELETE', key, '/v', name, '/f'], { timeout: 2500 });
    return r.ok || /unable to find|cannot find|does not exist/i.test(`${r.stdout} ${r.stderr}`);
  };

  try {
    if (enabled) {
      // IMPORTANT: never use DeepGuard PAC/setup-script mode. A stale PAC is
      // exactly what causes ERR_PROXY_CONNECTION_FAILED when the local agent
      // is not listening. Use only a verified manual proxy.
      await write('AutoDetect', 'REG_DWORD', 0);
      await remove('AutoConfigURL');
      await write('ProxyServer', 'REG_SZ', LOCAL_PROXY);
      await write('ProxyOverride', 'REG_SZ', String(old.Override || ''));
      await write('ProxyEnable', 'REG_DWORD', 1);
      await refreshWinInetProxy();

      const actual = await readWindowsInternetSettings();
      const configured = !!actual && Number(actual.Enabled || 0) === 1 &&
        proxyServerContainsLocal(actual.Server) && Number(actual.AutoDetect ?? 0) === 0 &&
        !String(actual.AutoConfigURL || '').trim();
      if (!configured) {
        proxyError = `Windows proxy verification failed. Expected manual proxy ${LOCAL_PROXY}; actual=${JSON.stringify(actual || {})}.`;
        windowsProxyConfigured = false;
        return false;
      }
      windowsProxyConfigured = true;
      store.set('proxyOwner', true);
      proxyError = '';
      return true;
    }

    // Restore the user's exact previous WinINet state. DeepGuard-owned stale
    // state is never restored as another DeepGuard proxy.
    const target = isDeepGuardOwnedWindowsSettings(old)
      ? directWindowsSettings(old.AutoDetect ?? 1)
      : old;
    await write('ProxyServer', 'REG_SZ', String(target.Server || ''));
    await write('ProxyOverride', 'REG_SZ', String(target.Override || ''));
    await write('AutoDetect', 'REG_DWORD', Number(target.AutoDetect ?? 1) ? 1 : 0);
    if (String(target.AutoConfigURL || '').trim()) await write('AutoConfigURL', 'REG_SZ', String(target.AutoConfigURL));
    else await remove('AutoConfigURL');
    await write('ProxyEnable', 'REG_DWORD', Number(target.Enabled || 0) ? 1 : 0);
    await refreshWinInetProxy();

    const actual = await readWindowsInternetSettings();
    const restored = !!actual && Number(actual.Enabled || 0) === Number(target.Enabled || 0) &&
      normalizeProxyServer(actual.Server) === normalizeProxyServer(target.Server) &&
      Number(actual.AutoDetect ?? 0) === Number(target.AutoDetect ?? 1) &&
      String(actual.AutoConfigURL || '') === String(target.AutoConfigURL || '');
    windowsProxyConfigured = false;
    store.set('proxyOwner', false);
    if (!restored) proxyError = `Windows network restore verification failed; actual=${JSON.stringify(actual || {})}.`;
    return restored;
  } catch (error) {
    proxyError = `Windows proxy ${enabled ? 'enable' : 'restore'} failed: ${error?.message || error}`;
    windowsProxyConfigured = false;
    return false;
  }
}

async function ensureCaTrust() {
  if (process.platform !== 'win32') return true;
  if (caTrusted) return true;
  const imported = await runCommand('certutil.exe', ['-user', '-addstore', 'Root', CA_CERT], { timeout: 8000 });
  caTrusted = imported.ok || /already|exists|duplicate/i.test(imported.stdout + imported.stderr);
  if (!caTrusted) proxyError = `CA trust installation failed. ${imported.stderr || imported.stdout || ''}`.trim();
  return caTrusted;
}

async function configureWindowsProxy(opToken = protectionOp) {
  if (process.platform !== 'win32') return false;
  if (proxyConfigurePromise) return proxyConfigurePromise;

  proxyConfigurePromise = (async () => {
    const current = () => opToken === protectionOp && !!store.get('protectionEnabled');
    if (!current()) return false;
    if (!apiReady) await createServer();
    if (!current()) return false;
    if (!proxyReady && !(await startProxy())) return false;
    if (!current()) return false;
    await readCurrentWindowsProxy();
    if (!fs.existsSync(CA_CERT)) {
      caTrusted = false;
      proxyError = 'Proxy is running, but the local CA certificate was not created.';
      broadcastStatus();
      return false;
    }
    if (!(await ensureCaTrust())) {
      broadcastStatus();
      return false;
    }
    if (!current()) return false;

    store.set('proxyOwner', true);
    const configured = await setWindowsUserProxy(true);
    windowsProxyConfigured = configured;
    if (!configured || !current()) {
      if (configured && !current()) await restoreWindowsProxy(true);
      return false;
    }
    proxyError = '';
    bootstrapStatus = 'Protection ON — local proxy active; ordinary traffic is tunneled normally.';
    broadcastStatus();
    return true;
  })();

  try { return await proxyConfigurePromise; }
  finally { proxyConfigurePromise = null; }
}

async function restoreWindowsProxy(force = false) {
  if (process.platform !== 'win32') return true;
  const current = await readWindowsInternetSettings();
  const owned = isDeepGuardOwnedWindowsSettings(current);
  const actual = await checkWindowsProxyActual();
  if (!force && !windowsProxyConfigured && !actual && !owned) return true;
  const old = originalWindowsProxy || store.get('originalWindowsProxy') || directWindowsSettings();
  const restored = await setWindowsUserProxy(false, old);
  windowsProxyConfigured = false;
  if (restored) {
    store.delete('originalWindowsProxy');
    originalWindowsProxy = null;
  }
  broadcastStatus();
  return restored;
}

function stopProxy() {
  if (proxyProcess) { try { proxyProcess.kill(); } catch {} }
  proxyProcess = null;
  proxyReady = false;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1220,
    height: 820,
    minWidth: 980,
    minHeight: 680,
    title: 'DeepGuard OneApp',
    backgroundColor: '#080d19',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
}

ipcMain.handle('status', () => status());
ipcMain.handle('events', () => events);
ipcMain.handle('scan', (_, data) => {
  try {
  const result = scanPrompt(String(data?.content || ''), { destination: data?.destination || 'manual', channel: 'dashboard', blockScore: POLICY.blockScore, redactScore: POLICY.redactScore, warnScore: POLICY.warnScore });
  const action = result.action;
  const out = { ...result, action, policyOverride: '', redactedContent: action === 'redact' ? redactText(data?.content || '') : undefined };
  addEvent({ app: 'Prompt Lab', source: 'Prompt Lab', destination: data?.destination || 'manual', risk: result.riskScore, action, findings: result.findingCount, channel: 'dashboard' });
  return out;
  } catch (error) {
    throw new Error(`Prompt scan failed: ${error?.message || error}`);
  }
});
ipcMain.handle('toggle-autoproxy', async () => {
  if (process.platform !== 'win32') {
    proxyError = 'Protection switch is currently supported on Windows only.';
    broadcastStatus();
    return status();
  }

  const enabled = !!store.get('protectionEnabled', false);
  const op = ++protectionOp;

  if (!enabled) {
    // Do not mark protection ON until the local agent, CA and Windows proxy
    // have all been verified. The UI therefore never shows ON while the
    // browser is actually disconnected.
    store.set('protectionEnabled', true);
    store.set('autoProxy', true);
    bootstrapStatus = 'Enabling protection…';
    broadcastStatus();
    try {
      const ok = await configureWindowsProxy(op);
      if (op !== protectionOp) return status();
      if (!ok) {
        store.set('protectionEnabled', false);
        store.set('autoProxy', false);
        await restoreWindowsProxy(true);
        stopProxy();
        windowsProxyConfigured = false;
        bootstrapStatus = 'Protection OFF — normal Windows internet path restored.';
        broadcastStatus();
        throw new Error(proxyError || 'Protection could not be enabled safely.');
      }
      const finalStatus = status();
      if (!finalStatus.active) {
        store.set('protectionEnabled', false);
        store.set('autoProxy', false);
        await restoreWindowsProxy(true);
        stopProxy();
        bootstrapStatus = 'Protection OFF — verification did not complete; normal internet restored.';
        broadcastStatus();
        throw new Error(proxyError || 'Protection verification failed.');
      }
      bootstrapStatus = 'Protection ON — local proxy active and verified.';
      broadcastStatus();
      return status();
    } catch (error) {
      store.set('protectionEnabled', false);
      store.set('autoProxy', false);
      await restoreWindowsProxy(true);
      stopProxy();
      windowsProxyConfigured = false;
      proxyError = error?.message || String(error);
      bootstrapStatus = 'Protection OFF — normal Windows internet path restored.';
      broadcastStatus();
      throw new Error(proxyError);
    }
  }

  // OFF: restore Windows first. If restoration fails, do not kill the proxy;
  // otherwise Windows would be left pointing at a dead local port.
  bootstrapStatus = 'Turning protection OFF…';
  broadcastStatus();
  const ok = await restoreWindowsProxy(true);
  if (!ok) {
    proxyError = proxyError || 'Could not restore Windows networking. DeepGuard is keeping the proxy alive for safety.';
    broadcastStatus();
    return status();
  }
  store.set('protectionEnabled', false);
  store.set('autoProxy', false);
  stopProxy();
  proxyReady = false;
  windowsProxyConfigured = false;
  bootstrapStatus = 'Protection OFF — normal Windows internet path restored.';
  broadcastStatus();
  return status();
});
ipcMain.handle('repair-network', async () => {
  if (process.platform !== 'win32') return status();
  ++protectionOp;
  store.set('protectionEnabled', false);
  store.set('autoProxy', false);
  const current = await readWindowsInternetSettings();
  const saved = store.get('originalWindowsProxy');
  const target = saved && typeof saved === 'object' && !isDeepGuardOwnedWindowsSettings(saved)
    ? saved
    : (isDeepGuardOwnedWindowsSettings(current) ? directWindowsSettings(current?.AutoDetect ?? 1) : current || directWindowsSettings());
  const ok = await setWindowsUserProxy(false, target);
  stopProxy();
  windowsProxyConfigured = false;
  proxyReady = false;
  if (ok) {
    store.set('proxyOwner', false);
    store.delete('originalWindowsProxy');
    originalWindowsProxy = null;
    proxyError = '';
    bootstrapStatus = 'Network repaired — DeepGuard is OFF and normal Windows networking is restored.';
  } else {
    bootstrapStatus = 'Network repair could not verify Windows settings.';
  }
  broadcastStatus();
  return status();
});
ipcMain.handle('diagnostics', async () => {
  const startedAt = Date.now();
  try {
    if (!apiReady) await createServer();
    const enabled = !!store.get('protectionEnabled', store.get('autoProxy'));

    // Diagnostics must never silently enable protection. When OFF, only inspect
    // current Windows state and return immediately; do not start the Go agent or
    // run a slow certificate-store scan.
    if (!enabled) {
      const windowsProxyActual = await checkWindowsProxyActual();
      const result = {
        ...status(),
        proxyReachable: !!(proxyProcess && proxyReady),
        apiReachable: apiReady,
        configured: false,
        windowsProxyActual,
        caTrustedActual: false,
        tlsProbe: { ok: false, error: 'Protection is OFF.' },
        httpProbe: { ok: false, error: 'Protection is OFF.' },
        fullyVerified: !windowsProxyActual,
        durationMs: Date.now() - startedAt,
        proxyError: windowsProxyActual
          ? 'A Windows proxy is still active. Turn protection ON then OFF once to restore it.'
          : '',
        caPath: CA_CERT,
        pacUrl: ''
      };
      bootstrapStatus = windowsProxyActual
        ? 'Protection is OFF, but Windows still has an active proxy setting.'
        : 'Protection is OFF. Windows is using the normal network path.';
      broadcastStatus();
      return result;
    }

    // ON diagnostics may start/reuse the local agent, but every network check
    // has a bounded timeout so the UI cannot remain stuck on “Checking…”.
    const proxyStarted = await startProxy();
    let configured = false;
    if (proxyStarted) configured = await configureWindowsProxy();
    const proxyReachable = await waitForPort(PROXY_PORT, PROXY_HOST, 1500);
    const apiReachable = await waitForPort(API_PORT, PROXY_HOST, 1000);
    const [windowsProxyActual, caTrustedActual] = await Promise.all([
      checkWindowsProxyActual(),
      checkCaTrustActual()
    ]);
    const tlsProbe = proxyReachable ? await probeProxyTls(5000) : { ok: false, error: 'Proxy is not listening.' };
    const httpProbe = tlsProbe.ok ? await probeProxyHttp(7000) : { ok: false, error: 'TLS probe did not succeed.' };
    windowsProxyConfigured = windowsProxyActual;
    caTrusted = caTrustedActual;
    const fullyVerified = proxyReachable && apiReachable && windowsProxyActual && caTrustedActual && tlsProbe.ok && httpProbe.ok;
    const result = {
      ...status(), proxyReachable, apiReachable, configured, windowsProxyActual,
      caTrustedActual, tlsProbe, httpProbe, fullyVerified,
      durationMs: Date.now() - startedAt,
      proxyError: fullyVerified ? '' : (proxyError || httpProbe.error || tlsProbe.error || `Nothing is listening on 127.0.0.1:${PROXY_PORT}`),
      caPath: CA_CERT, pacUrl: ''
    };
    bootstrapStatus = fullyVerified
      ? 'Protection verified: local proxy + CA trust + HTTPS inspection are working.'
      : 'Protection is ON, but one or more network checks failed.';
    broadcastStatus();
    return result;
  } catch (error) {
    proxyError = error?.message || String(error);
    const result = { ...status(), fullyVerified: false, durationMs: Date.now() - startedAt, proxyError };
    broadcastStatus();
    return result;
  }
});

ipcMain.handle('open-chatgpt', () => shell.openExternal('https://chatgpt.com/'));
ipcMain.handle('open-claude', () => shell.openExternal('https://claude.ai/'));

let shutdownPromise = null;
async function shutdownDeepGuard() {
  shuttingDown = true;
  if (shutdownPromise) return shutdownPromise;
  shutdownPromise = (async () => {
    try {
      if (process.platform === 'win32') {
        await restoreWindowsProxy(false);
        await restoreBrowserQuicPolicy();
      }
    } finally {
      stopProxy();
      server?.close();
      store.set('proxyOwner', false);
    }
  })();
  return shutdownPromise;
}

app.whenReady().then(async () => {
  try {
    // Render the window immediately. Never make the UI wait for registry,
    // certificate, or proxy cleanup work.
    await createServer();
    createWindow();
    store.set('protectionEnabled', false);
    store.set('autoProxy', false);
    windowsProxyConfigured = false;
    bootstrapStatus = 'Protection is OFF — normal Windows internet path is active.';
    broadcastStatus();

    // Recover an old DeepGuard-owned proxy/PAC in the background. This keeps
    // startup responsive and guarantees a previous crashed session cannot
    // leave Windows stuck on the local proxy.
    recoverStaleProxy().then(() => {
      bootstrapStatus = 'Protection is OFF — normal Windows internet path is active. Use the switch to enable DeepGuard.';
      broadcastStatus();
    }).catch(error => {
      proxyError = error?.message || String(error);
      bootstrapStatus = 'Protection OFF, but previous network settings need attention.';
      broadcastStatus();
    });
  } catch (error) {
    proxyError = error?.message || String(error);
    bootstrapStatus = 'Protection startup failed.';
    createWindow();
    broadcastStatus();
  }
});
app.on('before-quit', async e => {
  if (shutdownPromise) return;
  e.preventDefault();
  await shutdownDeepGuard();
  app.exit(0);
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
