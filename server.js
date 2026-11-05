#!/usr/bin/env node
'use strict';
// Mock TrueSight Server Automation application server.
//   HTTPS  :9843  REST API (/rest/api/v1|v2), BLCLI SOAP (/services/*), web console (/)
//   HTTP   :9842  same content, for local browsing/testing (set MOCK_HTTP_PORT=0 to disable)
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const { execFileSync, spawn } = require('child_process');

const store = require('./lib/store');
const engine = require('./lib/engine');
const rest = require('./lib/rest');
const soap = require('./lib/soap');
const notify = require('./lib/notify');
const helix = require('./lib/helix-connector');
const { iso } = require('./lib/util');

const HTTPS_PORT = Number(process.env.MOCK_HTTPS_PORT || 9843);
const HTTP_PORT = Number(process.env.MOCK_HTTP_PORT ?? 9842);
const BIND = process.env.MOCK_BIND || '0.0.0.0';
const CERT_DIR = path.join(__dirname, 'certs');
const PUBLIC_DIR = path.join(__dirname, 'public');
const INSPECTOR_MAX = 1000;
// Cloudflare Tunnel: 'cloudflare' (default) starts one on boot, 'off' disables it.
// With MOCK_TUNNEL_TOKEN set, a named tunnel (fixed hostname) is used instead of a quick tunnel.
const TUNNEL = (process.env.MOCK_TUNNEL || 'cloudflare').toLowerCase();
const TUNNEL_TOKEN = process.env.MOCK_TUNNEL_TOKEN || '';
const TUNNEL_HOSTNAME = process.env.MOCK_TUNNEL_HOSTNAME || '';
const tunnel = { pid: null, provider: null, mode: null, url: null, host: null, port: 443, status: 'disabled', error: null, started: null };

store.init({ reset: process.argv.includes('--reset') });
if (store.seeded) seedHistory();
notify.init();

// --- request inspector -----------------------------------------------------
const inspector = [];
let inspectorSeq = 0;

function redact(obj) {
  if (typeof obj === 'string') {
    return obj
      .replace(/("password"\s*:\s*")[^"]*"/gi, '$1***"')
      .replace(/(<(?:\w+:)?password>)[\s\S]*?(<\/(?:\w+:)?password>)/gi, '$1***$2');
  }
  return obj;
}

function record(req, res, out, ms) {
  if (req.headers['x-mock-ui']) return;
  const headers = { ...req.headers };
  if (headers.authorization) headers.authorization = headers.authorization.replace(/\s.+$/, ' ***');
  const respText = out.text ?? (out.body !== undefined ? JSON.stringify(out.body) : '');
  const entry = {
    id: ++inspectorSeq, time: iso(Date.now()), client: req.headers['cf-connecting-ip'] ? `${req.headers['cf-connecting-ip']} (via Cloudflare)` : req.socket.remoteAddress, scheme: req.socket.encrypted ? 'https' : 'http',
    method: req.method, path: req.path, query: req.query, status: out.status, ms, matched: out.matched !== false,
    note: out.note || out.route || null, headers, body: redact(String(req.raw || '').slice(0, 8000)), response: respText.slice(0, 8000),
  };
  inspector.push(entry);
  if (inspector.length > INSPECTOR_MAX) inspector.shift();
  const flag = entry.matched ? '' : '  <-- NOT IMPLEMENTED (see Inspector)';
  console.log(`${entry.time} ${entry.client} ${req.method} ${req.url} -> ${out.status} (${ms} ms)${out.note ? ` [${out.note}]` : ''}${flag}`);
}

// --- mock control API (used by the web console) ------------------------------
let uiSession = null;
function mockApi(req) {
  if (!req.path.startsWith('/mock/')) return null;
  const p = req.path.slice(6);
  if (p === 'ui-session') {
    if (!store.getSession(uiSession)) uiSession = store.login('BLAdmin', store.settings.users.BLAdmin?.password, 'BLAdmins').session?.id;
    return { status: 200, body: { session_id: uiSession } };
  }
  if (p === 'settings' && req.method === 'GET') return { status: 200, body: store.settings };
  if (p === 'settings' && (req.method === 'PUT' || req.method === 'POST')) { store.updateSettings(req.body || {}); return { status: 200, body: store.settings }; }
  if (p === 'inspector' && req.method === 'GET') {
    const after = Number(req.query.after || 0);
    return { status: 200, body: { entries: inspector.filter((e) => e.id > after) } };
  }
  if (p === 'inspector' && req.method === 'DELETE') { inspector.length = 0; return { status: 200, body: { cleared: true } }; }
  if (p === 'callbacks' && req.method === 'GET') return { status: 200, body: { entries: notify.log, connector_url: store.settings.connector_url } };
  if (p === 'callbacks' && req.method === 'DELETE') { notify.log.length = 0; return { status: 200, body: { cleared: true } }; }
  let m = p.match(/^callbacks\/(\d+)\/resend$/);
  if (m && req.method === 'POST') {
    const e = notify.resend(m[1]);
    return e ? { status: 200, body: e } : { status: 404, body: { error: 'callback or its job run not found' } };
  }
  // Runs a catalog update now; when it finishes, its notification goes to the HAC schedule's callback URL.
  m = p.match(/^catalogs\/(\d+)\/update$/);
  if (m && req.method === 'POST') {
    const c = store.catalog(m[1]);
    if (!c) return { status: 404, body: { error: 'catalog not found' } };
    const run = engine.catalogUpdate(c, {});
    const job = store.job(run.job_id);
    return { status: 200, body: { run_id: run.id, end_time: iso(run.end_time), callbacks: notify.targetsFor(run).map((n) => n.url), job: job.name } };
  }
  if (p === 'compliance-reset' && req.method === 'POST') {
    for (const s of store.state.servers) delete s.compliance_fixed;
    store.saveSoon();
    return { status: 200, body: { reset: true } };
  }
  if (p === 'reset' && req.method === 'POST') { store.reset(); seedHistory(); return { status: 200, body: { reset: true } }; }
  if (p === 'routes') return { status: 200, body: { rest: rest.listRoutes(), blcli: soap.listCommands() } };
  if (p === 'sessions') return { status: 200, body: { sessions: [...store.sessions.values()].map((s) => ({ user: s.user, role: s.role, created: iso(s.created), expires: iso(s.expires), id: `${s.id.slice(0, 8)}...` })) } };
  if (p === 'info') return { status: 200, body: { tunnel, helix: helix.status(), https_port: HTTPS_PORT, http_port: HTTP_PORT, hostnames: certHosts(), cert_file: fs.existsSync(path.join(CERT_DIR, 'mock-tssa.crt')) ? path.join(CERT_DIR, 'mock-tssa.crt') : null, version: store.settings.tssa_version } };
  return { status: 404, body: { error: 'unknown mock endpoint' } };
}

// --- static web console -------------------------------------------------------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json' };
function staticFile(req) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return null;
  if (req.path === '/favicon.ico') return { status: 204, text: '', matched: true, quiet: true };
  let p = req.path === '/' ? '/index.html' : req.path;
  if (p === '/rest/apidocs' || p === '/rest/apidocs/') return { status: 200, type: 'text/html; charset=utf-8', text: apidocs(), matched: true };
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return null;
  return { status: 200, type: MIME[path.extname(file)] || 'application/octet-stream', text: fs.readFileSync(file), matched: true, quiet: true, headers: { 'Cache-Control': 'no-store' } };
}

function apidocs() {
  const r = rest.listRoutes().map((x) => `<li><code>${x}</code></li>`).join('');
  const b = soap.listCommands().map((x) => `<li><code>${x.replace('.', ' ')}</code></li>`).join('');
  return `<!doctype html><meta charset="utf-8"><title>Mock TSSA API</title><body style="font-family:system-ui;max-width:900px;margin:2em auto;padding:0 16px">
<h1>Mock TSSA REST API</h1><p>Authenticate with <code>POST /rest/api/v1/sessions</code> and send the returned <code>session_id</code> in a <code>session-id</code> header.</p><ul>${r}</ul>
<h2>BLCLI commands (SOAP /services/CLITunnelService)</h2><ul>${b}</ul></body>`;
}

// --- request pipeline -----------------------------------------------------------
async function onRequest(req, res) {
  const t0 = Date.now();
  const url = new URL(req.url, 'http://x');
  req.path = decodeURIComponent(url.pathname).replace(/\/{2,}/g, '/');
  req.query = Object.fromEntries(url.searchParams);
  const chunks = [];
  for await (const c of req) chunks.push(c);
  req.raw = Buffer.concat(chunks).toString('utf8');
  req.body = parseBody(req);

  let out;
  try {
    out = (await helix.forward(req)) || mockApi(req) || (await rest.handle(req)) || soap.handle(req) || staticFile(req);
  } catch (e) {
    console.error(e);
    out = { status: 500, body: rest.errBody(500, e.message, req.path) };
  }
  if (!out) out = { status: 404, body: rest.errBody(404, `No mock implementation for ${req.method} ${req.path}`, req.path), matched: false };

  const headers = { 'X-Mock-TSSA': store.settings.tssa_version, ...(out.headers || {}) };
  let payload;
  if (out.text !== undefined) { payload = out.text; headers['Content-Type'] = out.type || 'text/plain; charset=utf-8'; }
  else { payload = JSON.stringify(out.body ?? {}, null, req.query.pretty ? 2 : 0); headers['Content-Type'] = 'application/json'; }
  res.writeHead(out.status, headers);
  res.end(payload);
  if (!req.path.startsWith('/mock/') && !out.quiet) record(req, res, out, Date.now() - t0);
}

function parseBody(req) {
  const raw = req.raw;
  if (!raw) return {};
  const ct = req.headers['content-type'] || '';
  if (ct.includes('json') || /^\s*[[{]/.test(raw)) { try { return JSON.parse(raw); } catch { return {}; } }
  if (ct.includes('x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(raw));
  return {};
}

// --- TLS -------------------------------------------------------------------------
function certHosts() {
  const names = new Set(['localhost', os.hostname(), os.hostname().toLowerCase()]);
  (process.env.MOCK_HOSTNAMES || '').split(',').map((s) => s.trim()).filter(Boolean).forEach((h) => names.add(h));
  const ips = new Set(['127.0.0.1']);
  for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) if (i.family === 'IPv4') ips.add(i.address);
  return { dns: [...names], ip: [...ips] };
}

function findOpenssl() {
  const candidates = ['openssl', 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe', 'C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe', 'C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe'];
  for (const c of candidates) {
    try { execFileSync(c, ['version'], { stdio: 'ignore' }); return c; } catch { /* try next */ }
  }
  return null;
}

function loadTls() {
  const cert = process.env.MOCK_CERT || path.join(CERT_DIR, 'mock-tssa.crt');
  const key = process.env.MOCK_KEY || path.join(CERT_DIR, 'mock-tssa.key');
  if (!fs.existsSync(cert) || !fs.existsSync(key)) {
    const ssl = findOpenssl();
    if (!ssl) {
      console.warn('WARNING: no certificate found and openssl is not available; HTTPS disabled. Provide MOCK_CERT/MOCK_KEY or install openssl.');
      return null;
    }
    fs.mkdirSync(CERT_DIR, { recursive: true });
    const { dns, ip } = certHosts();
    const san = [...dns.map((d) => `DNS:${d}`), ...ip.map((i) => `IP:${i}`)].join(',');
    const cn = (process.env.MOCK_HOSTNAMES || os.hostname()).split(',')[0].trim();
    execFileSync(ssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '825',
      '-keyout', key, '-out', cert, '-subj', `/CN=${cn}/O=Mock TSSA/OU=Lab`, '-addext', `subjectAltName=${san}`], { stdio: 'ignore' });
    console.log(`Generated self-signed certificate ${cert} (SAN: ${san})`);
  }
  return { cert: fs.readFileSync(cert), key: fs.readFileSync(key) };
}

// --- history ---------------------------------------------------------------------
function seedHistory() {
  const day = 86400000;
  const now = Date.now();
  const byName = (n) => store.state.jobs.find((j) => j.name === n);
  const plan = [
    ['Windows - Monthly Patch Analysis', 9], ['RHEL 9 - Patch Analysis', 8], ['RHEL 8 - Patch Analysis', 8],
    ['Oracle Linux 8 - Patch Analysis', 7], ['Ubuntu 22.04 - Patch Analysis', 7], ['SLES 15 - Patch Analysis', 6],
    ['Get Disk Usage - Linux', 5], ['CIS Windows Server 2022 Compliance', 4], ['CIS RHEL 9 Compliance', 4],
    ['Deploy SSH Hardening', 3], ['Config Snapshot - Linux', 2], ['Pre-Patch Health Check - All', 1.5],
    ['Windows - Monthly Patch Analysis', 1], ['RHEL 9 - Patch Analysis', 0.5],
  ];
  for (const [n, d] of plan) {
    const j = byName(n);
    if (j) engine.startRun(j, { startAt: now - d * day });
  }
  for (const c of store.state.catalogs) engine.catalogUpdate(c, { startAt: now - (1 + (c.id % 4)) * day });
  store.save();
}

// --- Cloudflare tunnel -------------------------------------------------------------
// cloudflared runs detached and logs to data/cloudflared.log; its pid and URL are kept in
// data/tunnel.json so a restarted mock re-adopts the same tunnel (and quick-tunnel URL).
// `node server.js --stop-tunnel` stops it.
const TUNNEL_STATE = path.join(__dirname, 'data', 'tunnel.json');
const TUNNEL_LOG = path.join(__dirname, 'data', 'cloudflared.log');
let tunnelWatch = null;

function findCloudflared() {
  const exe = process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared';
  const candidates = [process.env.MOCK_CLOUDFLARED, path.join(__dirname, 'bin', exe), 'cloudflared',
    'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe', 'C:\\Program Files\\cloudflared\\cloudflared.exe'].filter(Boolean);
  for (const c of candidates) {
    try { execFileSync(c, ['--version'], { stdio: 'ignore' }); return c; } catch { /* try next */ }
  }
  return null;
}

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
const readTunnelState = () => { try { return JSON.parse(fs.readFileSync(TUNNEL_STATE, 'utf8')); } catch { return null; } };

// True only when pid is a live cloudflared started by this mock (guards against pid reuse and
// against touching other cloudflared tunnels on the machine).
function isOurTunnel(st) {
  if (!st?.pid || !alive(st.pid)) return false;
  let cmd = '';
  try {
    cmd = process.platform === 'win32'
      ? execFileSync('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(st.pid)}").CommandLine`], { encoding: 'utf8', windowsHide: true })
      : fs.readFileSync(`/proc/${Number(st.pid)}/cmdline`, 'utf8').replace(/\0/g, ' ');
  } catch { return false; }
  return /cloudflared/i.test(cmd) && (st.mode === 'named' ? /--token/.test(cmd) : cmd.includes(`--url ${st.target}`));
}

function stopTunnel() {
  const st = readTunnelState();
  if (isOurTunnel(st)) { try { process.kill(st.pid); } catch { /* already gone */ } }
  try { fs.unlinkSync(TUNNEL_STATE); } catch { /* none */ }
  return st;
}

// Reads the cloudflared log for the public URL and connection state.
function scanTunnelLog(target, named) {
  let text = '';
  try { text = fs.readFileSync(TUNNEL_LOG, 'utf8'); } catch { return; }
  const m = text.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
  if (m && !named && tunnel.url !== m[0]) {
    tunnel.url = m[0];
    tunnel.host = new URL(m[0]).hostname;
    console.log(`Cloudflare quick tunnel: ${tunnel.url}  ->  ${target}`);
    console.log(`  HAC connector: Host Name = ${tunnel.host}, Application Port = 443`);
  }
  if (/Registered tunnel connection/i.test(text) && tunnel.status !== 'connected') {
    tunnel.status = 'connected';
    console.log(`Cloudflare tunnel connected${tunnel.url ? ` (${tunnel.url})` : ''}`);
  }
  const errs = text.split('\n').filter((l) => /\bERR\b/.test(l));
  tunnel.error = errs.length ? errs[errs.length - 1].slice(0, 300) : null;
  if (tunnel.pid) fs.writeFileSync(TUNNEL_STATE, JSON.stringify({ pid: tunnel.pid, url: tunnel.url, host: tunnel.host, target, mode: tunnel.mode, started: tunnel.started }));
}

function startTunnel(target) {
  if (['off', 'none', 'false', '0'].includes(TUNNEL)) return;
  tunnel.provider = 'cloudflare';
  const named = !!TUNNEL_TOKEN;
  tunnel.mode = named ? 'named' : 'quick';
  clearInterval(tunnelWatch);

  const prev = readTunnelState();
  if (prev && prev.target === target && prev.mode === tunnel.mode && isOurTunnel(prev)) {
    Object.assign(tunnel, { pid: prev.pid, url: prev.url, host: prev.host, started: prev.started, status: 'connected', error: null });
    console.log(`Re-using running Cloudflare tunnel (pid ${prev.pid}): ${tunnel.url}`);
  } else {
    stopTunnel();
    const bin = findCloudflared();
    if (!bin) {
      tunnel.status = 'error';
      tunnel.error = 'cloudflared not found. Put it in bin/, on PATH, or set MOCK_CLOUDFLARED.';
      console.warn(`WARNING: ${tunnel.error}`);
      return;
    }
    Object.assign(tunnel, { status: 'starting', error: null, started: iso(Date.now()),
      host: named ? TUNNEL_HOSTNAME || null : null, url: named && TUNNEL_HOSTNAME ? `https://${TUNNEL_HOSTNAME}` : null });
    const args = named
      ? ['tunnel', '--no-autoupdate', 'run', '--token', TUNNEL_TOKEN]
      : ['tunnel', '--no-autoupdate', '--no-tls-verify', '--url', target];
    fs.mkdirSync(path.dirname(TUNNEL_LOG), { recursive: true });
    const fd = fs.openSync(TUNNEL_LOG, 'w');
    const child = spawn(bin, args, { detached: true, stdio: ['ignore', fd, fd], windowsHide: true });
    child.unref();
    fs.closeSync(fd);
    tunnel.pid = child.pid;
  }

  tunnelWatch = setInterval(() => {
    if (!alive(tunnel.pid)) {
      clearInterval(tunnelWatch);
      tunnel.status = 'restarting';
      console.warn(`Cloudflare tunnel (pid ${tunnel.pid}) stopped; restarting${named ? '' : ' (quick tunnel URL will change)'}`);
      try { fs.unlinkSync(TUNNEL_STATE); } catch { /* none */ }
      setTimeout(() => startTunnel(target), 3000);
      return;
    }
    scanTunnelLog(target, named);
  }, 1000);
  tunnelWatch.unref();
  scanTunnelLog(target, named);
}

function shutdown() {
  // The tunnel is left running on purpose so the next start keeps the same URL.
  store.save();
  process.exit(0);
}

// --- start ---------------------------------------------------------------------
if (process.argv.includes('--stop-tunnel')) {
  const st = stopTunnel();
  console.log(st ? `Stopped Cloudflare tunnel pid ${st.pid} (${st.url})` : 'No tunnel running');
  process.exit(0);
}
setInterval(() => engine.tick(), 1000).unref();
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

const tls = loadTls();
if (tls) {
  https.createServer(tls, onRequest).listen(HTTPS_PORT, BIND, () => console.log(`Mock TSSA HTTPS listening on https://${os.hostname()}:${HTTPS_PORT}  (REST: /rest/api/v1, BLCLI SOAP: /services/*, console: /)`));
}
startTunnel(tls ? `https://localhost:${HTTPS_PORT}` : `http://localhost:${HTTP_PORT}`);
if (HTTP_PORT) {
  http.createServer(onRequest).listen(HTTP_PORT, BIND, () => console.log(`Mock TSSA HTTP  listening on http://localhost:${HTTP_PORT}   (web console)`));
}
console.log(`TSSA version ${store.settings.tssa_version}; ${store.state.servers.length} servers, ${store.state.catalogs.length} patch catalogs, ${store.state.jobs.length} jobs, ${store.state.runs.length} job runs. strict_auth=${store.settings.strict_auth}`);
helix.start({ rest, httpPort: HTTP_PORT });
