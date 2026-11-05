'use strict';
// All-in-one Helix connector. The downloaded Server Automation Connector zip is a Java
// process that heartbeats to Helix and polls /v1/workmanager for TSSA REST calls. This
// module does that work inside the mock: it logs in, heartbeats as the zip's worker,
// runs each request against the local TSSA API, and posts the result back. Job callbacks
// that a real connector receives on POST /forward are relayed to Automation Console.
// While the real connector is running this module stands by, so only one worker polls Helix.
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const store = require('./store');

// The newest "Server Automation Connector*.zip" in the Downloads folder.
function findDownloadedZip() {
  const dir = path.join(os.homedir(), 'Downloads');
  try {
    return fs.readdirSync(dir).filter((f) => /^Server Automation Connector.*\.zip$/i.test(f)).map((f) => path.join(dir, f))
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0] || null;
  } catch { return null; }
}
const HELIX_ENV_CANDIDATES = [
  process.env.MOCK_HELIX_ENV,
  path.join(__dirname, '..', 'data', 'helix.env'),
].filter(Boolean);

const state = {
  enabled: false,
  status: 'disabled',
  workerId: null,
  baseUrl: null,
  source: null,
  lastHeartbeat: null,
  lastPoll: null,
  lastError: null,
  heartbeats: 0,
  requests: 0,
  forwards: 0,
};

let timer = null;
let token = null;
let tokenAt = 0;
let busy = false;
let localRelay = null;
const answered = new Set();
const lastRequestByType = {};

function readZipEntry(zipPath, name) {
  const buf = fs.readFileSync(zipPath);
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (eocd < 0) throw new Error('not a zip file');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break;
    const nameLen = buf.readUInt16LE(p + 28);
    const extra = buf.readUInt16LE(p + 30);
    const comment = buf.readUInt16LE(p + 32);
    const comp = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const localOff = buf.readUInt32LE(p + 42);
    const fn = buf.slice(p + 46, p + 46 + nameLen).toString();
    if (fn === name) {
      const nlen = buf.readUInt16LE(localOff + 26);
      const ex = buf.readUInt16LE(localOff + 28);
      const start = localOff + 30 + nlen + ex;
      const data = buf.slice(start, start + compSize);
      return (comp === 8 ? zlib.inflateRawSync(data) : data).toString('utf8');
    }
    p += 46 + nameLen + extra + comment;
  }
  throw new Error(`zip has no ${name}`);
}

function parseProperties(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || t.startsWith('!')) continue;
    const i = t.indexOf('=');
    if (i > 0) out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return out;
}

function parseEnvFile(file) {
  const out = {};
  if (!file || !fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z0-9_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
  }
  return out;
}

function loadIdentity() {
  const zip = process.env.MOCK_CONNECTOR_ZIP || findDownloadedZip();
  if (!zip || !fs.existsSync(zip)) return null;
  const props = parseProperties(readZipEntry(zip, 'config/application.properties'));
  const creds = JSON.parse(readZipEntry(zip, 'config/creds.json'));
  const env = { ...parseEnvFile(HELIX_ENV_CANDIDATES.find((f) => fs.existsSync(f))), ...process.env };
  const base = (env.HAC_BASE_URL || creds.endpoints?.ifm || '').replace(/\/$/, '');
  return {
    zip,
    workerId: props.workerID || creds.user,
    baseUrl: base,
    zipKey: creds.accessKey ? { accessKey: creds.accessKey, secretKey: creds.secretKey, tenantId: creds.tenantId } : null,
    envKey: env.HAC_ACCESS_KEY && env.HAC_SECRET ? { accessKey: env.HAC_ACCESS_KEY, secretKey: env.HAC_SECRET, tenantId: creds.tenantId } : null,
    // The real connector's Forward sends creds.user (the worker id) as the "user" header.
    connectorUser: creds.user || props.workerID || null,
    connectorPort: Number(props['server.port']) || 443,
  };
}

// True when the real connector (the Java process from the downloaded zip) is listening. It polls
// Helix as this same worker, so running both makes them race for each request: Helix logs
// "duplicate workers running" and the loser's response is rejected.
function realConnectorUp(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port, timeout: 1000 });
    const done = (up) => { s.destroy(); resolve(up); };
    s.once('connect', () => done(true));
    s.once('timeout', () => done(false));
    s.once('error', () => done(false));
  });
}

function useRelay(url) {
  if (store.settings.connector_url === url) return;
  store.updateSettings({ connector_url: url });
  console.log(`Job callbacks now go to ${url}/forward`);
}

async function httpJson(method, url, headers, body) {
  const res = await fetch(url, {
    method,
    headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  return { status: res.status, text, json, headers: Object.fromEntries(res.headers.entries()) };
}

async function login(id) {
  const keys = [id.zipKey, id.envKey].filter(Boolean);
  let last = 'no access key';
  for (const key of keys) {
    const r = await httpJson('POST', `${id.baseUrl}/ims/api/v1/access_keys/login`, {}, {
      access_key: key.accessKey, access_secret_key: key.secretKey, tenant_id: key.tenantId,
    });
    const jwt = r.json?.json_web_token || r.json?.token;
    if (r.status === 200 && jwt) {
      token = jwt;
      tokenAt = Date.now();
      state.source = key === id.zipKey ? 'connector zip' : 'Helix access key';
      return true;
    }
    last = `login HTTP ${r.status}`;
  }
  state.lastError = last;
  return false;
}

function authHeaders(id) {
  return { Authorization: `Bearer ${token}`, user: id.workerId };
}

async function ensureToken(id) {
  if (token && Date.now() - tokenAt < 8 * 60 * 1000) return true;
  return login(id);
}

async function heartbeat(id) {
  const r = await httpJson('POST', `${id.baseUrl}/v1/connectorservice/connectors/heartbeat`, authHeaders(id), { hostName: os.hostname() });
  if (r.status === 401) { token = null; return; }
  if (r.status !== 200) {
    state.status = 'error';
    state.lastError = `heartbeat HTTP ${r.status}`;
    return;
  }
  state.status = r.json?.isEnabled === false ? 'disabled-by-helix' : 'connected';
  state.lastHeartbeat = new Date().toISOString();
  state.lastError = null;
  state.heartbeats += 1;
}

async function executeOne(rest, item) {
  const header = item.header || {};
  let payload;
  try {
    const raw = item.payload || '';
    const text = /^[\w+/=]+$/.test(raw) && raw.length > 20 ? Buffer.from(raw, 'base64').toString('utf8') : raw;
    payload = JSON.parse(text);
  } catch (e) {
    return responseFor(item, 400, `payload: ${e.message}`);
  }
  const content = typeof payload.content === 'string' ? safeJson(payload.content) : (payload.content || payload);
  const method = String(content.httpMethod?.name || content.httpMethod || 'GET').toUpperCase();
  const target = content.url || content.path || '/';
  let session = content.sessionID || content.sessionId;
  if (!session) session = store.login(store.settings.users.BLAdmin ? 'BLAdmin' : 'BLAdmin', null, content.role || 'BLAdmins').session?.id;
  const bodyText = content.content == null ? '' : (typeof content.content === 'string' ? content.content : JSON.stringify(content.content));
  const u = new URL(target, 'https://tssa.local');
  const out = (await rest.handle({
    method,
    path: decodeURIComponent(u.pathname),
    query: Object.fromEntries(u.searchParams),
    headers: { 'session-id': session || '', role: content.role || 'BLAdmins', 'content-type': content.contentTypeHeader || 'application/json' },
    raw: bodyText,
    body: safeJson(bodyText) || {},
  })) || { status: 404, body: { message: `No mock implementation for ${method} ${u.pathname}` } };
  const message = out.text !== undefined ? String(out.text) : JSON.stringify(out.body ?? {});
  const code = out.status >= 200 && out.status < 400 ? 0 : out.status;
  state.requests += 1;
  console.log(`Helix work ${method} ${u.pathname} -> ${out.status} part=${header.partNumber || 1}/${header.numberOfParts || 1} requestID=${header.requestID || header.requestId || ''}`);
  return responseFor(item, code, message, out.status);
}

function safeJson(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function responseFor(item, code, message, httpStatus = code) {
  const header = item?.header || item || {};
  const requestID = header.requestID || header.requestId || item?.requestID || item?.requestId;
  const transactionID = header.transactionID || header.transactionId || item?.transactionID || requestID;
  if (!requestID) console.log(`Helix work item keys=${Object.keys(item || {}).join(',')} header keys=${Object.keys(header).join(',')}`);
  const workStatus = code === 0 ? 'success' : 'failure';
  // response and responseCode are what BSARestResult carries back to HAC.
  const plugin = { requestID, returnCode: code, status: workStatus, message, response: message, responseCode: httpStatus };
  // WorkManagerResponseHeader: requestID plus the response fields. The post URL also
  // requires requestID, requestType and txID as query parameters.
  return {
    requestID,
    transactionID,
    header: {
      version: header.version || '1.0',
      workerID: header.workerID || header.workerId || state.workerId,
      requestID,
      transactionID,
      priority: header.priority ?? 0,
      timestamp: Date.now(),
      partNumber: header.partNumber || 1,
      numberOfParts: header.numberOfParts || 1,
      requester: header.requester || 'mock-tssa',
      responseID: requestID,
      status: workStatus,
      responseCode: code,
      processingTime: 0,
      isRecoverable: code !== 0,
    },
    payload: Buffer.from(JSON.stringify(plugin)).toString('base64'),
  };
}

async function poll(id, rest) {
  for (const requestType of ['priority', 'normal']) {
    const q = new URLSearchParams({ requestType, batchSize: '10' });
    if (lastRequestByType[requestType]) q.set('lastRequestID', lastRequestByType[requestType]);
    const url = `${id.baseUrl}/v1/workmanager/workers/${encodeURIComponent(id.workerId)}/requests?${q}`;
    const r = await httpJson('GET', url, authHeaders(id));
    if (r.status === 401) { token = null; return; }
    if (r.status !== 200 || !Array.isArray(r.json)) {
      if (r.status !== 200) state.lastError = `poll HTTP ${r.status}`;
      continue;
    }
    state.lastPoll = new Date().toISOString();
    for (const item of r.json) {
      const seen = item?.header?.requestID || item?.header?.requestId || item?.requestID;
      if (seen && answered.has(seen)) continue;
      const response = await executeOne(rest, item);
      if (response.requestID) {
        answered.add(response.requestID);
        if (answered.size > 500) answered.delete(answered.values().next().value);
        lastRequestByType[requestType] = response.requestID;
      }
      const q = new URLSearchParams({
        requestID: response.requestID || '',
        requestType,
        txID: response.transactionID || '',
      });
      const post = await httpJson('POST', `${id.baseUrl}/v1/workmanager/workers/${encodeURIComponent(id.workerId)}/responses?${q}`, authHeaders(id), { header: response.header, payload: response.payload });
      const posted = `${post.status} ${(post.text || '').replace(/\s+/g, ' ').slice(0, 240)}`;
      if (post.status >= 300 || (post.json && post.json.status && post.json.status !== 'success')) {
        state.lastError = `response HTTP ${post.status}`;
        console.log(`Helix work response -> ${posted}`);
      } else {
        console.log(`Helix work response -> ${posted} requestID=${response.requestID}`);
      }
    }
  }
}

async function cycle(id, rest) {
  if (busy) return;
  busy = true;
  try {
    const realUp = await realConnectorUp(id.connectorPort);
    useRelay(realUp ? `https://127.0.0.1:${id.connectorPort}` : localRelay);
    if (realUp) { state.status = 'standby'; return; }
    if (!(await ensureToken(id))) { state.status = 'login-failed'; return; }
    await heartbeat(id);
    await poll(id, rest);
  } catch (e) {
    state.status = 'error';
    state.lastError = e.message;
    console.error('Helix connector:', e.message);
  } finally {
    busy = false;
  }
}

function start({ rest, httpPort }) {
  const id = loadIdentity();
  if (!id || !id.workerId || !id.baseUrl) {
    console.log('Helix connector disabled (no connector zip or Helix URL). Set MOCK_CONNECTOR_ZIP to the downloaded connector.');
    return;
  }
  state.enabled = true;
  state.workerId = id.workerId;
  state.connectorUser = id.connectorUser;
  state.baseUrl = id.baseUrl;
  state.status = 'starting';
  localRelay = `http://127.0.0.1:${httpPort}`;
  console.log(`Helix connector worker ${id.workerId} -> ${id.baseUrl} (TSSA calls stay local)`);
  cycle(id, rest).then(() => {
    if (state.status === 'connected') console.log(`Helix connector connected (${state.source})`);
    else if (state.status === 'standby') console.log(`Helix connector on standby: the real connector is running on port ${id.connectorPort}`);
    else console.log(`Helix connector ${state.status}${state.lastError ? `: ${state.lastError}` : ''}`);
  });
  timer = setInterval(() => cycle(id, rest), 30000);
  timer.unref();
}

// The connector's POST /forward. Helix puts this URL on a job; the mock receives it and relays the body.
async function forward(req) {
  if (req.path !== '/forward' || req.method !== 'POST') return null;
  const id = { baseUrl: state.baseUrl, workerId: state.workerId, zipKey: null, envKey: null };
  const loaded = state.enabled ? null : loadIdentity();
  const base = state.baseUrl || loaded?.baseUrl;
  if (!base) return { status: 503, body: { error: 'Helix connector is not configured' } };
  if (!token) {
    const who = loaded || loadIdentity();
    if (who) await login(who);
  }
  let relay = req.query.url || '/';
  try { relay = decodeURIComponent(relay); } catch { /* already decoded */ }
  if (!relay.startsWith('/')) relay = `/${relay}`;
  const dest = relay.startsWith('/automation-console') ? `${base}${relay}` : `${base}/automation-console${relay}`;
  state.forwards += 1;
  if (!token) return { status: 502, body: { error: state.lastError || 'not logged in to Helix' }, note: 'forward' };
  const headers = { Authorization: `Bearer ${token}`, 'site-type': 'TSSA' };
  if (state.connectorUser) headers.user = state.connectorUser;
  const r = await httpJson('POST', dest, headers, req.body || {});
  const safeHeaders = Object.fromEntries(Object.entries(r.headers || {}).filter(([k]) => !/cookie|auth|token/i.test(k)));
  const detail = r.status >= 300 ? ` ${(r.text || '').replace(/\s+/g, ' ').slice(0, 300)} headers=${JSON.stringify(safeHeaders)}` : '';
  console.log(`Forward ${relay} -> ${r.status}${detail}`);
  return { status: r.status || 502, body: r.json ?? { forwarded: true, upstream: r.text?.slice(0, 500) }, note: 'forward' };
}

function status() {
  return {
    enabled: state.enabled, status: state.status, workerId: state.workerId, source: state.source,
    lastHeartbeat: state.lastHeartbeat, lastPoll: state.lastPoll, lastError: state.lastError,
    heartbeats: state.heartbeats, requests: state.requests, forwards: state.forwards,
  };
}

module.exports = { start, forward, status };
