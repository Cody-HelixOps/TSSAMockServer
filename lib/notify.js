'use strict';
// Outbound job notifications, as a real TSSA app server sends them. HAC puts a callback URL in
// catalog schedules (and jobs) under notifications.notification_url; when the job runs, TSSA POSTs
// its progress there. The URL host is tssa.connector.bmc.com (newer docs: tssa.connector.helixops.ai),
// which a real TSSA server maps to the connector's IP in its hosts file. The mock instead rewrites
// that host to settings.connector_url, so no hosts-file entry is needed.
const http = require('http');
const https = require('https');
const store = require('./store');
const { iso } = require('./util');

const LOG_MAX = 200;
const log = [];   // newest last: { id, time, event, run_id, job_id, url, sent_to, payload, attempts, status, response, error }
let seq = 0;

// The connector's Forward endpoint reads jobId and progressStatus (RUNNING | COMPLETE | FAILED).
function progressStatus(runStatus) {
  if (runStatus === 'RUNNING' || runStatus === 'NOT_STARTED') return 'RUNNING';
  if (runStatus === 'COMPLETED' || runStatus === 'COMPLETED_WITH_WARNINGS') return 'COMPLETE';
  return 'FAILED';
}

// Callback targets for a run: catalog update jobs use the catalog's schedules. A job execute
// carries its own callback (the policy operation waiting on this run). Otherwise use the URL
// stored when the job was created.
function targetsFor(run) {
  if (run.parent_run_id) return [];
  const job = store.job(run.job_id);
  if (!job) return [];
  const list = job.type === 'CATALOG_UPDATE_JOB'
    ? (store.catalog(job.params.catalog_id)?.schedules || []).map((s) => s?.notifications?.notification_url)
    : [run.notifications?.notification_url || job.notifications?.notification_url];
  const seen = new Set();
  return list.filter((n) => n?.url && !seen.has(n.url) && seen.add(n.url));
}

// HAC /api/v2/policies/notify expects the array a real TSSA app server posts:
// [{jobRunId, jobId, scheduleId, executedByRole, executedByUser, startTime, endTime, reset, cancelled, ...}]
function policyNotifyPayload(run, statusName) {
  const done = statusName !== 'RUNNING' && statusName !== 'NOT_STARTED';
  const job = store.job(run.job_id);
  // The same id execute and GET jobruns report as schedule_id (see scheduleIdOf in rest.js).
  const scheduleId = run.schedule_id || run.id;
  const progress = progressStatus(statusName);
  // Real TSSA posts an array. Each element keeps the text fields policy service reads
  // with get(field).asText(), including while the run is still going.
  return [{
    jobRunId: run.id,
    jobId: run.job_id,
    scheduleId,
    name: run.job_name || '',
    jobName: run.job_name || '',
    jobType: run.job_type || '',
    executedByRole: { id: 1000010, name: run.role || 'BLAdmins' },
    executedByUser: { id: 2000100, name: run.executed_by || 'BLAdmin' },
    startTime: iso(run.start_time),
    endTime: iso(done ? (run.aborted_at || run.end_time) : run.start_time),
    reset: false,
    cancelled: statusName === 'ABORTED' || statusName === 'CANCELLED',
    progressStatus: progress === 'FAILED' && statusName === 'COMPLETED_WITH_ERRORS' ? 'COMPLETE' : progress,
    status: statusName,
    message: '',
    hadErrors: statusName === 'FAILED' || statusName === 'COMPLETED_WITH_ERRORS',
    hadWarnings: statusName === 'COMPLETED_WITH_WARNINGS',
  }];
}

function callbackPath(url) {
  let s = String(url || '');
  try { s = decodeURIComponent(s); } catch { /* already decoded */ }
  return s;
}

function payloadFor(run, statusName, url = '') {
  // The callback URL is percent-encoded (.../forward?url=%2Fapi%2Fv2%2Fpolicies%2Fnotify...),
  // so the path is not visible until it is decoded.
  if (/policies\/notify/i.test(callbackPath(url))) return policyNotifyPayload(run, statusName);
  const job = store.job(run.job_id);
  const catalogId = job?.type === 'CATALOG_UPDATE_JOB' ? job.params.catalog_id : null;
  return {
    jobId: run.job_id,
    jobRunId: run.id,
    jobName: run.job_name,
    jobType: run.job_type,
    progressStatus: progressStatus(statusName),
    status: statusName,
    ...(catalogId ? { catalogId } : {}),
    startTime: iso(run.start_time),
    ...(statusName !== 'RUNNING' ? { endTime: iso(run.aborted_at || run.end_time) } : {}),
    ...(store.settings.notify_extra || {}),
  };
}

// tssa.connector.* -> settings.connector_url (scheme, host and port); path and query are kept.
function resolveUrl(url) {
  const u = new URL(url);
  const base = store.settings.connector_url;
  if (base && /^tssa\.connector\./i.test(u.hostname)) {
    const b = new URL(base);
    u.protocol = b.protocol; u.hostname = b.hostname; u.port = b.port;
  }
  return u;
}

function post(u, body, timeoutMs) {
  return new Promise((resolve) => {
    const data = JSON.stringify(body);
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.request(u, {
      method: 'POST', rejectUnauthorized: false, timeout: timeoutMs,   // the connector uses a self-signed certificate
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let text = '';
      res.on('data', (c) => { if (text.length < 4000) text += c; });
      res.on('end', () => resolve({ status: res.statusCode, response: text }));
    });
    req.on('timeout', () => req.destroy(new Error(`timed out after ${timeoutMs} ms`)));
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.end(data);
  });
}

// Sends one notification, retrying as the notification_url asks (retry_count, retry_pause s, retry_timeout s).
async function deliver(entry, n) {
  const retries = Math.min(Math.max(Number(n.retry_count ?? 3), 0), 10);
  const pauseMs = Math.max(Number(n.retry_pause ?? 20), 1) * 1000;
  const deadline = Date.now() + Math.max(Number(n.retry_timeout ?? 300), 5) * 1000;
  for (let attempt = 1; ; attempt++) {
    const r = await post(new URL(entry.sent_to), entry.payload, 30000);
    Object.assign(entry, { attempts: attempt, status: r.status, response: r.response ?? null, error: r.error ?? null, last_attempt: iso(Date.now()) });
    const ok = r.status >= 200 && r.status < 300;
    console.log(`Notify ${entry.event} run ${entry.run_id} -> ${entry.sent_to.split('?')[0]}: ${r.status || r.error}${ok ? '' : ` (attempt ${attempt}/${retries + 1})`}`);
    if (ok || attempt > retries || Date.now() + pauseMs > deadline) return;
    await new Promise((res) => setTimeout(res, pauseMs));
  }
}

function send(run, event, statusName, n, payload = payloadFor(run, statusName, n?.url)) {
  let sentTo;
  try { sentTo = resolveUrl(n.url).toString(); } catch { sentTo = n.url; }
  const entry = { id: ++seq, time: iso(Date.now()), event, run_id: run.id, job_id: run.job_id, job_name: run.job_name, url: n.url, sent_to: sentTo,
    payload, attempts: 0, status: null, response: null, error: null };
  log.push(entry);
  if (log.length > LOG_MAX) log.splice(0, log.length - LOG_MAX);
  deliver(entry, n);
  return entry;
}

function onEvent(evt, run) {
  if (store.settings.notifications_enabled === false) return;
  if (evt === 'run-started' && !store.settings.notify_running) return;
  if (evt !== 'run-started' && evt !== 'run-finished') return;
  // History seeded at startup happened in the past; only notify for runs happening now.
  if (evt === 'run-finished' && (run.aborted_at || run.end_time) < Date.now() - 60000) return;
  if (evt === 'run-started' && run.start_time < Date.now() - 60000) return;
  const statusName = evt === 'run-started' ? 'RUNNING' : run.abort_status || run.final_status;
  for (const n of targetsFor(run)) send(run, evt, statusName, n);
}

// A one-off callback that belongs to a job, not a run, such as the callback_url of a compliance remediation.
// No retries: HAC marks the operation CREATION_FAILED on a callback it can't read.
function sendJobCallback(job, url, payload) {
  return send({ id: null, job_id: job.id, job_name: job.name }, 'job-created', 'COMPLETED', { url, retry_count: 0 }, payload);
}

// Re-sends a logged notification with its original payload.
function resend(id) {
  const e = log.find((x) => x.id === Number(id));
  if (!e) return null;
  const run = store.run(e.run_id);
  if (!run) return null;
  return send(run, `${e.event.replace(/ \(resend\)$/, '')} (resend)`, e.payload.status, { url: e.url, retry_count: 0 }, { ...e.payload });
}

function init() { store.listeners.add(onEvent); }

module.exports = { init, log, resend, targetsFor, sendJobCallback };
