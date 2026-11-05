'use strict';
// In-memory TSSA state with JSON persistence, sessions and settings.
const fs = require('fs');
const path = require('path');
const { seed, addAdhocJobs } = require('./seed');
const { uuid } = require('./util');

const DATA_DIR = path.join(__dirname, '..', 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const MAX_RUNS = 1000;

const DEFAULT_SETTINGS = {
  app_server_name: 'mock-tssa-appserver',
  tssa_version: '26.3.00.130',
  speed: 1,                 // job run speed multiplier (2 = twice as fast)
  failure_rate: 0.08,       // per-target random failure probability
  strict_auth: false,       // when true, passwords must match `users`
  session_lifetime_min: 600,
  server_fields: null,      // optional whitelist of server fields returned to TSSA clients
  // Job notifications (lib/notify.js): callbacks to tssa.connector.* go to connector_url instead.
  notifications_enabled: true,
  connector_url: 'https://localhost:8443',
  notify_running: true,     // also send progressStatus RUNNING when a run starts
  notify_extra: null,       // optional object merged into every notification payload
  update_on_schedule_save: true,  // run a catalog update when HAC saves a schedule with a callback URL
  catalog_status: true,           // send the catalog update 'status' object; HAC's Add Catalog refuses catalogs without a passed one
  users: {
    BLAdmin: { password: 'password', roles: ['BLAdmins', 'RBACAdmins'] },
    HACService: { password: 'password', roles: ['BLAdmins'] },
  },
};

const store = {
  state: null,
  settings: null,
  sessions: new Map(),   // session_id -> { user, role, roles, created, expires }
  listeners: new Set(),

  init({ reset = false } = {}) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const saved = readJson(SETTINGS_FILE, {});
    this.settings = { ...DEFAULT_SETTINGS, ...saved, users: { ...DEFAULT_SETTINGS.users, ...(saved.users || {}) } };
    this.state = (!reset && readJson(STATE_FILE, null)) || null;
    if (!this.state) {
      this.state = seed();
      this.seeded = true;
    }
    addAdhocJobs(this.state, () => this.nextId());
    // Sessions survive restarts; clients such as the HAC connector cache them.
    for (const s of readJson(SESSIONS_FILE, [])) if (s.expires > Date.now()) this.sessions.set(s.id, s);
    this.saveSoon();
  },

  reset() {
    this.state = seed();
    this.seeded = true;
    this.save();
    this.emit('reset');
  },

  nextId() {
    this.state.idSeq += 1 + Math.floor(Math.random() * 7);
    return this.state.idSeq;
  },

  saveSoon() {
    clearTimeout(this._t);
    this._t = setTimeout(() => this.save(), 1500);
  },

  save() {
    clearTimeout(this._t);
    const s = this.state;
    if (s.runs.length > MAX_RUNS) s.runs.splice(0, s.runs.length - MAX_RUNS);
    writeJson(STATE_FILE, s);
    writeJson(SETTINGS_FILE, this.settings);
    writeJson(SESSIONS_FILE, [...this.sessions.values()]);
  },

  updateSettings(patch) {
    for (const k of Object.keys(DEFAULT_SETTINGS)) if (k in patch) this.settings[k] = patch[k];
    this.settings.speed = Math.max(0.1, Math.min(100, Number(this.settings.speed) || 1));
    this.settings.failure_rate = Math.max(0, Math.min(1, Number(this.settings.failure_rate) || 0));
    this.save();
  },

  emit(evt, data) { for (const l of this.listeners) l(evt, data); },

  // --- sessions ----------------------------------------------------------
  login(user, password, role, authType) {
    const u = this.settings.users[user];
    // RSSO logins carry an SSO token, not a password; the mock accepts them for configured users.
    const rsso = String(authType || '').toUpperCase() === 'RSSO';
    if (this.settings.strict_auth && rsso && !u) return { error: `Authentication failed: unknown RSSO user ${user}` };
    if (this.settings.strict_auth && !rsso) {
      if (!u || u.password !== password) return { error: 'Authentication failed: invalid user name or password' };
    }
    const roles = u ? u.roles : ['BLAdmins'];
    const chosen = role || roles[0];
    if (this.settings.strict_auth && !roles.includes(chosen)) return { error: `User ${user} is not a member of role ${chosen}` };
    const now = Date.now();
    const sess = { id: uuid(), user, role: chosen, roles, created: now, expires: now + this.settings.session_lifetime_min * 60000 };
    this.sessions.set(sess.id, sess);
    this.saveSoon();
    return { session: sess };
  },

  getSession(id) {
    if (!id) return null;
    let s = this.sessions.get(id);
    // Without strict auth, adopt session ids the mock never issued (cached by a client before a
    // restart, or from the real TSSA server) instead of failing with 401.
    if (!s && !this.settings.strict_auth && /^[\w-]{16,}$/.test(id)) {
      const now = Date.now();
      s = { id, user: 'BLAdmin', role: 'BLAdmins', roles: this.settings.users.BLAdmin?.roles || ['BLAdmins'], created: now, expires: now + this.settings.session_lifetime_min * 60000, adopted: true };
      this.sessions.set(id, s);
      this.saveSoon();
      console.log(`Adopted unknown session ${id.slice(0, 8)}... as BLAdmin (strict_auth is off)`);
    }
    if (!s) return null;
    if (s.expires < Date.now()) { this.sessions.delete(id); return null; }
    return s;
  },

  // --- lookups -----------------------------------------------------------
  server(idOrName) {
    const s = this.state.servers;
    const n = Number(idOrName);
    return s.find((x) => x.id === n) || s.find((x) => x.name === idOrName || x.short_name === idOrName);
  },
  group(idOrPath) {
    const n = Number(idOrPath);
    return this.state.groups.find((g) => g.id === n || g.path === idOrPath || g.name === idOrPath);
  },
  job(id) { return this.state.jobs.find((j) => j.id === Number(id)); },
  jobByPath(groupPath, name) { return this.state.jobs.find((j) => j.name === name && (!groupPath || j.group_path === groupPath)); },
  run(id) { return this.state.runs.find((r) => r.id === Number(id)); },
  catalog(id) { return this.state.catalogs.find((c) => c.id === Number(id) || c.name === id); },
  patch(id) { return this.state.patches.find((p) => p.id === Number(id)); },
  script(id) { return this.state.scripts.find((x) => x.id === Number(id) || x.name === id); },
  blpackage(id) { return this.state.blpackages.find((x) => x.id === Number(id) || x.name === id); },
  template(id) { return this.state.templates.find((x) => x.id === Number(id)); },

  // Expand a job's server + group targets into server objects.
  resolveTargets(targets) {
    const ids = new Set(targets?.server_ids || []);
    for (const gid of targets?.group_ids || []) {
      const g = this.group(gid);
      if (g) g.member_ids.forEach((m) => ids.add(m));
    }
    return [...ids].map((id) => this.server(id)).filter((s) => s && !s.decommissioned);
  },

  // Accept the many shapes a client may send for targets.
  parseTargets(body) {
    if (!body || typeof body !== 'object') return null;
    const t = body.targets || body.target || body;
    const out = { server_ids: [], group_ids: [] };
    const addServer = (v) => {
      const s = this.server(typeof v === 'object' ? (v.id ?? v.name ?? v.server_name) : v);
      if (s) out.server_ids.push(s.id);
    };
    const addGroup = (v) => {
      const g = this.group(typeof v === 'object' ? (v.id ?? v.path ?? v.name) : v);
      if (g) out.group_ids.push(g.id);
    };
    for (const k of ['servers', 'server_ids', 'server_names', 'serverIds', 'target_servers']) (Array.isArray(t[k]) ? t[k] : []).forEach(addServer);
    for (const k of ['groups', 'group_ids', 'server_groups', 'smart_groups', 'smart_group_ids']) (Array.isArray(t[k]) ? t[k] : []).forEach(addGroup);
    return out.server_ids.length || out.group_ids.length ? out : null;
  },
};

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function writeJson(file, obj) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, file);
}

module.exports = store;
