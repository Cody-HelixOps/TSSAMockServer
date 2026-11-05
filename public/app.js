'use strict';
// Mock TSSA web console. Talks to the same REST API the HAC connector uses.
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (t) => (t ? new Date(t.replace('+0000', 'Z')).toLocaleString() : '—');
const st = (s) => `<span class="st ${esc(s)}">${esc(String(s || '').replace(/_/g, ' '))}</span>`;
const dur = (a, b) => { if (!a) return ''; const ms = (b ? Date.parse(b.replace('+0000', 'Z')) : Date.now()) - Date.parse(a.replace('+0000', 'Z')); const s = Math.max(0, Math.round(ms / 1000)); return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; };

let SID = null;
let timer = null;
const cache = {};

async function session() {
  const r = await fetch('/mock/ui-session');
  SID = (await r.json()).session_id;
}

async function api(method, path, body) {
  if (!SID) await session();
  const opts = { method, headers: { 'session-id': SID, 'x-mock-ui': '1', accept: 'application/json' } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let r = await fetch(`/rest/api/v1${path}`, opts);
  if (r.status === 401) { await session(); opts.headers['session-id'] = SID; r = await fetch(`/rest/api/v1${path}`, opts); }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error(data.message || r.statusText);
  return data;
}
const mock = async (method, path, body) => (await fetch(`/mock/${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })).json();

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, 3000);
}

function drawer(title, html) {
  $('#drawerTitle').textContent = title; $('#drawerBody').innerHTML = html; $('#drawer').hidden = false;
}
$('#drawerClose').onclick = () => { $('#drawer').hidden = true; clearInterval(drawer.timer); };

// --- router ---------------------------------------------------------------
const pages = {};
function go(page, arg) {
  clearInterval(timer);
  clearTimeout(timer);
  go.page = page;
  go.arg = arg === undefined ? undefined : String(arg);
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === page));
  location.hash = arg ? `${page}/${arg}` : page;
  pages[page](arg);
}
document.querySelectorAll('#nav a').forEach((a) => { a.onclick = () => go(a.dataset.page); });
window.addEventListener('hashchange', () => {
  const [p, a] = (location.hash.slice(1) || 'dashboard').split('/');
  if (pages[p] && (p !== go.page || a !== go.arg)) go(p, a);
});

// --- dashboard ----------------------------------------------------------------
pages.dashboard = async () => {
  const [servers, catalogs, jobs, runs, info, sess] = await Promise.all([
    api('GET', '/servers'), api('GET', '/catalogs'), api('GET', '/jobs'), api('GET', '/jobruns?size=12'), mock('GET', 'info'), mock('GET', 'sessions'),
  ]);
  const online = servers.servers.filter((s) => s.is_online).length;
  const missing = servers.servers.reduce((a, s) => a + s.missing_patch_count, 0);
  const running = runs.job_runs.filter((r) => r.status === 'RUNNING').length;
  if (go.page !== 'dashboard') return;
  $('#main').innerHTML = `
    <h1>Dashboard</h1><p class="sub">Mock TrueSight Server Automation ${esc(info.version)} application server</p>
    <div class="cards">
      <div class="card"><div class="k">Servers (agent alive)</div><div class="v">${online} / ${servers.total_records}</div></div>
      <div class="card"><div class="k">Patch catalogs</div><div class="v">${catalogs.total_records}</div></div>
      <div class="card"><div class="k">Missing patch instances</div><div class="v">${missing}</div></div>
      <div class="card"><div class="k">Jobs</div><div class="v">${jobs.total_records}</div></div>
      <div class="card"><div class="k">Running job runs</div><div class="v">${running}</div></div>
      <div class="card"><div class="k">Active API sessions</div><div class="v">${sess.sessions.length}</div></div>
    </div>
    <div class="grid2">
      <div class="panel"><div class="panel-head"><h2>HAC connector settings</h2></div><div class="panel-body kv">
        <div>Cloudflare tunnel</div><div>${info.tunnel.provider ? `${st(info.tunnel.status === 'connected' ? 'ok' : info.tunnel.status === 'error' ? 'err' : 'warn').replace(/>(ok|warn|err)</, `>${esc(info.tunnel.status)}<`)} <span class="mono">${esc(info.tunnel.url || '')}</span>${info.tunnel.error ? `<div class="muted">${esc(info.tunnel.error)}</div>` : ''}` : '<span class="muted">disabled (MOCK_TUNNEL=off)</span>'}</div>
        <div>Helix connector</div><div>${info.helix ? `${st(info.helix.status === 'connected' ? 'ok' : info.helix.status === 'error' || info.helix.status === 'login-failed' ? 'err' : 'warn').replace(/>(ok|warn|err)</, `>${esc(info.helix.status)}<`)} <span class="mono">${esc(info.helix.workerId || '')}</span>${info.helix.lastError ? `<div class="muted">${esc(info.helix.lastError)}</div>` : ''}` : '<span class="muted">not running</span>'}</div>
        <div>Host Name</div><div class="mono">${info.tunnel.host ? esc(info.tunnel.host) : `${esc(info.hostnames.dns.filter((d) => d !== 'localhost')[0] || 'localhost')} <span class="muted">(or ${esc(info.hostnames.ip.filter((i) => i !== '127.0.0.1').join(', '))})</span>`}</div>
        <div>Application Port</div><div class="mono">${info.tunnel.host ? 443 : info.https_port}</div>
        <div>Role Name</div><div class="mono">BLAdmins</div>
        <div>Version</div><div class="mono">${esc(info.version)}</div>
        <div>User Name</div><div class="mono">BLAdmin</div>
        <div>Password</div><div class="mono">any (strict auth off) — see Settings</div>
        <div>Authentication</div><div class="mono">Secure Remote Password</div>
        <div>Certificate</div><div class="mono">${info.tunnel.host ? 'Cloudflare-issued (publicly trusted), no import needed' : esc(info.cert_file || 'not generated')}</div>
      </div></div>
      <div class="panel"><div class="panel-head"><h2>API sessions</h2></div><div class="scroll" style="max-height:260px"><table>
        <tr><th>User</th><th>Role</th><th>Created</th><th>Session</th></tr>
        ${sess.sessions.map((s) => `<tr><td>${esc(s.user)}</td><td>${esc(s.role)}</td><td>${fmt(s.created)}</td><td class="mono">${esc(s.id)}</td></tr>`).join('') || '<tr><td colspan=4 class="muted">No sessions yet</td></tr>'}
      </table></div></div>
    </div>
    <div class="panel"><div class="panel-head"><h2>Recent job runs</h2><button class="btn sm" onclick="go('runs')">All runs</button></div>${runsTable(runs.job_runs)}</div>`;
  clearTimeout(timer);
  timer = setTimeout(() => { if (go.page === 'dashboard') pages.dashboard().catch(() => {}); }, 5000);
};

function runsTable(list) {
  return `<div class="scroll"><table><tr><th>Run</th><th>Job</th><th>Type</th><th>Status</th><th>Progress</th><th>Targets</th><th>Started</th><th>Duration</th><th>By</th></tr>
  ${list.map((r) => `<tr class="click" onclick="openRun(${r.id})"><td class="mono">${r.id}</td><td>${esc(r.job_name)}${r.parent_job_run_id ? ' <span class="muted">(child)</span>' : ''}</td><td class="muted">${esc(r.job_type.replace(/_/g, ' ').toLowerCase())}</td><td>${st(r.status)}</td>
  <td><div class="bar"><i style="width:${r.progress}%"></i></div></td><td>${r.target_counts.total}${r.target_counts.failed ? ` <span class="st err">${r.target_counts.failed} failed</span>` : ''}</td><td>${fmt(r.start_time)}</td><td>${dur(r.start_time, r.end_time)}</td><td>${esc(r.executed_by)}</td></tr>`).join('') || '<tr><td colspan=9 class="muted">No runs</td></tr>'}</table></div>`;
}

// --- servers --------------------------------------------------------------------
pages.servers = async () => {
  const { servers } = await api('GET', '/servers');
  cache.servers = servers;
  if (go.page !== 'servers') return;
  $('#main').innerHTML = `<h1>Servers</h1><p class="sub">Managed servers enrolled with RSCD agents</p>
    <div class="panel"><div class="panel-head"><input id="q" placeholder="Filter servers…" style="width:260px"><span class="muted">${servers.length} servers</span></div>
    <div class="scroll"><table id="srvT"></table></div></div>`;
  const draw = () => {
    const q = $('#q').value.toLowerCase();
    $('#srvT').innerHTML = `<tr><th>Name</th><th>OS</th><th>Environment</th><th>Application</th><th>Agent</th><th>Missing patches</th><th>Last analysis</th></tr>${servers.filter((s) => JSON.stringify(s).toLowerCase().includes(q)).map((s) => `
      <tr class="click" onclick="openServer(${s.id})"><td><b>${esc(s.name)}</b><div class="muted mono">${esc(s.ip_address)}</div></td><td>${esc(s.os_version)}</td><td>${esc(s.property_map.ENVIRONMENT)}</td><td>${esc(s.property_map.APPLICATION)}</td>
      <td>${st(s.is_online ? 'ok' : 'err').replace(/>ok</, '>alive<').replace(/>err</, '>not responding<')}</td><td>${s.missing_patch_count}</td><td>${s.last_patch_analysis ? fmt(s.last_patch_analysis.date) : '<span class="muted">never</span>'}</td></tr>`).join('')}`;
  };
  $('#q').oninput = draw; draw();
};

window.openServer = async (id) => {
  const [s, mp] = await Promise.all([api('GET', `/servers/${id}`), api('GET', `/servers/${id}/missing-patches`)]);
  drawer(s.name, `<div class="kv">
    ${[['OS', s.os_version], ['Platform', s.platform], ['IP address', s.ip_address], ['Agent', `${s.agent_status} (${s.agent_version}, port ${s.agent_port})`], ['CPU / Memory', `${s.cpu_count} vCPU / ${s.memory_mb} MB`], ['Last reboot', fmt(s.last_reboot)], ['Patch catalog', s.patch_catalog.name], ['DBKey', s.db_key]].map(([k, v]) => `<div>${k}</div><div>${esc(v)}</div>`).join('')}
    </div><h3>Properties</h3><div class="kv">${s.properties.map(({ name: k, value: v }) => `<div class="mono">${esc(k)}</div><div>${esc(v)}</div>`).join('')}</div>
    <h3>Missing patches (${mp.total_records})</h3><table><tr><th>Patch</th><th>Severity</th><th>Title</th></tr>${mp.patches.map((p) => `<tr><td class="mono">${esc(p.name)}</td><td class="sev-${esc(p.severity)}">${esc(p.severity)}</td><td>${esc(p.title)}</td></tr>`).join('')}</table>`);
};

// --- depot --------------------------------------------------------------------------
pages.depot = async (tab = 'scripts') => {
  const [sc, bl, sw, df] = await Promise.all([api('GET', '/nshscripts'), api('GET', '/blpackages'), api('GET', '/software-packages'), api('GET', '/depot-files')]);
  const tabs = { scripts: 'NSH Scripts', packages: 'BLPackages', software: 'Software', files: 'Files' };
  let body = '';
  if (tab === 'scripts') body = `<table><tr><th>Name</th><th>Group</th><th>Platforms</th><th>Parameters</th><th>Description</th></tr>${sc.nsh_scripts.map((s) => `<tr class="click" onclick="openScript(${s.id})"><td><b>${esc(s.name)}</b></td><td class="mono">${esc(s.group_path)}</td><td>${esc(s.platforms.join(', '))}</td><td class="mono">${esc(s.parameters.map((p) => p.name).join(', '))}</td><td>${esc(s.description)}</td></tr>`).join('')}</table>`;
  if (tab === 'packages') body = `<table><tr><th>Name</th><th>Group</th><th>Version</th><th>Items</th></tr>${bl.blpackages.map((p) => `<tr><td><b>${esc(p.name)}</b><div class="muted">${esc(p.platforms.join(', '))}</div></td><td class="mono">${esc(p.group_path)}</td><td>${p.version}</td><td class="mono">${p.items.map((i) => `${esc(i.action)} ${esc(i.type)} ${esc(i.path)}`).join('<br>')}</td></tr>`).join('')}</table>`;
  if (tab === 'software') body = `<table><tr><th>Name</th><th>Type</th><th>File</th><th>Group</th></tr>${sw.software_packages.map((p) => `<tr><td><b>${esc(p.name)}</b></td><td>${esc(p.type)}</td><td class="mono">${esc(p.file)}</td><td class="mono">${esc(p.group_path)}</td></tr>`).join('')}</table>`;
  if (tab === 'files') body = `<table><tr><th>Name</th><th>Group</th><th>Size</th></tr>${df.depot_files.map((p) => `<tr><td><b>${esc(p.name)}</b></td><td class="mono">${esc(p.group_path)}</td><td>${p.size} B</td></tr>`).join('')}</table>`;
  if (go.page !== 'depot') return;
  $('#main').innerHTML = `<h1>Depot</h1><p class="sub">Scripts, BLPackages, software and files</p>
    <div class="tabs">${Object.entries(tabs).map(([k, v]) => `<button class="${k === tab ? 'on' : ''}" onclick="go('depot','${k}')">${v}</button>`).join('')}</div>
    <div class="panel"><div class="scroll">${body}</div></div>`;
};

window.openScript = async (id) => {
  const s = await api('GET', `/nshscripts/${id}`);
  drawer(s.name, `<div class="kv"><div>Group</div><div class="mono">${esc(s.group_path)}</div><div>Type</div><div>${esc(s.script_type)}</div><div>DBKey</div><div class="mono">${esc(s.db_key)}</div></div><h3>Script</h3><pre class="code">${esc(s.script_content)}</pre>`);
};

// --- catalogs --------------------------------------------------------------------------
pages.catalogs = async (id) => {
  const { catalogs } = await api('GET', '/catalogs');
  const cur = catalogs.find((c) => String(c.id) === String(id)) || catalogs[0];
  const pts = await api('GET', `/catalogs/${cur.id}/patches`);
  if (go.page !== 'catalogs') return;
  $('#main').innerHTML = `<h1>Patch Catalogs</h1><p class="sub">Windows and Linux patch catalogs</p>
    <div class="tabs">${catalogs.map((c) => `<button class="${c.id === cur.id ? 'on' : ''}" onclick="go('catalogs',${c.id})">${esc(c.name)}</button>`).join('')}</div>
    <div class="panel"><div class="panel-head"><div><h2>${esc(cur.name)}</h2><span class="muted">${esc(cur.source)} · ${cur.patch_count} patches · updated ${fmt(cur.last_updated)}</span></div>
      <div class="row">${st(cur.update_status)}<button class="btn primary" onclick="updateCatalog(${cur.id})">Update catalog</button></div></div>
      <div class="panel-body kv"><div>Group</div><div class="mono">${esc(cur.group_path)}</div><div>Filters</div><div class="mono">${esc(JSON.stringify(cur.filters))}</div><div>Containers</div><div>${cur.containers.map((k) => `${esc(k.name)} (${k.patch_count})`).join(' · ')}</div></div></div>
    <div class="panel"><div class="panel-head"><input id="pq" placeholder="Filter patches…" style="width:260px"><select id="psev"><option value="">All severities</option><option>Critical</option><option>Important</option><option>Moderate</option><option>Low</option></select></div>
    <div class="scroll"><table id="pT"></table></div></div>`;
  const draw = () => {
    const q = $('#pq').value.toLowerCase(); const sv = $('#psev').value;
    $('#pT').innerHTML = `<tr><th>Patch</th><th>Severity</th><th>Title</th><th>Product</th><th>Released</th><th>Size</th><th>Reboot</th><th>Missing on</th></tr>${pts.patches.filter((p) => (!sv || p.severity === sv) && JSON.stringify(p).toLowerCase().includes(q)).map((p) => `
      <tr><td class="mono">${esc(p.name)}</td><td class="sev-${esc(p.severity)}">${esc(p.severity)}</td><td>${esc(p.title)}<div class="muted mono">${esc(p.cve_ids.slice(0, 4).join(' '))}${p.cve_ids.length > 4 ? ' …' : ''}</div></td><td>${esc(p.product)}</td><td>${fmt(p.release_date).split(',')[0]}</td><td>${(p.size_bytes / 1048576).toFixed(1)} MB</td><td>${p.reboot_required ? 'Yes' : 'No'}</td><td>${p.missing_on_server_count} server(s)</td></tr>`).join('')}`;
  };
  $('#pq').oninput = draw; $('#psev').onchange = draw; draw();
};
window.updateCatalog = async (id) => { const r = await api('PATCH', `/catalogs/${id}`, {}); toast(`Catalog update started (run ${r.job_run_id})`); openRun(r.job_run_id); };

// --- jobs --------------------------------------------------------------------------------
pages.jobs = async () => {
  const { jobs } = await api('GET', '/jobs');
  const groups = [...new Set(jobs.map((j) => j.group_path))].sort();
  if (go.page !== 'jobs') return;
  $('#main').innerHTML = `<h1>Jobs</h1><p class="sub">Patching, NSH script, deploy, batch, compliance and snapshot jobs</p>
    <div class="panel"><div class="panel-head"><input id="jq" placeholder="Filter jobs…" style="width:260px"><button class="btn primary" onclick="newJob()">New job</button></div>
    <div class="scroll"><table id="jT"></table></div></div>`;
  const draw = () => {
    const q = $('#jq').value.toLowerCase();
    $('#jT').innerHTML = groups.map((g) => {
      const list = jobs.filter((j) => j.group_path === g && JSON.stringify(j).toLowerCase().includes(q));
      if (!list.length) return '';
      return `<tr><th colspan=6 class="mono">${esc(g)}</th></tr>${list.map((j) => `<tr><td><b>${esc(j.name)}</b><div class="muted">${esc(j.description)}</div></td><td>${esc(j.job_type_label)}</td>
        <td>${j.targets.servers.length ? `${j.targets.servers.length} server(s)` : ''} ${j.targets.groups.map((x) => esc(x.name)).join(', ')}</td>
        <td>${j.last_job_run ? `${st(j.last_job_run.status)}<div class="muted">${fmt(j.last_job_run.start_time)}</div>` : '<span class="muted">never run</span>'}</td>
        <td>${j.run_count} run(s)</td><td class="row"><button class="btn sm primary" onclick="execJob(${j.job_id})">Execute</button><button class="btn sm" onclick="openJob(${j.job_id})">Details</button></td></tr>`).join('')}`;
    }).join('');
  };
  $('#jq').oninput = draw; draw();
};

window.execJob = async (id) => {
  const r = await api('PATCH', `/jobs/${id}`, {});
  toast(`Started job run ${r.job_run_id}`);
  openRun(r.job_run_id);
};

window.openJob = async (id) => {
  const [j, runs] = await Promise.all([api('GET', `/jobs/${id}`), api('GET', `/jobs/${id}/jobruns`)]);
  const extra = j.catalog ? [['Catalog', j.catalog.name], ['Container', j.patch_container], ['Mode', j.remediate ? 'Analysis + remediation' : 'Analysis only'], ['Reboot', j.reboot_option]]
    : j.nsh_script ? [['NSH script', `${j.nsh_script.group_path}/${j.nsh_script.name}`], ['Arguments', j.arguments.join(' ')]]
      : j.blpackage ? [['BLPackage', `${j.blpackage.group_path}/${j.blpackage.name}`], ['Phases', (j.phases || []).join(', ')]]
        : j.template ? [['Template', j.template.name]] : j.member_jobs ? [['Member jobs', j.member_jobs.map((m) => m.name).join(' → ')]] : [];
  drawer(j.name, `<div class="row" style="margin-bottom:12px"><button class="btn primary" onclick="execJob(${j.job_id})">Execute</button><button class="btn danger" onclick="delJob(${j.job_id})">Delete</button></div>
    <div class="kv">${[['Type', j.job_type_label], ['Group', j.group_path], ['Job ID', j.job_id], ['DBKey', j.db_key], ['Created', `${fmt(j.date_created)} by ${j.created_by}`], ...extra,
    ['Target servers', j.targets.servers.map((s) => s.name).join(', ') || '—'], ['Target groups', j.targets.groups.map((g) => g.path).join(', ') || '—'],
    ['Schedules', j.schedules.map((s) => `${s.type} ${s.description} (next ${fmt(s.next_run)})`).join('; ') || '—']].map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('')}</div>
    <h3>Job runs</h3>${runsTable(runs.job_runs)}`);
};

window.delJob = async (id) => { if (!confirm('Delete this job?')) return; await api('DELETE', `/jobs/${id}`); $('#drawer').hidden = true; toast('Job deleted'); go('jobs'); };

window.newJob = async () => {
  const [servers, groups, cats, scripts, pkgs, tpls, jobs] = await Promise.all([api('GET', '/servers'), api('GET', '/groups/server'), api('GET', '/catalogs'), api('GET', '/nshscripts'), api('GET', '/blpackages'), api('GET', '/templates'), api('GET', '/jobs')]);
  drawer('New job', `<div class="form">
    <label>Type</label><select id="nType"><option value="PATCHING_JOB">Patching Job</option><option value="NSH_SCRIPT_JOB">NSH Script Job</option><option value="DEPLOY_JOB">BLPackage Deploy Job</option><option value="COMPLIANCE_JOB">Compliance Job</option><option value="SNAPSHOT_JOB">Snapshot Job</option><option value="BATCH_JOB">Batch Job</option></select>
    <label>Name</label><input id="nName" placeholder="My Job">
    <label>Group</label><input id="nGroup" value="/Workspace/Jobs/Custom">
    <label class="t-PATCHING_JOB">Catalog</label><select class="t-PATCHING_JOB" id="nCat">${cats.catalogs.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}</select>
    <label class="t-PATCHING_JOB">Container</label><select class="t-PATCHING_JOB" id="nCont"><option>All Patches</option><option>Critical and Important</option></select>
    <label class="t-PATCHING_JOB">Remediate</label><label class="t-PATCHING_JOB"><input type="checkbox" id="nRem"> analyze and deploy missing patches</label>
    <label class="t-NSH_SCRIPT_JOB">NSH script</label><select class="t-NSH_SCRIPT_JOB" id="nScript">${scripts.nsh_scripts.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join('')}</select>
    <label class="t-NSH_SCRIPT_JOB">Arguments</label><input class="t-NSH_SCRIPT_JOB" id="nArgs" placeholder="space separated">
    <label class="t-DEPLOY_JOB">BLPackage</label><select class="t-DEPLOY_JOB" id="nPkg">${pkgs.blpackages.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join('')}</select>
    <label class="t-COMPLIANCE_JOB">Template</label><select class="t-COMPLIANCE_JOB" id="nTpl">${tpls.templates.map((s) => `<option value="${s.id}">${esc(s.name)}</option>`).join('')}</select>
    <label class="t-BATCH_JOB">Member jobs</label><div class="chips t-BATCH_JOB">${jobs.jobs.filter((x) => x.job_type !== 'BATCH_JOB').map((x) => `<label><input type="checkbox" name="nMem" value="${x.job_id}">${esc(x.name)}</label>`).join('')}</div>
    <label>Target groups</label><div class="chips">${groups.groups.map((g) => `<label><input type="checkbox" name="nG" value="${g.id}">${esc(g.name)}</label>`).join('')}</div>
    <label>Target servers</label><div class="chips">${servers.servers.map((s) => `<label><input type="checkbox" name="nS" value="${s.id}">${esc(s.name.split('.')[0])}</label>`).join('')}</div>
    <span></span><div class="row"><button class="btn primary" id="nSave">Create</button><button class="btn" id="nSaveRun">Create and execute</button></div></div>`);
  const sync = () => document.querySelectorAll('[class*="t-"]').forEach((el) => { const m = el.className.match(/t-(\w+)/); el.style.display = m[1] === $('#nType').value ? '' : 'none'; });
  $('#nType').onchange = sync; sync();
  const save = async (run) => {
    const checked = (n) => [...document.querySelectorAll(`input[name=${n}]:checked`)].map((x) => Number(x.value));
    const body = { name: $('#nName').value || 'Untitled Job', type: $('#nType').value, group_path: $('#nGroup').value,
      targets: { server_ids: checked('nS'), group_ids: checked('nG') }, catalog_id: Number($('#nCat').value), container: $('#nCont').value,
      remediate: $('#nRem').checked, script_id: Number($('#nScript').value), arguments: $('#nArgs').value.split(/\s+/).filter(Boolean),
      package_id: Number($('#nPkg').value), template_id: Number($('#nTpl').value), member_jobs: checked('nMem') };
    try {
      const j = await api('POST', '/jobs', body);
      toast(`Created job ${j.name}`);
      if (run) execJob(j.job_id); else { $('#drawer').hidden = true; go('jobs'); }
    } catch (e) { toast(e.message); }
  };
  $('#nSave').onclick = () => save(false); $('#nSaveRun').onclick = () => save(true);
};

// --- runs ----------------------------------------------------------------------------------
pages.runs = async (id) => {
  if (id) return openRun(Number(id));
  const draw = async () => {
    const runs = await api('GET', '/jobruns?size=150');
    if (!location.hash.startsWith('#runs')) return;
    if (go.page !== 'runs') return;
  $('#main').innerHTML = `<h1>Job Runs</h1><p class="sub">Live job run status and logs (auto-refreshing)</p><div class="panel">${runsTable(runs.job_runs)}</div>`;
  };
  await draw();
  timer = setInterval(draw, 2000);
};

window.openRun = async (id) => {
  clearInterval(drawer.timer);
  let sev = ''; let srv = ''; let follow = true;
  const draw = async () => {
    const [r, ev, res] = await Promise.all([api('GET', `/jobruns/${id}`), api('GET', `/jobruns/${id}/events`), api('GET', `/jobruns/${id}/results`)]);
    const logEl = $('#runLog');
    const atBottom = !logEl || logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 30;
    const servers = [...new Set(ev.events.map((e) => e.server).filter(Boolean))];
    drawer(`Job run ${r.id}`, `
      <div class="row" style="justify-content:space-between;margin-bottom:10px"><div><b>${esc(r.job_name)}</b><div class="muted">${esc(r.group_path)}</div></div><div class="row">${st(r.status)}
      ${r.is_running ? `<button class="btn sm danger" onclick="abortRun(${r.job_id},${r.id})">Abort</button>` : ''}
      ${!r.is_running && r.target_counts.failed ? `<button class="btn sm" onclick="rerun(${r.job_id},${r.id})">Re-run failed</button>` : ''}
      <a class="btn sm" href="/rest/api/v1/jobruns/${r.id}/log" target="_blank" onclick="event.preventDefault();downloadLog(${r.id})">Export log</a></div></div>
      <div class="bar" style="margin-bottom:12px"><i style="width:${r.progress}%"></i></div>
      <div class="kv">${[['Type', r.job_type], ['Started', fmt(r.start_time)], ['Ended', fmt(r.end_time)], ['Duration', dur(r.start_time, r.end_time)], ['Executed by', `${r.executed_by} (${r.role_name})`], ['App server', r.application_server], ['Targets', `${r.target_counts.total} total · ${r.target_counts.succeeded} ok · ${r.target_counts.warnings} warnings · ${r.target_counts.failed} failed`]].map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('')}
      ${r.parent_job_run_id ? `<div>Parent run</div><div><a href="#" onclick="openRun(${r.parent_job_run_id});return false">${r.parent_job_run_id}</a></div>` : ''}
      ${r.child_job_runs.length ? `<div>Child runs</div><div>${r.child_job_runs.map((c) => `<a href="#" onclick="openRun(${c.id});return false">${esc(c.job_name)}</a> ${st(c.status)}`).join('<br>')}</div>` : ''}</div>
      <h3>Results by server</h3><table><tr><th>Server</th><th>Status</th><th>Exit</th><th>Detail</th></tr>${res.results.map((x) => `<tr><td>${esc(x.server_name)}</td><td>${st(x.status)}</td><td>${x.exit_code ?? ''}</td><td class="mono">${x.missing_patch_count !== undefined ? `${x.missing_patch_count} missing (${x.critical_count} critical)` : ''}${x.installed_patch_count !== undefined ? ` ${x.installed_patch_count} installed${x.rebooted ? ', rebooted' : ''}` : ''}${x.non_compliant !== undefined ? `${x.compliant} compliant / ${x.non_compliant} non-compliant` : ''}${x.output ? esc(x.output.split('\n')[0]) + (x.output.includes('\n') ? ' …' : '') : ''}</td></tr>`).join('')}</table>
      <div class="panel" style="margin-top:14px"><div class="panel-head"><h2>Job log</h2><div class="row">
        <select id="lSev"><option value="">All</option><option ${sev === 'INFO' ? 'selected' : ''}>INFO</option><option ${sev === 'WARNING' ? 'selected' : ''}>WARNING</option><option ${sev === 'ERROR' ? 'selected' : ''}>ERROR</option></select>
        <select id="lSrv"><option value="">All servers</option>${servers.map((s) => `<option ${s === srv ? 'selected' : ''}>${esc(s)}</option>`).join('')}</select>
        <label class="muted"><input type="checkbox" id="lFollow" ${follow ? 'checked' : ''}> follow</label></div></div>
        <div class="log" id="runLog">${ev.events.filter((e) => (!sev || e.severity === sev) && (!srv || e.server === srv)).map((e) => `<div class="l ${e.severity}"><span class="t" title="${esc(fmt(e.date))}">${esc(new Date(e.date.replace('+0000', 'Z')).toLocaleTimeString([], { hour12: false }))}</span><span>${esc(e.severity)}</span><span class="s">${esc(e.server || '')}</span><span>${esc(e.message)}</span></div>`).join('')}</div></div>`);
    const le = $('#runLog');
    if (follow && atBottom) le.scrollTop = le.scrollHeight;
    $('#lSev').onchange = (e) => { sev = e.target.value; draw(); };
    $('#lSrv').onchange = (e) => { srv = e.target.value; draw(); };
    $('#lFollow').onchange = (e) => { follow = e.target.checked; };
    if (!r.is_running && r.status !== 'NOT_STARTED') clearInterval(drawer.timer);
  };
  await draw();
  drawer.timer = setInterval(() => { if (!$('#drawer').hidden) draw(); else clearInterval(drawer.timer); }, 1500);
};

window.abortRun = async (jobId, runId) => { await api('PATCH', `/jobs/${jobId}/jobruns/${runId}/abort`); toast('Job run aborted'); openRun(runId); };
window.rerun = async (jobId, runId) => { const r = await api('PATCH', `/jobs/${jobId}/jobruns/${runId}`, { rerun_type: 'FAILED_TARGETS' }); toast(`Re-run started (${r.job_run_id})`); openRun(r.job_run_id); };
window.downloadLog = async (id) => {
  const text = await api('GET', `/jobruns/${id}/log`);
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = `jobrun-${id}.log`; a.click();
};

// --- inspector ------------------------------------------------------------------------------
let inspectorEntries = [];
pages.inspector = async () => {
  if (go.page !== 'inspector') return;
  $('#main').innerHTML = `<h1>API Inspector</h1><p class="sub">Every external request received (HAC connector, curl, BLCLI). Requests the mock does not implement are flagged so you can see exactly what the connector expects.</p>
    <div class="panel"><div class="panel-head"><div class="row"><label><input type="checkbox" id="iUn"> Only not-implemented</label><input id="iq" placeholder="Filter path…"></div><button class="btn" id="iClr">Clear</button></div>
    <div class="scroll"><table id="iT"></table></div></div>`;
  const draw = () => {
    const un = $('#iUn').checked; const q = $('#iq').value.toLowerCase();
    $('#iT').innerHTML = `<tr><th>Time</th><th>Client</th><th>Method</th><th>Path</th><th>Status</th><th>Note</th></tr>${inspectorEntries.slice().reverse().filter((e) => (!un || !e.matched) && e.path.toLowerCase().includes(q)).map((e) => `
      <tr class="click" onclick="openReq(${e.id})"><td>${fmt(e.time)}</td><td class="mono">${esc(e.client)}</td><td>${esc(e.method)}</td><td class="mono">${esc(e.path)}${Object.keys(e.query).length ? `?${esc(new URLSearchParams(e.query))}` : ''}</td>
      <td>${st(e.status < 300 ? 'ok' : e.status < 500 ? 'warn' : 'err').replace(/>(ok|warn|err)</, `>${e.status}<`)}</td><td>${e.matched ? esc(e.note || '') : '<span class="st err">NOT IMPLEMENTED</span> ' + esc(e.note || '')}</td></tr>`).join('')}`;
  };
  $('#iUn').onchange = draw; $('#iq').oninput = draw;
  $('#iClr').onclick = async () => { await mock('DELETE', 'inspector'); inspectorEntries = []; draw(); };
  draw();
  timer = setInterval(() => { if (location.hash.startsWith('#inspector')) draw(); }, 1500);
};
window.openReq = (id) => {
  const e = inspectorEntries.find((x) => x.id === id);
  const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };
  drawer(`${e.method} ${e.path}`, `<div class="kv"><div>Time</div><div>${fmt(e.time)}</div><div>Client</div><div>${esc(e.client)} (${e.scheme})</div><div>Status</div><div>${e.status}</div><div>Duration</div><div>${e.ms} ms</div><div>Implemented</div><div>${e.matched ? 'yes' : '<b>no</b>'}</div><div>Note</div><div>${esc(e.note || '')}</div></div>
    <h3>Query</h3><pre class="code">${esc(JSON.stringify(e.query, null, 2))}</pre><h3>Request headers</h3><pre class="code">${esc(JSON.stringify(e.headers, null, 2))}</pre>
    <h3>Request body</h3><pre class="code">${esc(pretty(e.body) || '(empty)')}</pre><h3>Response</h3><pre class="code">${esc(pretty(e.response))}</pre>`);
};

async function pollInspector() {
  try {
    const after = inspectorEntries.length ? inspectorEntries[inspectorEntries.length - 1].id : 0;
    const { entries } = await mock('GET', `inspector?after=${after}`);
    inspectorEntries.push(...entries);
    if (inspectorEntries.length > 1000) inspectorEntries.splice(0, inspectorEntries.length - 1000);
    const un = inspectorEntries.filter((e) => !e.matched).length;
    $('#unmatchedBadge').hidden = !un; $('#unmatchedBadge').textContent = un;
    const runs = await api('GET', '/jobruns?status=RUNNING&size=1');
    $('#runningBadge').hidden = !runs.total_records; $('#runningBadge').textContent = runs.total_records;
  } catch { /* server restarting */ }
}

// --- callbacks ------------------------------------------------------------------------------
let callbacks = [];
const cbState = (e) => (e.status === null ? 'RUNNING' : e.status >= 200 && e.status < 300 ? 'COMPLETED' : 'FAILED');
pages.callbacks = async () => {
  if (go.page !== 'callbacks') return;
  const { connector_url: cu } = await mock('GET', 'callbacks');
  if (go.page !== 'callbacks') return;
  $('#main').innerHTML = `<h1>Callbacks</h1><p class="sub">Notifications the mock sends when a job run starts or finishes, as a real TSSA server posts to the <span class="mono">notification_url</span> HAC gives it.
    URLs for <span class="mono">tssa.connector.*</span> are sent to <span class="mono">${esc(cu || '(not set)')}</span> instead (Settings), so no hosts-file entry is needed.</p>
    <div class="panel"><div class="panel-head"><h2>Sent notifications</h2><button class="btn" id="cbClr">Clear</button></div>
    <div class="scroll"><table id="cbT"></table></div></div>`;
  const draw = () => {
    $('#cbT').innerHTML = `<tr><th>Time</th><th>Event</th><th>Job</th><th>Run</th><th>progressStatus</th><th>Sent to</th><th>Result</th><th></th></tr>${callbacks.slice().reverse().map((e) => `
      <tr class="click" onclick="openCb(${e.id})"><td>${fmt(e.time)}</td><td>${esc(e.event)}</td><td>${esc(e.job_name)}</td><td class="mono">${e.run_id}</td><td>${esc(e.payload.progressStatus)}</td>
      <td class="mono">${esc(e.sent_to.split('?')[0])}</td><td>${st(cbState(e)).replace(/>[^<]*</, `>${e.status === null ? 'sending…' : esc(e.status || e.error)}${e.attempts > 1 ? ` (${e.attempts} tries)` : ''}<`)}</td>
      <td><button class="btn" onclick="event.stopPropagation();resendCb(${e.id})">Resend</button></td></tr>`).join('') || '<tr><td colspan="8" class="sub">No callbacks yet. Save a catalog schedule in HAC, or run a catalog update for a catalog HAC has a schedule on.</td></tr>'}`;
  };
  $('#cbClr').onclick = async () => { await mock('DELETE', 'callbacks'); callbacks = []; draw(); };
  draw();
  timer = setInterval(() => { if (location.hash.startsWith('#callbacks')) draw(); }, 1500);
};
window.openCb = (id) => {
  const e = callbacks.find((x) => x.id === id);
  const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } };
  drawer(`Callback ${e.id}: ${e.event}`, `<div class="kv"><div>Time</div><div>${fmt(e.time)}</div><div>Job run</div><div>${e.run_id} (${esc(e.job_name)})</div>
    <div>HAC URL</div><div class="mono">${esc(e.url)}</div><div>Sent to</div><div class="mono">${esc(e.sent_to)}</div>
    <div>Attempts</div><div>${e.attempts}</div><div>Status</div><div>${esc(e.status ?? 'sending…')}</div>${e.error ? `<div>Error</div><div>${esc(e.error)}</div>` : ''}</div>
    <h3>Payload</h3><pre class="code">${esc(JSON.stringify(e.payload, null, 2))}</pre><h3>Response</h3><pre class="code">${esc(pretty(e.response) || '(empty)')}</pre>`);
};
window.resendCb = async (id) => { const r = await mock('POST', `callbacks/${id}/resend`); toast(r.error || 'Callback re-sent'); };

async function pollCallbacks() {
  try {
    callbacks = (await mock('GET', 'callbacks')).entries;
    const bad = callbacks.filter((e) => cbState(e) === 'FAILED').length;
    $('#cbBadge').hidden = !bad; $('#cbBadge').textContent = bad;
  } catch { /* server restarting */ }
}

// --- HAC Auto-Sync -----------------------------------------------------------------------------
pages.autosync = async () => {
  const code = await (await fetch('hac-auto-sync.js')).text();
  if (go.page !== 'autosync') return;
  $('#main').innerHTML = `<h1>HAC Auto-Sync</h1><p class="sub">HAC shows a run's results only after someone clicks <b>Sync</b>. This script clicks it for you, every 30 seconds, while your signed-in HAC tab stays open.</p>
    <div class="panel"><div class="panel-head"><h2>Start it</h2><button class="btn primary" id="asCopy">Copy script</button></div>
    <div class="panel-body"><ol>
      <li>Open HAC and sign in.</li>
      <li>Press F12 and open the <b>Console</b> tab.</li>
      <li>Paste the script and press Enter. If the browser refuses the paste, type <span class="mono">allow pasting</span> first.</li>
      <li>Check that an Auto-Sync box appears at the bottom right of HAC, then close the console.</li>
    </ol><p class="sub">Keep the tab open. It can be in the background. Reloading HAC stops the script, so paste it again afterwards. It stops by itself after 8 hours, and the box has a Stop button.</p></div>
    <pre class="code" style="border:0;margin:0;max-height:420px">${esc(code)}</pre></div>`;
  $('#asCopy').onclick = async () => {
    try { await navigator.clipboard.writeText(code); toast('Script copied'); }
    catch { toast("Couldn't copy. Select the script below and copy it by hand."); }
  };
};

// --- settings -------------------------------------------------------------------------------
pages.settings = async () => {
  const s = await mock('GET', 'settings');
  const routes = await mock('GET', 'routes');
  if (go.page !== 'settings') return;
  $('#main').innerHTML = `<h1>Settings</h1><p class="sub">Simulation behaviour and credentials</p>
    <div class="panel"><div class="panel-body form">
      <label>Application server name</label><input id="sApp" value="${esc(s.app_server_name)}">
      <label>Reported TSSA version</label><input id="sVer" value="${esc(s.tssa_version)}">
      <label>Job speed multiplier</label><input id="sSpeed" type="number" step="0.5" min="0.1" value="${s.speed}">
      <label>Per-target failure rate</label><input id="sFail" type="number" step="0.01" min="0" max="1" value="${s.failure_rate}">
      <label>Strict authentication</label><label><input type="checkbox" id="sStrict" ${s.strict_auth ? 'checked' : ''}> require passwords below to match</label>
      <label>BLAdmin password</label><input id="sPw" value="${esc(s.users.BLAdmin?.password || '')}">
      <label>Session lifetime (min)</label><input id="sLife" type="number" value="${s.session_lifetime_min}">
      <label>Send job callbacks</label><label><input type="checkbox" id="sNotify" ${s.notifications_enabled !== false ? 'checked' : ''}> POST to HAC's notification_url when runs start and finish</label>
      <label>Connector URL</label><input id="sConn" value="${esc(s.connector_url || '')}" placeholder="https://localhost:8443">
      <label>Update catalog on schedule save</label><label><input type="checkbox" id="sUpd" ${s.update_on_schedule_save ? 'checked' : ''}> run a catalog update when HAC saves a schedule</label>
      <span></span><div class="row"><button class="btn primary" id="sSave">Save</button><button class="btn" id="sCompl">Undo compliance remediation</button><button class="btn danger" id="sReset">Reset all data</button></div>
    </div></div>
    <div class="grid2"><div class="panel"><div class="panel-head"><h2>REST endpoints (${routes.rest.length})</h2></div><div class="scroll" style="max-height:360px"><pre class="code" style="border:0;max-height:none">${esc(routes.rest.join('\n'))}</pre></div></div>
    <div class="panel"><div class="panel-head"><h2>BLCLI commands (${routes.blcli.length})</h2></div><div class="scroll" style="max-height:360px"><pre class="code" style="border:0;max-height:none">${esc(routes.blcli.map((x) => x.replace('.', ' ')).join('\n'))}</pre></div></div></div>`;
  $('#sSave').onclick = async () => {
    const users = { ...s.users, BLAdmin: { ...(s.users.BLAdmin || { roles: ['BLAdmins'] }), password: $('#sPw').value } };
    await mock('PUT', 'settings', { app_server_name: $('#sApp').value, tssa_version: $('#sVer').value, speed: Number($('#sSpeed').value), failure_rate: Number($('#sFail').value), strict_auth: $('#sStrict').checked, session_lifetime_min: Number($('#sLife').value), users,
      notifications_enabled: $('#sNotify').checked, connector_url: $('#sConn').value.trim(), update_on_schedule_save: $('#sUpd').checked });
    toast('Settings saved');
  };
  $('#sCompl').onclick = async () => { await mock('POST', 'compliance-reset'); toast('The next compliance scan finds non-compliant rules again'); };
  $('#sReset').onclick = async () => { if (!confirm('Reset all servers, catalogs, jobs and runs to the seeded state?')) return; await mock('POST', 'reset'); SID = null; toast('Data reset'); go('dashboard'); };
};

// --- boot -----------------------------------------------------------------------------------
setInterval(() => { $('#clock').textContent = new Date().toLocaleTimeString(); }, 1000);
setInterval(pollInspector, 2000);
setInterval(pollCallbacks, 3000);
(async () => {
  await session();
  const info = await mock('GET', 'info');
  $('#ver').textContent = `TrueSight Server Automation ${info.version} (mock)`;
  pollInspector();
  pollCallbacks();
  const [p, a] = (location.hash.slice(1) || 'dashboard').split('/');
  go(pages[p] ? p : 'dashboard', a);
})();
