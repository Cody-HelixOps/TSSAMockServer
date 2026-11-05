#!/usr/bin/env node
'use strict';
// Smoke test against a running mock: node test/smoke.js [https://host:9843]
const https = require('https');

const BASE = process.argv[2] || 'https://localhost:9843';
const agent = new https.Agent({ rejectUnauthorized: false });
let failures = 0;

function req(method, path, { body, headers = {}, raw } = {}) {
  return new Promise((resolve, reject) => {
    const data = raw ?? (body !== undefined ? JSON.stringify(body) : undefined);
    const r = https.request(`${BASE}${path}`, { method, agent, headers: { accept: 'application/json', ...(data && !raw ? { 'Content-Type': 'application/json' } : {}), ...headers } }, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(buf); } catch { /* text */ }
        resolve({ status: res.statusCode, headers: res.headers, json, text: buf });
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? `  (${extra})` : ''}`);
  if (!cond) failures++;
}

const soap = (body, sid = '') => `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header>${sid ? `<sessionId>${sid}</sessionId>` : ''}</soapenv:Header><soapenv:Body>${body}</soapenv:Body></soapenv:Envelope>`;
const cli = (ns, cmd, args, sid) => req('POST', '/services/CLITunnelService', { raw: soap(`<executeCommandByParamList><nameSpace>${ns}</nameSpace><commandName>${cmd}</commandName>${args.map((a) => `<commandArguments>${a}</commandArguments>`).join('')}</executeCommandByParamList>`, sid), headers: { 'Content-Type': 'text/xml' } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const unauth = await req('GET', '/rest/api/v1/servers');
  check('REST rejects missing session', unauth.status === 401);

  const login = await req('POST', '/rest/api/v1/sessions', { body: { user_name: 'BLAdmin', password: process.env.MOCK_PASSWORD || 'password', role_name: 'BLAdmins', authentication_type: 'SRP' } });
  check('POST /sessions', login.status === 200 && login.json.session_id, login.json?.session_id);
  const H = { headers: { 'session-id': login.json.session_id } };

  const servers = await req('GET', '/rest/api/v1/servers', H);
  check('GET /servers (server_list)', servers.json?.server_list?.length > 0, `${servers.json?.total_records} servers`);
  const catalogs = await req('GET', '/rest/api/v1/catalogs', H);
  check('GET /catalogs (Windows + Linux)', catalogs.json?.catalogs.some((c) => c.os_type === 'Windows') && catalogs.json?.catalogs.some((c) => c.os_type !== 'Windows'));
  check('GET /catalogs uses TSSA links array', Array.isArray(catalogs.json?.links) && catalogs.json.links.some((l) => l.rel === 'self'));
  const cid = catalogs.json.catalogs[0].id;
  const detail = await req('GET', `/rest/api/v1/catalogs/${cid}`, H);
  check('GET /catalogs/{id} has schedules array (HAC Add Catalog needs it)', Array.isArray(detail.json?.schedules));
  const sched = await req('PUT', '/rest/api/v1/catalogs/999999/schedules', { ...H, body: { schedules: [] } });
  check('PUT /catalogs/{id}/schedules accepts clears for unknown ids', sched.status === 200);
  const info = await req('GET', '/rest/actuator/info');
  check('GET /rest/actuator/info', info.status === 200 && !!info.json?.version?.version);
  const winSrv = await req('GET', '/rest/api/v1/servers?device_type=server&device_state=Enrolled&page=0&size=1000&additional_detail=true&os_name=Windows', H);
  check('GET /servers honours os_name', winSrv.json?.server_list.length > 0 && winSrv.json.server_list.every((s) => s.os.name === 'Windows' && s.properties));
  const patches = await req('GET', `/rest/api/v2/catalogs/${cid}/patches?size=5`, H);
  check('GET /v2/catalogs/{id}/patches (hotfix items)', patches.json?.patches.length === 5 && !!patches.json.patches[0].hotfix);
  const scripts = await req('GET', '/rest/api/v1/nshscripts', H);
  check('GET /nshscripts', scripts.json?.nsh_scripts.length > 0);
  for (const type of ['NSHSCRIPT', 'BLPACKAGE', 'MSI_WINDOWS_INSTALLABLE', 'RPM_INSTALLABLE']) {
    const ds = await req('POST', `/rest/api/v1/depots/search?size=10&page=0&type=${type}`, { ...H, body: {} });
    check(`POST /depots/search type=${type} (HAC content picker)`, ds.json?.depot_object_list?.length > 0 && !!ds.json.depot_object_list[0].depot_object?.save_in, `${ds.json?.total_records} items`);
  }
  const pkgs = await req('GET', '/rest/api/v1/blpackages', H);
  check('GET /blpackages', pkgs.json?.blpackages.length > 0);

  const jg = await req('GET', '/rest/api/v1/groups/job?page=0&size=5000', H);
  const jobGroups = jg.json?.groups || [];
  const root = jobGroups.find((g) => g.path === '/');
  check('GET /groups/job parent is set on every group (policy create calls getParent().getPath())',
    jg.status === 200 && !!root && jobGroups.every((g) => typeof g.parent?.path === 'string' && g.parent_group?.path === g.parent.path));
  const made = await req('POST', '/rest/api/v1/groups/job', { ...H, body: { name: '1234567890_Administrator', parent_group_id: root?.id, description: 'Default policy job group' } });
  check('POST /groups/job creates /<id>_Administrator under /',
    made.status === 200 && made.json?.group?.path === '/1234567890_Administrator' && made.json?.group?.id > 0,
    made.json?.group?.path || made.text?.slice(0, 180));
  const depotRoot = (await req('GET', '/rest/api/v1/groups/depot?page=0&size=5000', H)).json?.groups?.some((g) => g.path === '/');
  check('GET /groups/depot lists a root', depotRoot === true);

  const jobs = await req('GET', '/rest/api/v1/nshscript-jobs?name=Disk Usage - Linux', H);
  const job = jobs.json?.jobs[0];
  check('GET /nshscript-jobs filter', !!job, job?.name);
  check('job id is a JobResponse.Id object', job?.id?.job_id === job?.job_id && job?.id?.job_version === 1 && !('id' in job.id));
  check('job type is a JobTypeDetail object', job?.type?.id === 200 && job?.type?.name === 'NSH Script Job' && job?.job_type === 'NSH_SCRIPT_JOB');
  const run = await req('PATCH', `/rest/api/v1/nshscript-jobs/${job.job_id}`, { ...H, body: {} });
  check('PATCH /nshscript-jobs/{id} executes', run.status === 202 && run.json.status === 'RUNNING' && run.json.message === '' && run.json.schedule_id > 0 && run.json.job_run?.status === 'RUNNING' && run.json.id?.job_id === job.job_id, `run ${run.json?.job_run_id}`);
  const runList = await req('GET', `/rest/api/v1/nshscript-jobs/${job.job_id}/jobruns`, H);
  const listed = runList.json?.job_runs?.[0];
  check('GET jobruns has the real job run fields (policy Sync reads them)',
    listed?.job_run?.job_run_id === run.json.job_run_id && listed?.job?.job_id === job.job_id && listed?.job?.job_version === 1
      && listed?.schedule_id === run.json.schedule_id && listed?.role_executed?.id > 0 && listed?.user_executed?.id > 0 && /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}$/.test(listed?.start_time) && typeof listed?.object_type?.id === 'number' && typeof listed?.progress_status === 'string' && typeof listed?.has_errors === 'boolean' && typeof listed?.is_cancelled === 'boolean');
  await sleep(1500);
  const ev = await req('GET', `/rest/api/v1/nshscript-jobs/${job.job_id}/jobruns/${run.json.job_run_id}/events`, H);
  check('GET jobruns/{rid}/events streams log', ev.json?.events.length > 0, `${ev.json?.events.length} events so far`);

  const schedPut = await req('PUT', `/rest/api/v1/nshscript-jobs/${job.job_id}`, { ...H, body: { schedules: [{ once: { datetime: '2020-01-01 00:00:00' }, timezone: 'UTC' }] } });
  const schedId = schedPut.json?.schedules?.[0]?.id;
  check('PUT job stores a schedule with an id', schedId > 0 && !('fired' in schedPut.json.schedules[0]));
  await sleep(2500);
  const scheduledRun = (await req('GET', `/rest/api/v1/nshscript-jobs/${job.job_id}/jobruns`, H)).json?.job_runs?.[0];
  check('due one-time schedule runs the job', scheduledRun?.schedule_id === schedId, `run ${scheduledRun?.job_run_id}`);
  const execNow = await req('POST', '/rest/api/v1/nshscript-jobs', { ...H, body: { name: `Smoke Execute Now ${Date.now()}`, nsh_script: scripts.json.nsh_scripts[0].id, execute_now: true, targets: { server_names: ['win-web-01.mock.lab'] } } });
  check('POST job with execute_now returns execute_now_schedule_id', execNow.status === 201 && execNow.json?.execute_now_schedule_id > 0);
  await req('DELETE', `/rest/api/v1/nshscript-jobs/${execNow.json?.job_id}`, H);
  const members = await req('GET', '/rest/api/v1/groups/server/' + (await req('GET', '/rest/api/v1/groups/server?page=0&size=1', H)).json.groups[0].id + '/members', H);
  check('GET /groups/server/{id}/members', members.status === 200 && Array.isArray(members.json?.servers));

  const create = await req('POST', '/rest/api/v1/patching-jobs', { ...H, body: { name: `Smoke Patch Job ${Date.now()}`, catalog_id: cid, targets: { server_names: ['win-web-01.mock.lab'] } } });
  check('POST /patching-jobs creates job', create.status === 201 && create.json?.id?.job_id === create.json?.job_id, create.json?.name);
  const del = await req('DELETE', `/rest/api/v1/patching-jobs/${create.json.job_id}`, H);
  check('DELETE /patching-jobs/{id}', del.status === 200);

  // Abort on the last catalog (SUSE) so the catalogs HAC imports keep a passed latest update.
  const cu = await req('PATCH', `/rest/api/v1/catalogs/${catalogs.json.catalogs[catalogs.json.catalogs.length - 1].id}`, { ...H, body: {} });
  check('PATCH /catalogs/{id} starts catalog update', cu.status === 202);
  const ab = await req('PATCH', `/rest/api/v1/catalog-update-jobs/${cu.json.job_id}/jobruns/${cu.json.job_run_id}/abort`, H);
  check('PATCH .../abort', ab.json?.status === 'ABORTED');

  // Every call a real HAC made against a real TSSA 26.3 REST server (restapi_default.log).
  const firstRun = async (slug, pick = () => true) => {
    for (const j of (await req('GET', `/rest/api/v1/${slug}?size=200`, H)).json.jobs) {
      const r = ((await req('GET', `/rest/api/v1/${slug}/${j.job_id}/jobruns`, H)).json.job_runs || []).find(pick);
      if (r) return [j.job_id, r.id ?? r.job_run_id];
    }
    return [];
  };
  const [pj, pr] = await firstRun('patching-jobs', (r) => /COMPLETED/.test(r.status));
  const [cj, cr] = await firstRun('compliance-jobs', (r) => /COMPLETED/.test(r.status));
  const nj = (await req('GET', '/rest/api/v1/nshscript-jobs', H)).json.jobs[0];
  const sid0 = servers.json.server_list[0].id;
  const logCalls = [
    ['GET /sessions', '/rest/api/v1/sessions', (j) => !!j.session_id],
    ['GET /servers/{id}', `/rest/api/v1/servers/${sid0}`, (j) => j.server.id === sid0 && !!j.properties],
    ['GET /catalogs?page=0&size=1000', '/rest/api/v1/catalogs?page=0&size=1000', (j) => j.catalogs.length > 0],
    ['GET /catalogs/{id}/containers', `/rest/api/v1/catalogs/${cid}/containers`, (j) => j.patch_containers.length > 0 && !!j.patch_containers[0].bulletin],
    ['GET patching-jobs results (BMC summary)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/results`, (j) => j.results.length > 0 && j.id === pr && typeof j.analysis?.patches?.missing === 'number' && typeof j.analysis?.scanned_machines === 'number'],
    ['GET patching-jobs results/analysis (patch_list rows)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/results/analysis`, (j) => Array.isArray(j.patch_list) && j.patch_list.length <= 250 && j.total_records >= j.patch_list.length && j.patch_list.every((p) => p.patch_status === 'MISSING' && p.server?.id > 0 && ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(p.severity))],
    ['GET patching-jobs results/analysis/servers/ (trailing slash, list rows)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/results/analysis/servers/`, (j) => j.servers.length > 0 && j.list.length === j.servers.length && /SUCCESS|FAILED/.test(j.list[0].status) && j.list[0].server?.id > 0],
    ['GET patching-jobs results/remediation (list rows)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/results/remediation`, (j) => Array.isArray(j.list) && j.total_records === j.list.length],
    ['GET patching-jobs results/remediation/servers/ (list rows)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/results/remediation/servers/`, (j) => Array.isArray(j.list)],
    ['GET patching-jobs events (job_run_events)', `/rest/api/v1/patching-jobs/${pj}/jobruns/${pr}/events`, (j) => j.job_run_events.length > 0 && !!j.job_run_events[0].message],
    ['GET compliance-jobs results/servers/ (trailing slash)', `/rest/api/v1/compliance-jobs/${cj}/jobruns/${cr}/results/servers/`, (j) => j.servers.length > 0 && j.list.length > 0 && j.list[0].compliant_rules !== undefined && !!j.list[0].name],
    ['GET compliance-jobs results/rules (rule rows)', `/rest/api/v1/compliance-jobs/${cj}/jobruns/${cr}/results/rules`, (j) => j.rules.length > 0 && !!j.rules[0].rule_name && j.list.length > 0 && !!j.list[0].server_id && !!j.list[0].rule_name],
    ['GET compliance-jobs results/rules page 2 is empty (HAC pages until it is)', `/rest/api/v1/compliance-jobs/${cj}/jobruns/${cr}/results/rules?page=1&size=5000`, (j) => j.list.length === 0],
    ['GET /nshscript-jobs/{id}', `/rest/api/v1/nshscript-jobs/${nj.job_id}`, (j) => j.job_id === nj.job_id && j.id.job_id === nj.job_id],
  ];
  for (const [name, path, ok] of logCalls) {
    const r = await req('GET', path, H);
    let pass = false;
    try { pass = r.status === 200 && ok(r.json); } catch { /* shape mismatch */ }
    check(name, pass, r.status === 200 ? '' : `HTTP ${r.status}`);
  }

  const tpl = (await req('GET', '/rest/api/v1/templates', H)).json.templates[0];
  const hacJob = await req('POST', '/rest/api/v1/compliance-jobs', { ...H, body: { name: `Smoke compliance ${Date.now()}`, templates: [{ id: tpl.id }] } });
  check('POST /compliance-jobs takes templates: [{ id }] (HAC)', hacJob.status === 201 && hacJob.json?.templates?.[0]?.id === tpl.id);
  await req('DELETE', `/rest/api/v1/compliance-jobs/${hacJob.json?.job_id}`, H);

  const nshList = await req('GET', '/rest/api/v1/nshscript-jobs?size=50', H);
  const deployList = await req('GET', '/rest/api/v1/deploy-jobs?sub_type=Basic&size=50', H);
  const batchList = await req('GET', '/rest/api/v1/batch-jobs?size=50', H);
  check('Ad hoc job lists use HAC\'s keys', nshList.json?.nshscript_job_list?.length >= 15 && deployList.json?.deploy_job_list?.length >= 7 && batchList.json?.batch_job_list?.length >= 5);
  check('deploy-jobs?sub_type=Basic hides generated jobs', deployList.json?.deploy_job_list?.every((j) => !j.is_generated && !j.name.startsWith('TS_')));
  const deployJob = deployList.json.deploy_job_list[0];
  check('Job details have HAC\'s wizard fields', !!deployJob.software_list?.[0] && !!deployJob.basic && !!batchList.json.batch_job_list[0].members?.length && Array.isArray(nshList.json.nshscript_job_list[0].script_parameters_details));
  const task = await req('POST', '/rest/api/v1/execution-tasks', { ...H, body: { name: `Smoke task ${Date.now()}`, job: { id: nshList.json.nshscript_job_list[0].job_id }, targets: { servers: [{ name: servers.json.server_list[0].name }] } } });
  check('POST /execution-tasks returns execution_task_id', task.status === 201 && !!task.json?.execution_task_id && !!task.json?.job?.id);
  const taskPut = await req('PUT', `/rest/api/v1/execution-tasks/${task.json?.execution_task_id}`, { ...H, body: { schedules: [{ once: { datetime: '2099-01-01 00:00:00' }, timezone: 'UTC' }] } });
  check('PUT /execution-tasks stores the schedule', taskPut.status === 200 && taskPut.json?.schedules?.length === 1);
  await req('DELETE', `/rest/api/v1/execution-tasks/${task.json?.execution_task_id}`, H);
  const remediate = await req('POST', '/rest/api/v1/compliance-jobs/remediate-async', { ...H, body: { name: `Smoke remediation ${Date.now()}`, targets: { servers: [{ name: servers.json.server_list[0].name }] } } });
  const remKey = remediate.json?.cache_key;
  const remJob = await req('GET', `/rest/api/v1/compliance-jobs/remediate-async/${remKey}`, H);
  check('compliance-jobs/remediate-async returns a key for its job', remediate.status === 200 && remJob.status === 200 && !!remJob.json?.job_id);
  await req('DELETE', `/rest/api/v1/deploy-jobs/${remJob.json?.job_id}`, H);

  const helper = await req('GET', '/hac-auto-sync.js');
  let helperParses = false;
  try { new Function(helper.text); helperParses = true; } catch { /* reported by the check */ }
  check('GET /hac-auto-sync.js parses', helper.status === 200 && helperParses);

  const lg = await req('POST', '/services/LoginService', { raw: soap('<loginUsingUserCredential><userName>BLAdmin</userName><password>password</password><authenticationType>SRP</authenticationType></loginUsingUserCredential>'), headers: { 'Content-Type': 'text/xml' } });
  const sid = (lg.text.match(/returnSessionId>([^<]+)</) || [])[1];
  check('SOAP LoginService', !!sid);
  const ar = await req('POST', '/services/AssumeRoleService', { raw: soap('<assumeRole><roleName>BLAdmins</roleName></assumeRole>', sid), headers: { 'Content-Type': 'text/xml' } });
  check('SOAP AssumeRoleService', ar.status === 200);
  const ls = await cli('Server', 'listAllServers', [], sid);
  check('BLCLI Server listAllServers', /win-web-01/.test(ls.text));
  const key = await cli('NSHScriptJob', 'getDBKeyByGroupAndName', ['/Workspace/Jobs/Operations', 'Get Disk Usage - Linux'], sid);
  const dbkey = (key.text.match(/returnValue[^>]*>([^<]+)</) || [])[1];
  check('BLCLI NSHScriptJob getDBKeyByGroupAndName', /SJobModelKeyImpl/.test(dbkey || ''), dbkey);
  const ex = await cli('Job', 'execute', [dbkey], sid);
  check('BLCLI Job execute', /SJobRunKeyImpl/.test(ex.text));

  console.log(failures ? `\n${failures} check(s) failed` : '\nAll checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
