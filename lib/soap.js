'use strict';
// BLCLI over SOAP: /services/LoginService, /services/AssumeRoleService, /services/CLITunnelService.
const store = require('./store');
const engine = require('./engine');
const { xmlEscape, xmlUnescape, iso } = require('./util');

const NS = {
  login: 'http://bladelogic.com/webservices/skeleton/login',
  role: 'http://bladelogic.com/webservices/skeleton/assumerole',
  cli: 'http://bladelogic.com/webservices/skeleton/clitunnel',
};

const envelope = (inner, header = '') => `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soapenv:Header>${header}</soapenv:Header>
<soapenv:Body>${inner}</soapenv:Body>
</soapenv:Envelope>`;

const fault = (msg, code = 'soapenv:Server') => envelope(`<soapenv:Fault><faultcode>${code}</faultcode><faultstring>${xmlEscape(msg)}</faultstring><detail><ns1:BLException xmlns:ns1="http://bladelogic.com/webservices/framework/exception">${xmlEscape(msg)}</ns1:BLException></detail></soapenv:Fault>`);

const tag = (xml, name) => {
  const m = xml.match(new RegExp(`<(?:[\\w-]+:)?${name}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`));
  return m ? xmlUnescape(m[1].trim()) : null;
};
const tags = (xml, name) => [...xml.matchAll(new RegExp(`<(?:[\\w-]+:)?${name}(?:\\s[^>]*)?(?:/>|>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>)`, 'g'))].map((m) => xmlUnescape((m[1] || '').trim()));

const idFromKey = (k) => {
  const m = String(k).match(/:(\d+)-/) || String(k).match(/^(\d+)$/);
  return m ? Number(m[1]) : NaN;
};
const jobKey = (j) => `DBKey:SJobModelKeyImpl:${j.id}-1-${j.id + 1}`;
const runKey = (r) => `DBKey:SJobRunKeyImpl:${r.id}-1-${r.id + 1}`;

class CliError extends Error {}

const TYPE_BY_NS = {
  NSHScriptJob: 'NSH_SCRIPT_JOB', PatchingJob: 'PATCHING_JOB', DeployJob: 'DEPLOY_JOB', BlPackageDeployJob: 'DEPLOY_JOB', BatchJob: 'BATCH_JOB',
  ComplianceJob: 'COMPLIANCE_JOB', FileDeployJob: 'FILE_DEPLOY_JOB', SnapshotJob: 'SNAPSHOT_JOB', Job: null,
};

function findJob(group, name, type) {
  const j = store.state.jobs.find((x) => x.name === name && (!group || x.group_path === group) && (!type || x.type === type));
  if (!j) throw new CliError(`Could not find job '${name}' in group '${group}'`);
  return j;
}

function jobFromKey(k) {
  const j = store.job(idFromKey(k));
  if (!j) throw new CliError(`Invalid job key: ${k}`);
  return j;
}

function runFromKeyOrId(k) {
  const r = store.run(idFromKey(k));
  if (!r) throw new CliError(`Invalid job run key or id: ${k}`);
  engine.materialize(r);
  return r;
}

function runTsSince(r) {
  return engine.visibleEvents(r).map((e) => `${iso(e.time)}\t${e.severity}\t${e.server || ''}\t${e.message}`).join('\n');
}

// Each command returns the BLCLI returnValue (string / array -> newline separated).
const COMMANDS = {
  'Utility.getCurrentRole': (a, s) => s.role,
  'Utility.getCurrentUserName': (a, s) => s.user,
  'Utility.getAppServerVersion': () => store.settings.tssa_version,

  'Server.listAllServers': () => store.state.servers.filter((x) => !x.decommissioned).map((x) => x.name),
  'Server.listServersInGroup': ([g]) => {
    const grp = store.group(g);
    if (!grp) throw new CliError(`Could not find group '${g}'`);
    return grp.member_ids.map((id) => store.server(id)?.name).filter(Boolean);
  },
  'Server.getServerIdByName': ([n]) => { const s = store.server(n); if (!s) throw new CliError(`Server '${n}' does not exist`); return s.id; },
  'Server.getServerDBKeyByName': ([n]) => { const s = store.server(n); if (!s) throw new CliError(`Server '${n}' does not exist`); return `DBKey:SDeviceKeyImpl:${s.id}-1-${s.id + 1}`; },
  'Server.printPropertyValue': ([n, p]) => serverProp(n, p),
  'Server.getFullyResolvedPropertyValue': ([n, p]) => serverProp(n, p),
  'Server.printAllProperties': ([n]) => {
    const s = store.server(n);
    if (!s) throw new CliError(`Server '${n}' does not exist`);
    return Object.entries({ NAME: s.name, OS: s.os, OS_RELEASE: s.os_version, AGENT_VERSION: s.agent_version, IP_ADDRESS: s.ip_address, ...s.properties }).map(([k, v]) => `${k} = ${v}`);
  },
  'Server.getAgentStatus': ([n]) => store.server(n)?.agent_status || 'unknown',
  'Server.decommissionServer': ([n]) => { const s = store.server(n); if (s) s.decommissioned = true; return true; },

  'ServerGroup.listChildGroupsInGroup': ([p]) => store.state.groups.filter((g) => g.path.startsWith(`${p}/`) && g.path.split('/').length === p.split('/').length + 1).map((g) => g.name),
  'ServerGroup.groupNameToId': ([p]) => { const g = store.group(p); if (!g) throw new CliError(`Could not find group '${p}'`); return g.id; },
  'SmartServerGroup.listAllSmartGroups': () => store.state.groups.filter((g) => g.group_type === 'SMART').map((g) => g.path),

  'NSHScript.listAllByGroup': ([g]) => store.state.scripts.filter((x) => !g || x.group_path === g).map((x) => x.name),
  'NSHScript.getDBKeyByGroupAndName': ([g, n]) => { const x = store.state.scripts.find((y) => y.name === n); if (!x) throw new CliError(`Could not find NSH script '${n}'`); return `DBKey:SDepotObjectKeyImpl:${x.id}-1-${x.id + 1}`; },
  'BlPackage.listAllByGroup': ([g]) => store.state.blpackages.filter((x) => !g || x.group_path === g).map((x) => x.name),
  'BlPackage.getDBKeyByGroupAndName': ([g, n]) => { const x = store.state.blpackages.find((y) => y.name === n); if (!x) throw new CliError(`Could not find BLPackage '${n}'`); return `DBKey:SDepotObjectKeyImpl:${x.id}-1-${x.id + 1}`; },
  'DepotObject.listAllByGroup': ([g]) => [...store.state.scripts, ...store.state.blpackages, ...store.state.software, ...store.state.depot_files].filter((x) => !g || x.group_path === g).map((x) => x.name),

  'PatchCatalog.listAllCatalogs': () => store.state.catalogs.map((c) => `${c.group_path}/${c.name}`),
  'PatchCatalog.getCatalogDBKeyByName': ([g, n]) => { const c = store.catalog(n || g); if (!c) throw new CliError(`Catalog not found: ${n || g}`); return `DBKey:SPatchCatalogKeyImpl:${c.id}-1-${c.id + 1}`; },
  'PatchCatalog.executeCatalogUpdateJob': ([g, n], s) => { const c = store.catalog(n || g) || store.catalog(idFromKey(g)); if (!c) throw new CliError('Catalog not found'); return runKey(engine.catalogUpdate(c, { user: s.user, role: s.role })); },
  'PatchCatalog.listPatchesInCatalog': ([g, n]) => { const c = store.catalog(n || g); if (!c) throw new CliError('Catalog not found'); return c.patch_ids.map((id) => store.patch(id)?.name); },

  'JobGroup.listChildGroupsInGroup': ([p]) => [...new Set(store.state.jobs.map((j) => j.group_path).filter((g) => g.startsWith(`${p}/`)).map((g) => `${p}/${g.slice(p.length + 1).split('/')[0]}`))].map((g) => g.split('/').pop()),
  'Job.listAllByGroup': ([g]) => store.state.jobs.filter((j) => j.group_path === g).map((j) => j.name),
  'Job.execute': ([k], s) => runKey(engine.startRun(jobFromKey(k), { user: s.user, role: s.role })),
  'Job.executeJobAndWait': ([k], s) => runKey(engine.startRun(jobFromKey(k), { user: s.user, role: s.role })),
  'Job.executeAgainstServers': ([k, servers], s) => runKey(engine.startRun(jobFromKey(k), { user: s.user, role: s.role, targets: { server_ids: String(servers).split(',').map((n) => store.server(n.trim())?.id).filter(Boolean) } })),
  'Job.getTargetServers': ([k]) => store.resolveTargets(jobFromKey(k).targets).map((x) => x.name),
  'Job.getJobNameByDBKey': ([k]) => jobFromKey(k).name,

  'JobRun.getLatestJobRunIdByJobKey': ([k]) => latest(jobFromKey(k)).id,
  'JobRun.getLatestJobRunKeyByJobKey': ([k]) => runKey(latest(jobFromKey(k))),
  'JobRun.jobRunKeyToJobRunId': ([k]) => runFromKeyOrId(k).id,
  'JobRun.findRunKeyById': ([id]) => runKey(runFromKeyOrId(id)),
  'JobRun.getJobRunStatusByRunKey': ([k]) => engine.status(runFromKeyOrId(k)),
  'JobRun.getJobRunStatusById': ([id]) => engine.status(runFromKeyOrId(id)),
  'JobRun.getJobRunIsRunningByRunKey': ([k]) => engine.status(runFromKeyOrId(k)) === 'RUNNING',
  'JobRun.getJobRunHadErrors': ([k]) => engine.visibleEvents(runFromKeyOrId(k)).some((e) => e.severity === 'ERROR'),
  'JobRun.getJobRunHadErrorsById': ([id]) => engine.visibleEvents(runFromKeyOrId(id)).some((e) => e.severity === 'ERROR'),
  'JobRun.getLogItemsByJobRunId': ([k, id]) => runTsSince(runFromKeyOrId(id ?? k)),
  'JobRun.getServersStatusByJobRun': ([id]) => Object.entries(runFromKeyOrId(id).results).map(([sid, r]) => `${store.server(sid)?.name}\t${r.status}`),
  'JobRun.abortJobRunById': ([id]) => engine.abortRun(runFromKeyOrId(id), 'abort'),
  'Utility.exportNSHScriptRunByRunKey': ([k]) => runTsSince(runFromKeyOrId(k)),
};

for (const [ns, type] of Object.entries(TYPE_BY_NS)) {
  COMMANDS[`${ns}.getDBKeyByGroupAndName`] = ([g, n]) => jobKey(findJob(g, n, type));
  COMMANDS[`${ns}.executeJobAndWait`] = COMMANDS['Job.execute'];
  COMMANDS[`${ns}.listAllByGroup`] = ([g]) => store.state.jobs.filter((j) => j.group_path === g && (!type || j.type === type)).map((j) => j.name);
}

function latest(j) {
  const runs = store.state.runs.filter((r) => r.job_id === j.id);
  if (!runs.length) throw new CliError(`Job '${j.name}' has no runs`);
  return runs[runs.length - 1];
}

function serverProp(n, p) {
  const s = store.server(n);
  if (!s) throw new CliError(`Server '${n}' does not exist`);
  const map = { NAME: s.name, OS: s.os, OS_RELEASE: s.os_version, AGENT_VERSION: s.agent_version, IP_ADDRESS: s.ip_address, AGENT_STATUS: s.agent_status, ...s.properties };
  if (!(p in map)) throw new CliError(`Property '${p}' does not exist on server '${n}'`);
  return map[p];
}

function result(success, value, error) {
  const v = Array.isArray(value) ? value.join('\n') : value;
  const t = typeof value === 'boolean' ? 'xsd:boolean' : typeof value === 'number' ? 'xsd:long' : 'xsd:string';
  return `<ns2:executeCommandByParamListResponse xmlns:ns2="${NS.cli}"><ns2:return>`
    + '<ns2:attachment xsi:nil="true"/><ns2:comments xsi:nil="true"/>'
    + (error ? `<ns2:error>${xmlEscape(error)}</ns2:error>` : '<ns2:error xsi:nil="true"/>')
    + (success ? `<ns2:returnValue xsi:type="${t}">${xmlEscape(v)}</ns2:returnValue>` : '<ns2:returnValue xsi:nil="true"/>')
    + `<ns2:success>${success}</ns2:success></ns2:return></ns2:executeCommandByParamListResponse>`;
}

function handle(req) {
  if (!req.path.startsWith('/services/')) return null;
  const svc = req.path.split('/')[2] || '';
  if (req.method === 'GET') {
    if ('wsdl' in req.query || 'WSDL' in req.query) return { status: 200, type: 'text/xml', text: wsdl(svc), matched: true };
    return { status: 200, type: 'text/plain', text: `${svc}: mock TSSA BLCLI web service. POST SOAP envelopes here.`, matched: true };
  }
  const xml = req.raw || '';
  const op = (xml.match(/<(?:[\w-]+:)?Body[^>]*>\s*<(?:[\w-]+:)?([\w]+)/) || [])[1];
  if (!op) return { status: 500, type: 'text/xml', text: fault('Malformed SOAP request: no Body operation'), matched: true };

  if (op === 'loginUsingUserCredential' || op === 'loginUsingSessionCredential' || op === 'login') {
    const user = tag(xml, 'userName') || tag(xml, 'username') || 'BLAdmin';
    const { session, error } = store.login(user, tag(xml, 'password'), null);
    if (error) return { status: 500, type: 'text/xml', text: fault(error), matched: true, note: 'BLCLI login failed' };
    return { status: 200, type: 'text/xml', text: envelope(`<ns2:${op}Response xmlns:ns2="${NS.login}"><ns2:returnSessionId>${session.id}</ns2:returnSessionId></ns2:${op}Response>`), matched: true, note: `login ${user}` };
  }

  const sid = tag(xml, 'sessionId');
  let sess = store.getSession(sid);
  if (!sess) {
    if (store.settings.strict_auth) return { status: 500, type: 'text/xml', text: fault('Session is not valid or has expired'), matched: true };
    sess = { id: sid, user: 'BLAdmin', role: 'BLAdmins', roles: ['BLAdmins'] };
  }

  if (op === 'assumeRole') {
    const role = tag(xml, 'roleName') || 'BLAdmins';
    if (store.settings.strict_auth && !sess.roles.includes(role)) return { status: 500, type: 'text/xml', text: fault(`User is not a member of role ${role}`), matched: true };
    const real = store.sessions.get(sess.id);
    if (real) real.role = role;
    return { status: 200, type: 'text/xml', text: envelope(`<ns2:assumeRoleResponse xmlns:ns2="${NS.role}"/>`), matched: true, note: `assumeRole ${role}` };
  }

  if (op === 'logout') return { status: 200, type: 'text/xml', text: envelope(`<ns2:logoutResponse xmlns:ns2="${NS.login}"/>`), matched: true };

  if (op === 'executeCommandByParamList' || op === 'executeCommandUsingAttachments' || op === 'executeCommandByParamString') {
    const ns = tag(xml, 'nameSpace');
    const cmd = tag(xml, 'commandName');
    const args = op === 'executeCommandByParamString'
      ? (tag(xml, 'commandArguments') || '').match(/"[^"]*"|\S+/g)?.map((x) => x.replace(/^"|"$/g, '')) || []
      : tags(xml, 'commandArguments');
    const key = `${ns}.${cmd}`;
    const fn = COMMANDS[key];
    if (!fn) {
      return { status: 200, type: 'text/xml', text: envelope(result(false, null, `Command execution failed. Command ${ns} ${cmd} is not implemented by the mock TSSA server`)), matched: false, note: `BLCLI ${ns} ${cmd} (not implemented)` };
    }
    try {
      const v = fn(args, sess);
      store.saveSoon();
      return { status: 200, type: 'text/xml', text: envelope(result(true, v)), matched: true, note: `BLCLI ${ns} ${cmd} ${args.join(' ')}` };
    } catch (e) {
      if (!(e instanceof CliError)) console.error(e);
      return { status: 200, type: 'text/xml', text: envelope(result(false, null, `Command execution failed. ${e.message}`)), matched: true, note: `BLCLI ${ns} ${cmd} -> error` };
    }
  }
  return { status: 500, type: 'text/xml', text: fault(`Operation ${op} is not supported by the mock TSSA server`), matched: false, note: `SOAP op ${op}` };
}

function wsdl(svc) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" name="${xmlEscape(svc)}" targetNamespace="${svc.includes('Login') ? NS.login : svc.includes('Role') ? NS.role : NS.cli}">
  <wsdl:documentation>Mock TSSA ${xmlEscape(svc)} (abbreviated WSDL)</wsdl:documentation>
</wsdl:definitions>`;
}

const listCommands = () => Object.keys(COMMANDS).sort();

module.exports = { handle, listCommands };
