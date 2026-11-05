'use strict';
// Job execution simulator. A run's whole timeline (events, per-target results,
// final status, side effects) is planned up front; events become visible as
// wall-clock time passes, and side effects apply once the run finishes.
const store = require('./store');
const { live: rnd, fmtBytes } = require('./util');

const SEV_RANK = { Critical: 0, Important: 1, Moderate: 2, Low: 3 };

// --- timeline helper ------------------------------------------------------
class Timeline {
  constructor() { this.events = []; this.t = 0; }
  at(t, severity, server, message) { this.events.push({ at: Math.round(t), severity, server: server || null, message }); return t; }
}

const sec = (a, b = a) => (a + rnd() * (b - a)) * 1000;

function runStatus(results) {
  const vals = Object.values(results);
  const failed = vals.filter((r) => r.status === 'FAILED').length;
  if (!vals.length) return 'COMPLETED';
  if (failed === vals.length) return 'FAILED';
  if (failed) return 'COMPLETED_WITH_ERRORS';
  if (vals.some((r) => r.status === 'COMPLETED_WITH_WARNINGS')) return 'COMPLETED_WITH_WARNINGS';
  return 'COMPLETED';
}

function targetFailure(server) {
  if (server.agent_status !== 'agent is alive') return 'offline';
  return rnd.chance(store.settings.failure_rate) ? 'random' : null;
}

function connect(tl, t, s) {
  tl.at(t, 'INFO', s.name, `Connecting to RSCD agent on ${s.name}:${s.agent_port}`);
  if (s.agent_status !== 'agent is alive') {
    t += sec(20, 30);
    tl.at(t, 'ERROR', s.name, `Unable to connect to ${s.name}:${s.agent_port}: Connection timed out (agent is not responding)`);
    return { t, ok: false };
  }
  t += sec(0.3, 1.2);
  tl.at(t, 'INFO', s.name, `Connected. Agent version ${s.agent_version}, OS ${s.os_version} (${s.architecture})`);
  return { t, ok: true };
}

// --- builders ---------------------------------------------------------------
function buildPatchAnalysis(job, targets, ctx) {
  const tl = new Timeline();
  const cat = store.catalog(job.params.catalog_id);
  const container = cat.containers.find((c) => c.name === job.params.container) || cat.containers[0];
  const results = {};
  let end = 0;
  tl.at(sec(0.5), 'INFO', null, `Patch analysis using catalog '${cat.name}' (container '${container.name}', ${container.patch_ids.length} patches)`);
  if (cat.os !== 'WINDOWS') tl.at(sec(1, 2), 'INFO', null, `Validated catalog repository metadata (last updated ${new Date(cat.last_updated).toUTCString()})`);
  targets.forEach((s, i) => {
    let t = sec(1.5) + i * sec(0.4, 1.2);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1, message: 'Agent not responding', missing_patch_ids: [] }; end = Math.max(end, t); return; }
    if (s.catalog_id !== cat.id && !(cat.os === 'WINDOWS' && s.platform === 'WINDOWS')) {
      tl.at(t += 300, 'WARNING', s.name, `Target OS '${s.os_version}' does not match catalog '${cat.name}'; target skipped`);
      results[s.id] = { status: 'COMPLETED_WITH_WARNINGS', exit_code: 0, message: 'Not applicable', missing_patch_ids: [] };
      end = Math.max(end, t); return;
    }
    const fail = targetFailure(s);
    if (cat.os === 'WINDOWS') {
      t += sec(1, 3); tl.at(t, 'INFO', s.name, 'Copying patch analysis metadata wsusscn2.cab (612.4 MB) from catalog repository to target');
      t += sec(4, 10); tl.at(t, 'INFO', s.name, 'Running offline Windows Update Agent scan (BMC patch analysis engine)');
      if (fail) { t += sec(3, 8); tl.at(t, 'ERROR', s.name, 'Windows Update Agent scan failed: 0x80244022 WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL. Exit code 1'); }
    } else {
      const tool = s.family === 'UBUNTU' ? 'apt-get --simulate upgrade' : s.family === 'SLES' ? 'zypper list-patches' : 'dnf check-update --security';
      t += sec(1, 3); tl.at(t, 'INFO', s.name, `Pushing catalog repository configuration to /etc/${s.family === 'UBUNTU' ? 'apt/sources.list.d' : s.family === 'SLES' ? 'zypp/repos.d' : 'yum.repos.d'}/bmc-patch-catalog.repo`);
      t += sec(3, 8); tl.at(t, 'INFO', s.name, `Running '${tool}' against catalog repository`);
      if (fail) { t += sec(3, 8); tl.at(t, 'ERROR', s.name, 'Failed to download metadata for repo bmc-patch-catalog: Curl error (28): Timeout was reached. Exit code 1'); }
    }
    if (fail) { results[s.id] = { status: 'FAILED', exit_code: 1, message: 'Patch analysis failed', missing_patch_ids: [] }; end = Math.max(end, t); return; }
    t += sec(4, 12);
    const missing = (store.state.missing[s.id] || []).filter((id) => container.patch_ids.includes(id)).map((id) => store.patch(id)).filter(Boolean)
      .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
    const crit = missing.filter((p) => p.severity === 'Critical').length;
    const imp = missing.filter((p) => p.severity === 'Important').length;
    tl.at(t, missing.length ? 'WARNING' : 'INFO', s.name, `Analysis found ${missing.length} missing patch(es) (${crit} Critical, ${imp} Important, ${missing.length - crit - imp} other)`);
    missing.slice(0, 12).forEach((p, k) => tl.at(t + 50 * (k + 1), 'INFO', s.name, `  Missing: ${p.name}  [${p.severity}]  ${p.title}`));
    if (missing.length > 12) tl.at(t + 700, 'INFO', s.name, `  ... and ${missing.length - 12} more`);
    t += 900; tl.at(t, 'INFO', s.name, 'Patch analysis completed on target. Exit code 0');
    results[s.id] = { status: 'COMPLETED', exit_code: 0, missing_patch_ids: missing.map((p) => p.id), missing_count: missing.length, critical: crit, important: imp };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [{ type: 'analysis', catalog_id: cat.id, container: container.name }] };
}

function buildRemediation(job, targets, ctx) {
  // job here is a synthetic deploy job created from a patching job run.
  const tl = new Timeline();
  const results = {};
  let end = 0;
  const reboot = job.params.reboot || 'IF_REQUIRED';
  tl.at(sec(0.5), 'INFO', null, `Remediation deploy job '${job.name}' generated from patch analysis results`);
  targets.forEach((s, i) => {
    const patches = (job.params.patch_map[s.id] || []).map((id) => store.patch(id)).filter(Boolean);
    let t = sec(1) + i * sec(0.5, 1.5);
    if (!patches.length) return;
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1, installed_patch_ids: [] }; end = Math.max(end, t); return; }
    const size = patches.reduce((a, p) => a + p.size, 0);
    tl.at(t += sec(0.5), 'INFO', s.name, `Simulate phase started (${patches.length} item(s))`);
    tl.at(t += sec(2, 4), 'INFO', s.name, 'Simulate phase completed successfully');
    tl.at(t += sec(0.5), 'INFO', s.name, `Stage phase started: transferring ${patches.length} item(s) (${fmtBytes(size)}) to ${s.os === 'Windows' ? 'C:\\Windows\\Temp\\stage' : '/tmp/stage'}`);
    tl.at(t += sec(3, 10), 'INFO', s.name, 'Stage phase completed successfully');
    tl.at(t += sec(0.5), 'INFO', s.name, 'Commit phase started');
    const failAt = targetFailure(s) ? rnd.int(0, patches.length - 1) : -1;
    const installed = [];
    let needsReboot = false;
    for (let k = 0; k < patches.length; k++) {
      const p = patches[k];
      if (k === failAt) {
        t += sec(4, 12);
        tl.at(t, 'ERROR', s.name, s.os === 'Windows'
          ? `Installing ${p.packages[0]} failed: exit code 0x80070643 (ERROR_INSTALL_FAILURE)`
          : `Installing ${p.packages[0]} failed: Transaction check error: file conflicts with package from installed set`);
        tl.at(t += sec(1, 3), 'WARNING', s.name, 'Rolling back committed items for failed transaction');
        tl.at(t += sec(2, 5), 'INFO', s.name, 'Rollback completed');
        break;
      }
      t += sec(3, 9);
      const code = s.os === 'Windows' && p.reboot_required ? 3010 : 0;
      if (p.reboot_required) needsReboot = true;
      tl.at(t, 'INFO', s.name, `Installed ${p.name} (${p.packages[0]}) - exit code ${code}${code === 3010 ? ' (reboot required)' : ''}`);
      installed.push(p.id);
    }
    const failed = installed.length < patches.length;
    if (!failed) tl.at(t += sec(0.5), 'INFO', s.name, 'Commit phase completed successfully');
    if (!failed && (reboot === 'ALWAYS' || (reboot === 'IF_REQUIRED' && needsReboot))) {
      tl.at(t += sec(0.5), 'INFO', s.name, 'Reboot required by committed items. Rebooting server');
      const r = sec(25, 70);
      tl.at(t += r, 'INFO', s.name, `Server rebooted successfully; agent responded after ${Math.round(r / 1000)} s`);
    } else if (!failed && needsReboot) {
      tl.at(t += 200, 'WARNING', s.name, 'Reboot required but suppressed by job option (reboot = NEVER)');
    }
    results[s.id] = { status: failed ? 'FAILED' : 'COMPLETED', exit_code: failed ? 1 : 0, installed_patch_ids: installed, rebooted: !failed && needsReboot && reboot !== 'NEVER' };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [{ type: 'remediation' }] };
}

function scriptOutput(key, s, args) {
  const win = s.os === 'Windows';
  const r = rnd;
  switch (key) {
    case 'disk': return win
      ? ['Name  Used (GB)  Free (GB)  Provider    Root', '----  ---------  ---------  --------    ----', `C        ${(40 + r() * 60).toFixed(2)}      ${(10 + r() * 60).toFixed(2)}  FileSystem  C:\\`, `D       ${(100 + r() * 200).toFixed(2)}     ${(50 + r() * 250).toFixed(2)}  FileSystem  D:\\`]
      : ['Filesystem              Size  Used Avail Use% Mounted on', `/dev/mapper/vg0-root     50G   ${r.int(10, 40)}G   ${r.int(8, 38)}G  ${r.int(20, 85)}% /`, `/dev/sda1              1014M  ${r.int(200, 400)}M  ${r.int(600, 800)}M  ${r.int(20, 40)}% /boot`, `/dev/mapper/vg0-var      30G   ${r.int(5, 26)}G   ${r.int(4, 25)}G  ${r.int(15, 92)}% /var`, `/dev/mapper/vg0-home     20G  ${(r() * 9).toFixed(1)}G   ${r.int(10, 19)}G  ${r.int(2, 45)}% /home`];
    case 'health': {
      const free = (6 + r() * 60).toFixed(1);
      return [`Running pre-patch health check on ${s.short_name}`, `Free space on ${win ? 'C:' : '/'}: ${free} GB (minimum ${args[0] || 5} GB) ... OK`, `Uptime: ${r.int(1, 90)} days ... OK`, `Pending reboot: ${win ? 'No' : 'n/a'} ... OK`, `RSCD agent ${s.agent_version} ... OK`, 'RESULT: PASS'];
    }
    case 'postval': return win
      ? ['Validating critical services', 'W3SVC          Running', 'WinRM          Running', 'RSCDsvc        Running', 'EventLog       Running', 'All critical services are running']
      : ['Validating critical services', 'sshd.service        active (running)', 'rscd.service        active (running)', 'crond.service       active (running)', `${s.short_name.includes('web') ? 'nginx' : 'chronyd'}.service       active (running)`, 'All critical services are running'];
    case 'restart': return win
      ? ['Status   Name               DisplayName', '------   ----               -----------', `Running  ${args[0] || 'W3SVC'}              World Wide Web Publishing Service`]
      : [`Restarted ${args[0] || 'service'}`, 'active'];
    case 'inventory': return [`Hostname: ${s.name}`, `OS: ${s.os_version}`, `Architecture: ${s.architecture}`, `CPUs: ${s.cpu_count}`, `Memory: ${s.memory_mb} MB`, `IP Address: ${s.ip_address}`, `Uptime: ${r.int(1, 90)} days, ${r.int(0, 23)}:${String(r.int(0, 59)).padStart(2, '0')}`];
    case 'reboot': return [r.chance(0.3) ? 'True' : 'False'];
    case 'tmp': return [`Removed ${r.int(80, 4000).toLocaleString()} files (${(r() * 3).toFixed(2)} GB) older than ${args[0] || 7} days from ${win ? 'C:\\Windows\\Temp' : '/tmp and /var/tmp'}`];
    case 'ntp': return win
      ? ['Leap Indicator: 0(no warning)', 'Stratum: 3 (secondary reference - syncd by (S)NTP)', `Last Successful Sync Time: ${new Date().toLocaleString()}`, `Source: dc01.${s.name.split('.').slice(1).join('.')}`, `Phase Offset: 0.00${r.int(10, 99)}s`]
      : ['Reference ID    : 0A140105 (ntp1.mock.lab)', 'Stratum         : 3', `System time     : 0.0000${r.int(10, 99)} seconds fast of NTP time`, 'Leap status     : Normal'];
    case 'yumclean': return s.family === 'UBUNTU' ? ['Reading package lists... Done', 'Cleaned /var/cache/apt/archives'] : [`${r.int(20, 90)} files removed`];
    case 'certs': return [`Checked ${r.int(4, 30)} certificates on ${s.short_name}`, `${r.int(0, 3)} expire within ${args[0] || 30} days`];
    case 'logs': return [`Rotated ${r.int(3, 40)} logs in ${args[0] || '/var/log/app'}`, `Freed ${(r() * 2).toFixed(2)} GB`];
    case 'dns': return ['Windows IP Configuration', 'Successfully flushed the DNS Resolver Cache.'];
    case 'bundle': return [`Collected ${r.int(40, 200)} files`, `Bundle written to ${win ? 'C:\\Temp\\' : '/tmp/'}support-${s.short_name}.zip`];
    default: return ['Script completed'];
  }
}

function buildScript(job, targets) {
  const tl = new Timeline();
  const sc = store.script(job.params.script_id);
  const args = job.params.arguments || [];
  const results = {};
  let end = 0;
  tl.at(sec(0.5), 'INFO', null, `Script '${sc ? sc.name : 'unknown'}' (${sc ? sc.group_path : ''}), type ${sc ? sc.script_type : ''}, arguments [${args.join(', ')}]`);
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.2, 0.8);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1, output: '' }; end = Math.max(end, t); return; }
    if (sc && !sc.platforms.includes(s.platform)) {
      tl.at(t += 300, 'WARNING', s.name, `Script is not applicable to platform ${s.platform}; skipped`);
      results[s.id] = { status: 'COMPLETED_WITH_WARNINGS', exit_code: 0, output: '' }; end = Math.max(end, t); return;
    }
    tl.at(t += sec(0.5, 1.5), 'INFO', s.name, `Executing script '${sc.name}' on ${s.short_name}`);
    const fail = targetFailure(s);
    const out = fail ? [win(s) ? 'Access is denied.' : 'Permission denied'] : scriptOutput(sc.key, s, args);
    t += sec(2, 6);
    out.forEach((line, k) => tl.at(t + k * 40, 'INFO', s.name, line));
    t += out.length * 40 + 200;
    const code = fail ? 1 : 0;
    tl.at(t, fail ? 'ERROR' : 'INFO', s.name, `Script exited with exit code ${code}`);
    results[s.id] = { status: fail ? 'FAILED' : 'COMPLETED', exit_code: code, output: out.join('\n') };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [] };
}
const win = (s) => s.os === 'Windows';

function buildDeploy(job, targets) {
  const tl = new Timeline();
  const pkg = store.blpackage(job.params.package_id);
  const results = {};
  let end = 0;
  tl.at(sec(0.5), 'INFO', null, `Deploying BLPackage '${pkg.name}' (version ${pkg.version}, ${pkg.items.length} item(s)) with phases ${(job.params.phases || ['SIMULATE', 'STAGE', 'COMMIT']).join(', ')}`);
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.3, 1);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1 }; end = Math.max(end, t); return; }
    if (!pkg.platforms.includes(s.platform)) {
      tl.at(t += 300, 'WARNING', s.name, `BLPackage has no items applicable to ${s.platform}; target skipped`);
      results[s.id] = { status: 'COMPLETED_WITH_WARNINGS', exit_code: 0 }; end = Math.max(end, t); return;
    }
    tl.at(t += sec(0.5), 'INFO', s.name, 'Simulate phase started');
    pkg.items.forEach((it) => tl.at(t += sec(0.3, 1), 'INFO', s.name, `  Simulated ${it.action} ${it.type} '${it.path}'`));
    tl.at(t += 300, 'INFO', s.name, 'Simulate phase completed successfully');
    tl.at(t += sec(0.5), 'INFO', s.name, `Stage phase started: transferring ${pkg.items.length} item(s)`);
    tl.at(t += sec(2, 8), 'INFO', s.name, 'Stage phase completed successfully');
    tl.at(t += 300, 'INFO', s.name, 'Commit phase started');
    const failAt = targetFailure(s) ? rnd.int(0, pkg.items.length - 1) : -1;
    let failed = false;
    pkg.items.forEach((it, k) => {
      if (failed) return;
      t += sec(1, 5);
      if (k === failAt) {
        failed = true;
        tl.at(t, 'ERROR', s.name, `Commit failed for ${it.type} '${it.path}': ${it.type === 'SOFTWARE' ? 'exit code 1603 (Fatal error during installation)' : 'Access denied'}`);
        tl.at(t += sec(1, 3), 'WARNING', s.name, 'Undoing committed items');
        tl.at(t += sec(1, 3), 'INFO', s.name, 'Undo completed');
      } else {
        tl.at(t, 'INFO', s.name, `  ${it.action} ${it.type} '${it.path}' ... OK`);
      }
    });
    if (!failed) tl.at(t += 300, 'INFO', s.name, 'Commit phase completed successfully');
    results[s.id] = { status: failed ? 'FAILED' : 'COMPLETED', exit_code: failed ? 1 : 0 };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [] };
}

function buildFileDeploy(job, targets) {
  const tl = new Timeline();
  const f = store.state.depot_files.find((x) => x.id === job.params.file_id) || store.state.depot_files[0];
  const results = {};
  let end = 0;
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.2, 0.6);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1 }; end = Math.max(end, t); return; }
    const dest = win(s) ? 'C:\\ProgramData\\Corp\\certs\\' : '/etc/pki/ca-trust/source/anchors/';
    tl.at(t += sec(0.5, 2), 'INFO', s.name, `Copying '${f.name}' (${fmtBytes(f.size)}) to ${dest}`);
    const fail = targetFailure(s);
    tl.at(t += sec(1, 3), fail ? 'ERROR' : 'INFO', s.name, fail ? `Copy failed: ${dest} : No space left on device` : 'Copied successfully; checksum verified');
    results[s.id] = { status: fail ? 'FAILED' : 'COMPLETED', exit_code: fail ? 1 : 0 };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [] };
}

const RULES = {
  WINDOWS: ['1.1.1 Enforce password history', '2.3.1.1 Accounts: Block Microsoft accounts', '9.1.1 Windows Firewall: Domain: Firewall state', '18.9.19.2 Turn off background refresh of Group Policy', '2.3.11.7 LAN Manager authentication level', '18.3.4 SMB v1 client driver disabled', '17.5.1 Audit Account Lockout'],
  LINUX: ['1.1.2.3 nosuid option set on /tmp', '5.2.8 SSH root login is disabled', '5.2.13 SSH Idle Timeout configured', '3.4.1.1 nftables is installed', '1.6.1.3 SELinux policy is configured', '4.1.3.1 auditd collects sudoers changes', '6.1.10 No world-writable files exist'],
};

function buildCompliance(job, targets) {
  const tl = new Timeline();
  const tpl = store.template(job.params.template_id) || store.state.templates[0];
  const results = {};
  let end = 0;
  tl.at(sec(0.5), 'INFO', null, `Evaluating component template '${tpl.name}' (${tpl.rules} rules)`);
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.3, 1);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1 }; end = Math.max(end, t); return; }
    tl.at(t += sec(1, 2), 'INFO', s.name, `Discovering components for template '${tpl.name}'`);
    tl.at(t += sec(4, 12), 'INFO', s.name, `Evaluating ${tpl.rules} rules`);
    const fixed = s.compliance_fixed?.includes(tpl.id);
    const nonc = fixed ? 0 : rnd.int(0, 18);
    const na = fixed ? 0 : rnd.int(2, 15);
    rnd.sample(RULES[s.platform] || RULES.LINUX, Math.min(nonc, 5)).forEach((rule) => tl.at(t += 120, 'WARNING', s.name, `  Non-compliant: ${rule}`));
    const ok = tpl.rules - nonc - na;
    tl.at(t += 300, nonc ? 'WARNING' : 'INFO', s.name, `Compliance results: ${ok} compliant, ${nonc} non-compliant, ${na} not applicable (score ${Math.round((ok / (tpl.rules - na)) * 100)}%)`);
    results[s.id] = { status: nonc ? 'COMPLETED_WITH_WARNINGS' : 'COMPLETED', exit_code: 0, compliant: ok, non_compliant: nonc, not_applicable: na };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [] };
}

// A remediation job HAC created from compliance results. Only the rules a real job would fix are logged.
function buildComplianceRemediation(job, targets) {
  const tl = new Timeline();
  const { job_run_id: sourceRun, template_id: templateId } = job.params.compliance_remediation;
  const tpl = store.template(templateId) || store.state.templates[0];
  const results = {};
  let end = 0;
  tl.at(sec(0.5), 'INFO', null, `Remediating non-compliant rules of template '${tpl.name}' found by compliance job run ${sourceRun}`);
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.3, 1);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1 }; end = Math.max(end, t); return; }
    (RULES[s.platform] || RULES.LINUX).forEach((rule) => tl.at(t += sec(0.5, 2), 'INFO', s.name, `  Remediated rule: ${rule}`));
    tl.at(t += 300, 'INFO', s.name, 'Remediation completed successfully');
    results[s.id] = { status: 'COMPLETED', exit_code: 0 };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [{ type: 'compliance_remediation', template_id: tpl.id }] };
}

function buildSnapshot(job, targets) {
  const tl = new Timeline();
  const results = {};
  let end = 0;
  targets.forEach((s, i) => {
    let t = sec(1) + i * sec(0.2, 0.6);
    const c = connect(tl, t, s); t = c.t;
    if (!c.ok) { results[s.id] = { status: 'FAILED', exit_code: -1 }; end = Math.max(end, t); return; }
    const n = rnd.int(800, 3500);
    tl.at(t += sec(3, 9), 'INFO', s.name, `Snapshot of ${win(s) ? 'C:\\Windows\\System32\\drivers\\etc, HKLM\\SOFTWARE\\Policies' : '/etc'} captured ${n} objects (${fmtBytes(n * rnd.int(900, 4000))})`);
    results[s.id] = { status: 'COMPLETED', exit_code: 0, objects: n };
    end = Math.max(end, t);
  });
  return { tl, results, end, effects: [] };
}

function buildCatalogUpdate(job) {
  const tl = new Timeline();
  const cat = store.catalog(job.params.catalog_id);
  let t = sec(0.5);
  tl.at(t, 'INFO', null, `Updating patch catalog '${cat.name}' from ${cat.source}`);
  tl.at(t += sec(1, 2), 'INFO', null, `Applying catalog filters: ${JSON.stringify(cat.filters)}`);
  tl.at(t += sec(2, 6), 'INFO', null, cat.os === 'WINDOWS' ? 'Downloading Microsoft update metadata (wsusscn2.cab, 612.4 MB)' : 'Downloading repository metadata (repomd.xml, primary.xml.gz, updateinfo.xml.gz)');
  const entries = rnd.int(900, 4200);
  tl.at(t += sec(4, 12), 'INFO', null, `Processed ${entries.toLocaleString()} metadata entries`);
  // A catalog built from real vendor advisories (tools/fetch-real-content.js) gains no made-up patches:
  // every patch has to carry real CVE ids so HAC can automap vulnerabilities to it.
  const realContent = store.patch(cat.patch_ids[cat.patch_ids.length - 1])?.source;
  const added = realContent ? 0 : rnd.int(1, 4);
  tl.at(t += sec(1, 3), 'INFO', null, added ? `Found ${added} new patch(es) matching catalog filters` : 'Catalog is up to date; no new patches matching catalog filters');
  tl.at(t += sec(3, 10), 'INFO', null, `Downloaded payloads for ${added} patch(es) to catalog repository`);
  tl.at(t += 500, 'INFO', null, `Catalog '${cat.name}' updated successfully`);
  return { tl, results: {}, end: t, effects: [{ type: 'catalog_update', catalog_id: cat.id, added }], noTargets: true };
}

const BUILDERS = {
  PATCHING_JOB: buildPatchAnalysis,
  NSH_SCRIPT_JOB: buildScript,
  DEPLOY_JOB: (job, targets, ctx) => {
    if (job.params.compliance_remediation) return buildComplianceRemediation(job, targets);
    return job.params.patch_map ? buildRemediation(job, targets, ctx) : buildDeploy(job, targets, ctx);
  },
  FILE_DEPLOY_JOB: buildFileDeploy,
  COMPLIANCE_JOB: buildCompliance,
  SNAPSHOT_JOB: buildSnapshot,
  CATALOG_UPDATE_JOB: buildCatalogUpdate,
};

// --- run lifecycle ---------------------------------------------------------
function startRun(job, opts = {}) {
  const now = Date.now();
  const startAt = opts.startAt ?? now;
  const speed = store.settings.speed || 1;
  const targets = opts.targets ? store.resolveTargets(opts.targets) : store.resolveTargets(job.targets);
  const run = {
    id: store.nextId(), job_id: job.id, job_name: job.name, job_type: job.type, job_group_path: job.group_path,
    parent_run_id: opts.parentRunId || null, child_run_ids: [],
    executed_by: opts.user || 'BLAdmin', role: opts.role || 'BLAdmins',
    start_time: startAt, end_time: null, target_ids: targets.map((s) => s.id),
    events: [], results: {}, final_status: null, finalized: false, aborted_at: null, effects: [],
    app_server: store.settings.app_server_name,
  };
  store.state.runs.push(run);

  const header = new Timeline();
  header.at(0, 'INFO', null, `Started running the job '${job.name}' with priority 'NORMAL' on application server '${store.settings.app_server_name}'.`);
  header.at(150, 'INFO', null, `Job run ${run.id} initiated by ${run.executed_by} using role ${run.role}`);
  if (job.type !== 'CATALOG_UPDATE_JOB') header.at(300, 'INFO', null, `Executing against ${targets.length} target(s): ${targets.slice(0, 8).map((s) => s.short_name).join(', ')}${targets.length > 8 ? ', ...' : ''}`);

  let events = [];
  let results = {};
  let end = 400;
  let effects = [];
  const pushPlan = (plan, offset) => {
    plan.tl.events.forEach((e) => events.push({ ...e, at: offset + e.at / speed }));
    return offset + plan.end / speed;
  };

  if (job.type === 'BATCH_JOB') {
    let off = 600;
    for (const cid of job.params.child_job_ids || []) {
      const child = store.job(cid);
      if (!child) continue;
      events.push({ at: off, severity: 'INFO', server: null, message: `Starting member job '${child.name}' (${child.type})` });
      const cr = startRun(child, { ...opts, startAt: startAt + off, parentRunId: run.id, targets: opts.targets || job.targets });
      run.child_run_ids.push(cr.id);
      off = cr.end_time - startAt + 500;
      events.push({ at: off, severity: cr.final_status === 'COMPLETED' ? 'INFO' : cr.final_status === 'FAILED' ? 'ERROR' : 'WARNING', server: null, message: `Member job '${child.name}' finished with status ${cr.final_status} (run ${cr.id})` });
      for (const [sid, r] of Object.entries(cr.results)) {
        const prev = results[sid];
        if (!prev || prev.status !== 'FAILED') results[sid] = { status: r.status, exit_code: r.exit_code };
      }
      if (cr.final_status === 'FAILED' && job.params.stop_on_failure) {
        events.push({ at: off + 100, severity: 'ERROR', server: null, message: 'Stopping batch job because a member job failed' });
        break;
      }
    }
    end = off + 300;
  } else {
    const plan = BUILDERS[job.type](job, targets, { run });
    end = pushPlan(plan, 400);
    results = plan.results;
    effects = plan.effects;

    // Patching job with remediation: spawn the generated deploy job after analysis.
    if (job.type === 'PATCHING_JOB' && job.params.remediate) {
      const patchMap = {};
      for (const [sid, r] of Object.entries(results)) if (r.status === 'COMPLETED' && r.missing_patch_ids?.length) patchMap[sid] = r.missing_patch_ids;
      const remTargets = Object.keys(patchMap).map(Number);
      if (remTargets.length) {
        const remJob = {
          id: store.nextId(), name: `${job.name} - Remediation Deploy ${new Date(startAt).toISOString().slice(0, 16).replace('T', ' ')}`,
          type: 'DEPLOY_JOB', group_path: `${job.group_path}/Remediation`, description: `Generated by patching job '${job.name}'`,
          created_by: run.executed_by, date_created: startAt, last_modified: startAt, schedules: [],
          targets: { server_ids: remTargets, group_ids: [] }, generated: true,
          params: { patch_map: patchMap, reboot: job.params.reboot, phases: ['SIMULATE', 'STAGE', 'COMMIT'] },
        };
        store.state.jobs.push(remJob);
        events.push({ at: end + 300, severity: 'INFO', server: null, message: `Analysis complete. Creating remediation BLPackage and deploy job '${remJob.name}' for ${remTargets.length} target(s)` });
        const cr = startRun(remJob, { ...opts, startAt: startAt + end + 1500, parentRunId: run.id, targets: remJob.targets });
        run.child_run_ids.push(cr.id);
        end = cr.end_time - startAt + 300;
        events.push({ at: end, severity: cr.final_status === 'COMPLETED' ? 'INFO' : 'WARNING', server: null, message: `Remediation deploy job finished with status ${cr.final_status} (run ${cr.id})` });
        for (const [sid, r] of Object.entries(cr.results)) {
          if (r.status === 'FAILED') results[sid] = { ...results[sid], status: 'FAILED', remediation: 'FAILED' };
          else results[sid] = { ...results[sid], remediation: 'COMPLETED', installed_patch_ids: r.installed_patch_ids };
        }
      } else {
        events.push({ at: end + 300, severity: 'INFO', server: null, message: 'No missing patches found on any target; remediation not required' });
        end += 400;
      }
    }
  }

  const final = targets.length || job.type === 'CATALOG_UPDATE_JOB' ? runStatus(results) : 'COMPLETED';
  const counts = Object.values(results).reduce((a, r) => { a[r.status] = (a[r.status] || 0) + 1; return a; }, {});
  end += 400;
  const footer = final === 'COMPLETED'
    ? `Job '${job.name}' completed successfully.`
    : `Job '${job.name}' completed with status ${final}: ${counts.FAILED || 0} target(s) failed, ${(counts.COMPLETED || 0) + (counts.COMPLETED_WITH_WARNINGS || 0)} succeeded.`;
  if (!targets.length && job.type !== 'CATALOG_UPDATE_JOB') events.push({ at: 500, severity: 'WARNING', server: null, message: 'Job has no valid targets' });
  events.push({ at: end, severity: final === 'COMPLETED' ? 'INFO' : final === 'FAILED' ? 'ERROR' : 'WARNING', server: null, message: footer });

  let evId = 0;
  run.events = [...header.events, ...events]
    .sort((a, b) => a.at - b.at)
    .map((e) => ({ id: ++evId, time: Math.round(startAt + e.at), severity: e.severity, server: e.server, message: e.message }));
  run.results = results;
  run.final_status = final;
  run.effects = effects;
  run.end_time = Math.round(startAt + end);
  if (!opts.parentRunId) {
    run.notifications = opts.notifications || null;
    run.schedule_id = opts.scheduleId || null;
  }
  store.emit('run-started', run);
  materialize(run);
  store.saveSoon();
  return run;
}

function status(run, now = Date.now()) {
  if (run.aborted_at) return run.abort_status;
  if (now < run.start_time) return 'NOT_STARTED';
  if (now < run.end_time) return 'RUNNING';
  return run.final_status;
}

function visibleEvents(run, now = Date.now()) {
  const limit = run.aborted_at ? Math.min(run.aborted_at, now) : now;
  const ev = run.events.filter((e) => e.time <= limit);
  if (run.aborted_at && run.abort_event) ev.push(run.abort_event);
  return ev;
}

function progress(run, now = Date.now()) {
  if (run.aborted_at || now >= run.end_time) return 100;
  if (now < run.start_time) return 0;
  return Math.floor(((now - run.start_time) / (run.end_time - run.start_time)) * 100);
}

function materialize(run, now = Date.now()) {
  if (run.finalized || run.aborted_at || now < run.end_time) return;
  run.finalized = true;
  for (const eff of run.effects || []) applyEffect(run, eff);
  store.emit('run-finished', run);
  store.saveSoon();
}

function applyEffect(run, eff) {
  const st = store.state;
  if (eff.type === 'analysis') {
    for (const [sid, r] of Object.entries(run.results)) {
      const s = store.server(sid);
      if (s && r.status === 'COMPLETED') s.last_analysis = { run_id: run.id, time: run.end_time, missing_patch_ids: r.missing_patch_ids, catalog_id: eff.catalog_id };
    }
  } else if (eff.type === 'remediation') {
    for (const [sid, r] of Object.entries(run.results)) {
      const set = new Set(r.installed_patch_ids || []);
      st.missing[sid] = (st.missing[sid] || []).filter((id) => !set.has(id));
      const s = store.server(sid);
      if (s && r.rebooted) s.last_reboot = run.end_time;
      if (s && s.last_analysis) s.last_analysis.missing_patch_ids = s.last_analysis.missing_patch_ids.filter((id) => !set.has(id));
    }
  } else if (eff.type === 'compliance_remediation') {
    for (const [sid, r] of Object.entries(run.results)) {
      const s = store.server(sid);
      if (s && r.status === 'COMPLETED') s.compliance_fixed = [...new Set([...(s.compliance_fixed || []), eff.template_id])];
    }
  } else if (eff.type === 'catalog_update') {
    const cat = store.catalog(eff.catalog_id);
    const sample = store.patch(cat.patch_ids[cat.patch_ids.length - 1]);
    for (let i = 0; i < eff.added; i++) {
      const id = store.nextId();
      const name = cat.os === 'WINDOWS' ? `KB${5070000 + (id % 9000)}` : sample.name.replace(/\d+(?=(-1)?$)/, (m) => String(Number(m) + i + 7));
      const severity = rnd.pick(['Critical', 'Important', 'Moderate']);
      const title = cat.os === 'WINDOWS'
        ? `${new Date().toISOString().slice(0, 7)} ${sample.title.replace(/^\d{4}-\d{2} /, '').replace(/\(KB\d+\)/, `(${name})`)}`
        : `${severity}: ${sample.product} security update`;
      const packages = cat.os === 'WINDOWS' ? [`windows10.0-${name.toLowerCase()}-x64.msu`] : sample.packages.map((pk) => pk.replace(/-(\d+)\./, (m, n) => `-${Number(n) + 1}.`));
      const p = { ...sample, id, name, bulletin_id: name, title, packages, release_date: Date.now() - 86400000, severity, cves: [`CVE-2026-${rnd.int(60000, 69999)}`] };
      st.patches.push(p);
      cat.patch_ids.push(p.id);
      cat.containers[0].patch_ids.push(p.id);
      if (['Critical', 'Important'].includes(p.severity)) cat.containers[1].patch_ids.push(p.id);
      for (const s of st.servers.filter((x) => x.catalog_id === cat.id)) if (rnd.chance(0.6)) st.missing[s.id] = [...(st.missing[s.id] || []), p.id];
    }
    cat.last_updated = run.end_time;
    cat.update_status = 'COMPLETED';
  }
}

function abortRun(run, mode = 'abort') {
  const now = Date.now();
  if (status(run, now) !== 'RUNNING' && status(run, now) !== 'NOT_STARTED') return false;
  run.aborted_at = now;
  run.abort_status = mode === 'cancel' ? 'CANCELLED' : 'ABORTED';
  run.abort_event = { id: run.events.length + 1, time: now, severity: 'WARNING', server: null, message: `Job run ${mode === 'cancel' ? 'cancelled' : 'aborted'} by user request. Targets in progress were stopped.` };
  run.finalized = true;
  for (const cid of run.child_run_ids) { const c = store.run(cid); if (c) abortRun(c, mode); }
  store.emit('run-finished', run);
  store.saveSoon();
  return true;
}

function catalogUpdate(cat, opts = {}) {
  let job = store.state.jobs.find((j) => j.type === 'CATALOG_UPDATE_JOB' && j.params.catalog_id === cat.id);
  if (!job) {
    job = {
      id: store.nextId(), name: `Catalog Update - ${cat.name}`, type: 'CATALOG_UPDATE_JOB', group_path: cat.group_path,
      description: `Updates patch catalog '${cat.name}'`, created_by: 'BLAdmin', date_created: Date.now(), last_modified: Date.now(),
      schedules: [], targets: { server_ids: [], group_ids: [] }, params: { catalog_id: cat.id },
    };
    store.state.jobs.push(job);
  }
  cat.update_status = 'RUNNING';
  return startRun(job, opts);
}

// Epoch ms of a wall-clock "YYYY-MM-DD HH:mm:ss" in a timezone.
function zonedTime(datetime, timeZone = 'UTC') {
  const utc = Date.parse(`${String(datetime).replace(' ', 'T')}Z`);
  try {
    const f = new Intl.DateTimeFormat('en-US', { timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const p = Object.fromEntries(f.formatToParts(utc).map((x) => [x.type, x.value]));
    return utc - (Date.parse(`${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}Z`) - utc);
  } catch {
    return utc;
  }
}

// Starts one-time schedules that are due. HAC's Execute Now on an operation doesn't run the job: it
// saves { once: { datetime }, timezone, notifications } on it and expects the server to run it then.
function runDueSchedules() {
  const now = Date.now();
  for (const job of store.state.jobs) {
    for (const s of job.schedules || []) {
      if (s.fired || !s.once?.datetime || zonedTime(s.once.datetime, s.timezone) > now) continue;
      s.fired = true;
      startRun(job, { scheduleId: s.id, notifications: s.notifications || job.notifications });
    }
  }
  // An execution task runs its job against the task's own targets.
  for (const t of store.state.tasks || []) {
    const job = store.job(t.job_id);
    for (const s of t.schedules || []) {
      if (!job || s.fired || !s.once?.datetime || zonedTime(s.once.datetime, s.timezone) > now) continue;
      s.fired = true;
      startRun(job, { scheduleId: s.id, targets: t.targets || undefined, notifications: s.notifications });
    }
  }
}

function tick() {
  runDueSchedules();
  const now = Date.now();
  for (const r of store.state.runs) if (!r.finalized) materialize(r, now);
}

module.exports = { startRun, status, visibleEvents, progress, materialize, abortRun, catalogUpdate, tick, RULES };
