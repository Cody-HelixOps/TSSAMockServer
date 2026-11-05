// HAC Auto-Sync. Paste this into the browser console of a signed-in HAC tab.
//
// HAC only accepts Sync from a browser sign-in, and its page security policy stops this tab from
// calling the mock, so nothing can say "a run has finished". This calls Sync on a timer instead.
// A Sync with nothing new costs one GET jobruns on the mock.
(() => {
  const EVERY_MS = 30000;
  const RUN_FOR_HOURS = 8;   // so a forgotten tab doesn't keep calling a shared tenant
  const SECURITY_GROUP = 'Administrator';
  const API = '/automation-console/ui/api';

  window.mockAutoSync?.stop();

  const headers = { 'Content-Type': 'application/json', Accept: 'application/json', 'hac-context': 'TSSA', 'X-SECURITY-GROUP': SECURITY_GROUP };
  const stopAt = Date.now() + RUN_FOR_HOURS * 3600000;
  let timer = null;
  let stopped = false;

  const box = document.createElement('div');
  box.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:99999;display:flex;gap:10px;align-items:center;max-width:420px;padding:8px 12px;border-radius:6px;background:#1f2633;color:#fff;font:13px/1.4 system-ui,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.35)';
  const label = document.createElement('span');
  const stopButton = document.createElement('button');
  stopButton.textContent = 'Stop';
  stopButton.style.cssText = 'flex:none;padding:2px 8px;border:0;border-radius:4px;background:#fff;color:#1f2633;font:inherit;cursor:pointer';
  box.append(label, stopButton);
  document.body.append(box);

  const show = (message) => { label.textContent = `Auto-Sync: ${message}`; };

  function stop(message) {
    stopped = true;
    clearTimeout(timer);
    if (message) show(message);
    else box.remove();
  }
  stopButton.addEventListener('click', () => stop());
  window.mockAutoSync = { stop };

  const call = (method, path, body) => fetch(`${API}${path}`, { method, credentials: 'include', headers, body });

  async function list(method, path, body) {
    const res = await call(method, path, body);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  // Only patch and compliance scan policies and patching operations with a TSSA job. Others on the tenant
  // have nothing to sync from the mock, and some are waiting on change requests. Compliance jobs keep the
  // policy's own name; patch jobs get a TS_ prefix.
  const hasTssaJob = (p) => String(p.bsa_policy?.name || '').startsWith('TS_');
  // Ad hoc operations only while they're unfinished: older ones can point at jobs the mock doesn't have.
  const isMockOperation = (o) => hasTssaJob(o) && (['PATCHING', 'COMPLIANCE'].includes(o.policy_subtype)
    || (['NSH', 'DEPLOY', 'BATCH'].includes(o.policy_subtype) && !['SUCCESS', 'FAILED'].includes(o.status)));

  async function findTargets() {
    const [found, policies] = await Promise.all([
      list('POST', '/v1/policies/operations/search?page=0&size=500', '{}'),
      list('GET', '/v1/policies/search'),
    ]);
    return [
      ...policies.filter((p) => p.policy_type === 'scan' && hasTssaJob(p))
        .map((p) => ({ name: p.policy_name, path: `/v2/policies/patch-policies/${p.policy_id}/sync` })),
      ...policies.filter((p) => p.policy_type === 'compliance_scan' && p.connector_type === 'tssa')
        .map((p) => ({ name: p.policy_name, path: `/v2/policies/compliance-scans/${p.policy_id}/sync` })),
      ...(found.operations || []).filter(isMockOperation)
        .map((o) => ({ name: o.policy_name, path: `/v1/policies/operations/${o.policy_id}/sync` })),
    ];
  }

  async function cycle() {
    try {
      const targets = await findTargets();
      const failed = [];
      for (const target of targets) {
        if (stopped) return;
        const res = await call('POST', target.path, '{}');
        if (!res.ok) failed.push(`${target.name} (HTTP ${res.status})`);
      }
      const time = new Date().toLocaleTimeString();
      show(failed.length
        ? `${targets.length - failed.length} of ${targets.length} synced at ${time}. Failed: ${failed.join(', ')}`
        : `${targets.length} synced at ${time}`);
    } catch (e) {
      show(`can't read HAC's policies (${e.message}). If your session expired, reload HAC and paste this script again.`);
    }
    if (stopped) return;
    if (Date.now() > stopAt) stop(`stopped after ${RUN_FOR_HOURS} hours. Paste the script to start it again.`);
    else timer = setTimeout(cycle, EVERY_MS);
  }

  show('starting');
  cycle();
})();
