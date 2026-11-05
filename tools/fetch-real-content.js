#!/usr/bin/env node
'use strict';
// Builds data/real-content.json: real vendor advisories with their real CVE ids, so the mock's patch
// catalogs can be matched to scanner findings (HAC automaps vulnerabilities to patches by CVE).
//
//   node tools/fetch-real-content.js [--months 4] [--per-family 40]
//
// Sources (public, no sign-in):
//   Windows  Microsoft MSRC CVRF API        KB updates per month with their CVEs
//   RHEL 8/9 Red Hat Security Data API      RHSA advisories, CVEs and fixed packages
//   OL 8     derived from the RHEL 8 RHSAs  Oracle's ELSA errata reuse the RHSA number and CVEs
//   Ubuntu   Ubuntu security notices        USNs for 22.04 (jammy) with CVEs and package versions
//   SUSE     SUSE CSAF advisories           SUSE-SU updates for SLES 15 SP5
const https = require('https');
const fs = require('fs');
const path = require('path');

const arg = (name, dflt) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? Number(process.argv[i + 1]) : dflt; };
const MONTHS = arg('months', 4);
const PER_FAMILY = arg('per-family', 40);
const OUT = path.join(__dirname, '..', 'data', 'real-content.json');
const SEV_RANK = { critical: 4, important: 3, high: 3, moderate: 2, medium: 2, low: 1, negligible: 0, none: 0 };
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : 'Moderate');
const maxSev = (list) => cap(list.reduce((a, s) => ((SEV_RANK[String(s).toLowerCase()] ?? 0) > (SEV_RANK[a.toLowerCase()] ?? 0) ? String(s) : a), 'low'));

function get(url, { json = true, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'mock-tssa-content/1.0', Accept: json ? 'application/json' : '*/*', ...headers } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) return resolve(get(new URL(res.headers.location, url).href, { json, headers }));
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { body += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`${res.statusCode} ${url}`));
        try { resolve(json ? JSON.parse(body) : body); } catch (e) { reject(new Error(`bad JSON from ${url}: ${e.message}`)); }
      });
    });
    req.setTimeout(120000, () => req.destroy(new Error(`timeout ${url}`)));
    req.on('error', reject);
  });
}

// --- Windows: MSRC CVRF ----------------------------------------------------------
const WIN_PRODUCTS = [
  [/^Windows Server 2016( \(Server Core installation\))?$/, 'Windows Server 2016'],
  [/^Windows Server 2019( \(Server Core installation\))?$/, 'Windows Server 2019'],
  [/^Windows Server 2022( \(Server Core installation\))?$/, 'Windows Server 2022'],
  [/^Windows Server 2025( \(Server Core installation\))?$/, 'Windows Server 2025'],
  [/^Microsoft \.NET Framework .* on Windows Server 20(16|19|22|25)/, '.NET Framework'],
  [/^Microsoft SQL Server 2019 for x64-based Systems/, 'SQL Server 2019'],
  [/^Microsoft Exchange Server 2019 Cumulative Update/, 'Exchange Server 2019'],
  [/^Microsoft Exchange Server 2016 Cumulative Update/, 'Exchange Server 2016'],
  [/^Microsoft SharePoint Server Subscription Edition/, 'SharePoint Server Subscription Edition'],
  [/^Microsoft SharePoint Server 2019/, 'SharePoint Server 2019'],
  [/^Microsoft Office LTSC 2021 for 64-bit/, 'Office LTSC 2021'],
  [/^Microsoft Office 2019 for 64-bit/, 'Office 2019'],
  [/^Microsoft Office 2016 \(64-bit/, 'Office 2016'],
  [/^Microsoft Outlook 2016 \(64-bit/, 'Outlook 2016'],
];

let msrcUpdates;
const msrcList = async () => (msrcUpdates ||= (await get('https://api.msrc.microsoft.com/cvrf/v3.0/updates')).value
  .filter((u) => /^\d{4}-[A-Z][a-z]{2}$/.test(u.ID) && Date.parse(u.InitialReleaseDate) <= Date.now()));

async function windows() {
  const list = (await msrcList()).sort((a, b) => Date.parse(b.InitialReleaseDate) - Date.parse(a.InitialReleaseDate)).slice(0, MONTHS);
  const out = (await msrcMonths(list)).flat();
  // Keep the biggest update per product per month (the cumulative ones), then the rest by CVE count.
  out.sort((a, b) => b.cves.length - a.cves.length);
  const seen = new Set();
  const main = out.filter((p) => { const k = `${p.product}|${p.bulletin_id}`; if (seen.has(k)) return false; seen.add(k); return true; });
  const rest = out.filter((p) => !main.includes(p));
  return [...main, ...rest].slice(0, PER_FAMILY * 2).sort((a, b) => Date.parse(a.release_date) - Date.parse(b.release_date));
}

const msrcCache = new Map();
async function msrcMonths(list) {
  const res = [];
  for (const u of [...list].sort((a, b) => Date.parse(a.InitialReleaseDate) - Date.parse(b.InitialReleaseDate))) {
    if (!msrcCache.has(u.ID)) { process.stdout.write(`  MSRC ${u.ID}\n`); msrcCache.set(u.ID, await msrcMonth(u)); }
    res.push(msrcCache.get(u.ID));
  }
  return res;
}

async function msrcMonth(u) {
  const out = [];
  {
    const doc = await get(u.CvrfUrl);
    const names = new Map();
    const walk = (b) => { for (const p of b?.FullProductName || []) names.set(p.ProductID, p.Value); for (const x of b?.Branch || []) walk(x); };
    walk(doc.ProductTree);
    for (const p of doc.ProductTree?.FullProductName || []) names.set(p.ProductID, p.Value);
    const kbs = new Map();
    for (const v of doc.Vulnerability || []) {
      const sevByProduct = new Map();
      for (const t of v.Threats || []) if (t.Type === 3) for (const pid of t.ProductID || []) sevByProduct.set(pid, t.Description?.Value);
      for (const r of v.Remediations || []) {
        if (r.Type !== 2 || !/^\d{6,8}$/.test(r.Description?.Value || '')) continue;
        for (const pid of r.ProductID || []) {
          const product = WIN_PRODUCTS.find(([re]) => re.test(names.get(pid) || ''))?.[1];
          if (!product) continue;
          const kb = r.Description.Value;
          const k = kbs.get(kb) || { kb, products: new Map(), cves: new Set(), sev: [], restart: false, subtype: r.SubType };
          k.products.set(product, (k.products.get(product) || 0) + 1);
          k.cves.add(v.CVE);
          k.sev.push(sevByProduct.get(pid) || 'Important');
          if (/yes/i.test(r.RestartRequired?.Value || '')) k.restart = true;
          kbs.set(kb, k);
        }
      }
    }
    const month = new Date(u.InitialReleaseDate);
    const ym = `${month.getUTCFullYear()}-${String(month.getUTCMonth() + 1).padStart(2, '0')}`;
    for (const k of kbs.values()) {
      const product = [...k.products.entries()].sort((a, b) => b[1] - a[1])[0][0];
      const os = product.startsWith('Windows Server');
      out.push({
        name: `KB${k.kb}`, product, bulletin_id: `MS${ym.slice(2, 4)}-${u.ID.slice(5).toUpperCase()}`,
        title: os ? `${ym} Cumulative Update for ${product} for x64-based Systems (KB${k.kb})` : `${ym} Security Update for ${product} (KB${k.kb})`,
        severity: maxSev(k.sev), classification: 'Security Updates', release_date: u.InitialReleaseDate,
        reboot_required: k.restart || os, cves: [...k.cves].sort(), packages: [`windows10.0-kb${k.kb}-x64.msu`],
        source: `https://msrc.microsoft.com/update-guide/releaseNote/${u.ID}`,
      });
    }
  }
  return out;
}

// --- Red Hat: security data API --------------------------------------------------------------
async function redhat(major) {
  const after = new Date(Date.now() - MONTHS * 31 * 86400000).toISOString().slice(0, 10);
  const product = encodeURIComponent(`Red Hat Enterprise Linux ${major}`);
  const cves = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await get(`https://access.redhat.com/hydra/rest/securitydata/cve.json?product=${product}&after=${after}&per_page=500&page=${page}`);
    cves.push(...batch);
    if (batch.length < 500) break;
  }
  process.stdout.write(`  Red Hat ${major}: ${cves.length} CVEs\n`);
  const tag = new RegExp(`\\.el${major}(_\\d+)?(\\.|$)`);
  const adv = new Map();
  for (const c of cves) {
    const pkgs = (c.affected_packages || []).filter((p) => tag.test(p));
    for (const a of c.advisories || []) {
      if (!/^RH[SB]A-/.test(a)) continue;
      const e = adv.get(a) || { advisory: a, cves: new Set(), sev: [], pkgs: new Set(), dates: [] };
      e.cves.add(c.CVE);
      e.sev.push(c.severity);
      pkgs.forEach((p) => e.pkgs.add(p));
      e.dates.push(c.public_date);
      adv.set(a, e);
    }
  }
  return [...adv.values()].filter((e) => e.pkgs.size).map((e) => {
    // "libxml2-0:2.9.13-12.el9_6" -> libxml2-2.9.13-12.el9_6.x86_64.rpm
    const files = [...e.pkgs].map((p) => `${p.replace(/-\d+:/, '-')}.x86_64.rpm`);
    const pkg = [...e.pkgs][0].replace(/-\d+:.*$/, '');
    const sev = maxSev(e.sev);
    return {
      name: e.advisory, product: pkg, bulletin_id: e.advisory, title: `${sev}: ${pkg} security update`,
      severity: sev, classification: 'Security Advisory', release_date: e.dates.sort().slice(-1)[0],
      reboot_required: /^(kernel|glibc|systemd)$/.test(pkg), cves: [...e.cves].sort(), packages: files.slice(0, 6),
      source: `https://access.redhat.com/errata/${e.advisory}`,
    };
  }).sort((a, b) => Date.parse(b.release_date) - Date.parse(a.release_date)).slice(0, PER_FAMILY).reverse();
}

// Oracle Linux publishes each RHEL rebuild as ELSA-YYYY-NNNN with the RHSA's number and CVEs.
const oracleFrom = (rhel8) => rhel8.filter((p) => p.name.startsWith('RHSA-')).map((p) => {
  const elsa = p.name.replace(/^RHSA-(\d{4}):(\d+)$/, 'ELSA-$1-$2');
  return { ...p, name: elsa, bulletin_id: elsa, source: `https://linux.oracle.com/errata/${elsa}.html` };
});

// --- Ubuntu: security notices ------------------------------------------------------------------
async function ubuntu() {
  const out = [];
  for (let offset = 0; out.length < PER_FAMILY && offset < 400; offset += 20) {
    const { notices } = await get(`https://ubuntu.com/security/notices.json?release=jammy&limit=20&offset=${offset}`);
    for (const n of notices) {
      const pkgs = (n.release_packages?.jammy || []).filter((p) => !p.is_source);
      const src = (n.release_packages?.jammy || []).find((p) => p.is_source);
      const cves = n.cves_ids || (n.cves || []).map((c) => c.id || c);
      if (!pkgs.length || !cves.length) continue;
      const prio = (n.cves || []).map((c) => c.priority).filter(Boolean);
      const sev = maxSev(prio.length ? prio : ['medium']);
      out.push({
        name: n.id, product: src?.name || pkgs[0].name, bulletin_id: n.id, title: `${sev}: ${n.title}`,
        severity: sev, classification: 'Security Advisory', release_date: `${n.published.slice(0, 19)}Z`,
        reboot_required: /linux/.test(src?.name || ''), cves: [...new Set(cves)].sort(),
        packages: pkgs.slice(0, 6).map((p) => `${p.name}_${p.version}_amd64.deb`), source: `https://ubuntu.com/security/notices/${n.id}`,
      });
    }
  }
  process.stdout.write(`  Ubuntu 22.04: ${out.length} USNs\n`);
  return out.slice(0, PER_FAMILY).reverse();
}

// --- SUSE: CSAF advisories ----------------------------------------------------------------------
async function suse() {
  const base = 'https://ftp.suse.com/pub/projects/security/csaf/';
  const year = new Date().getUTCFullYear();
  const files = (await get(`${base}changes.csv`, { json: false })).split('\n')
    .map((l) => l.split(',').map((x) => x.replace(/"/g, '')))
    .filter(([f, t]) => new RegExp(`^suse-su-(${year}|${year - 1})_`).test(f || '') && t)
    .sort((a, b) => b[1].localeCompare(a[1])).map(([f]) => f);
  const out = [];
  for (const f of [...new Set(files)].slice(0, 300)) {
    if (out.length >= PER_FAMILY) break;
    let doc;
    try { doc = await get(base + f); } catch { continue; }
    const products = JSON.stringify(doc.product_tree || {});
    if (!/Server[^"]*15 SP5/.test(products)) continue;
    const cves = (doc.vulnerabilities || []).map((v) => v.cve).filter(Boolean);
    if (!cves.length) continue;
    const rpms = [...new Set((products.match(/"name":"([a-zA-Z0-9_.+-]+-[^-"]+-[^-"]+\.x86_64)"/g) || []).map((m) => m.slice(8, -1)))];
    const id = doc.document?.tracking?.id || f.replace(/^suse-su-(\d{4})_(\d+)-(\d)\.json$/, 'SUSE-SU-$1:$2-$3');
    const sev = maxSev([doc.document?.aggregate_severity?.text || 'moderate']);
    const pkg = (doc.document?.title || '').replace(/^Security update for /i, '').split(/[ ,]/)[0] || 'package';
    out.push({
      name: id, product: pkg, bulletin_id: id, title: `${sev}: ${doc.document?.title || id}`, severity: sev,
      classification: 'Security Advisory', release_date: doc.document?.tracking?.initial_release_date || new Date().toISOString(),
      reboot_required: /kernel/.test(pkg), cves: [...new Set(cves)].sort(), packages: rpms.slice(0, 6).map((r) => `${r}.rpm`),
      source: `https://www.suse.com/support/update/announcement/${id.toLowerCase()}/`,
    });
  }
  process.stdout.write(`  SUSE 15 SP5: ${out.length} advisories\n`);
  return out.reverse();
}

// --- Targeted: real fixes for the CVEs HAC already holds --------------------------------------
// Microsoft bulletins older than the MSRC CVRF API (2016+).
const LEGACY_MS = {
  'CVE-2008-4250': { kb: '958644', bulletin: 'MS08-067', title: 'MS08-067: Vulnerability in Server Service Could Allow Remote Code Execution', date: '2008-10-23T17:00:00Z' },
  'CVE-2013-3900': { kb: '2893294', bulletin: 'MS13-098', title: 'MS13-098: Vulnerability in Windows Could Allow Remote Code Execution (WinVerifyTrust)', date: '2013-12-10T17:00:00Z' },
};
// Third-party Windows applications (the TSSA Windows catalog carries these through its Ivanti/Shavlik
// content). Fixed versions and vendor bulletins are the ones named in the scanner findings.
const THIRD_PARTY = [
  { cat: 'Java', match: /January 2024 CPU/, product: 'Oracle Java SE 8', version: '8u401', bulletin: 'JAVA8-401', file: 'jre-8u401-windows-x64.exe', date: '2024-01-16T17:00:00Z', vendor: 'Oracle' },
  { cat: 'Java', match: /April 2020 CPU/, product: 'Oracle Java SE 8', version: '8u251', bulletin: 'JAVA8-251', file: 'jre-8u251-windows-x64.exe', date: '2020-04-14T17:00:00Z', vendor: 'Oracle' },
  { cat: 'Google Chrome', product: 'Google Chrome', version: '124.0.6367.201', bulletin: 'CHROME-124-0-6367-201', file: 'googlechromestandaloneenterprise64.msi', date: '2024-05-09T17:00:00Z', vendor: 'Google' },
  { cat: 'Microsoft Edge', product: 'Microsoft Edge (Chromium-based)', version: '125.0.2535.67', bulletin: 'MSEDGE-125-0-2535-67', file: 'MicrosoftEdgeEnterpriseX64.msi', date: '2024-05-24T17:00:00Z', vendor: 'Microsoft' },
  { cat: 'Mozilla Firefox', product: 'Mozilla Firefox', version: '125.0', bulletin: 'MFSA2024-18', file: 'Firefox Setup 125.0.msi', date: '2024-04-16T17:00:00Z', vendor: 'Mozilla' },
  { cat: 'Adobe', product: 'Adobe Acrobat Reader DC', version: '23.008.20533', bulletin: 'APSB24-07', file: 'AcroRdrDCUpd2300820533.msp', date: '2024-02-13T17:00:00Z', vendor: 'Adobe' },
];
const WINDOWS_CATS = /^(Microsoft Windows|Microsoft Office|Microsoft Outlook|Exchange Server|Microsoft SharePoint)$/;

async function targeted(file) {
  const t = JSON.parse(fs.readFileSync(file, 'utf8'));
  const rows = t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])));
  const want = new Set(rows.map((r) => r.cve));
  const out = { WINDOWS: [], RHEL9: [], RHEL8: [], UBUNTU: [] };
  const covered = new Set();

  // Microsoft: find each CVE's MSRC release month, then take the KBs in that month that fix it.
  const msCves = rows.filter((r) => WINDOWS_CATS.test(r.category)).map((r) => r.cve);
  const months = new Map();
  for (const cve of msCves) {
    if (LEGACY_MS[cve]) continue;
    try {
      const ids = (await get(`https://api.msrc.microsoft.com/cvrf/v3.0/updates('${cve}')`)).value || [];
      for (const u of ids) if (/^\d{4}-[A-Z][a-z]{2}$/.test(u.ID)) months.set(u.ID, u);
    } catch { /* not an MSRC CVE */ }
  }
  for (const kbs of await msrcMonths([...months.values()])) {
    // One KB per product per month: the one that fixes the most HAC CVEs.
    const best = new Map();
    for (const p of kbs) {
      const hits = p.cves.filter((c) => want.has(c)).length;
      if (!hits) continue;
      const k = p.product;
      if (!best.has(k) || hits > best.get(k).hits) best.set(k, { p, hits });
    }
    for (const { p } of best.values()) { out.WINDOWS.push(p); p.cves.forEach((c) => want.has(c) && covered.add(c)); }
  }
  for (const [cve, m] of Object.entries(LEGACY_MS)) {
    if (!want.has(cve)) continue;
    out.WINDOWS.push({
      name: `KB${m.kb}`, product: 'Windows Server', bulletin_id: m.bulletin, title: `${m.title} (KB${m.kb})`, severity: 'Critical',
      classification: 'Security Updates', release_date: m.date, reboot_required: true, cves: [cve],
      packages: [`windows-kb${m.kb}-x64.msu`], source: `https://learn.microsoft.com/en-us/security-updates/securitybulletins/${m.date.slice(0, 4)}/${m.bulletin.toLowerCase()}`,
    });
    covered.add(cve);
  }
  for (const tp of THIRD_PARTY) {
    const cves = rows.filter((r) => r.category === tp.cat && (!tp.match || tp.match.test(r.name))).map((r) => r.cve);
    if (!cves.length) continue;
    out.WINDOWS.push({
      name: `${tp.product} ${tp.version}`, product: tp.product, bulletin_id: tp.bulletin, title: `${tp.product} ${tp.version} security update`,
      severity: 'Critical', classification: 'Security Updates', release_date: tp.date, reboot_required: false, cves: cves.sort(),
      packages: [tp.file], vendor: tp.vendor, third_party: true, source: `${tp.vendor} ${tp.bulletin}`,
    });
    cves.forEach((c) => covered.add(c));
  }

  // Linux: Red Hat and Ubuntu per-CVE data name the advisory and fixed package for each release.
  const linuxCves = rows.filter((r) => !WINDOWS_CATS.test(r.category) && !THIRD_PARTY.some((tp) => tp.cat === r.category)).map((r) => r.cve);
  const rh = { 9: new Map(), 8: new Map() };
  const usn = new Map();
  for (const cve of linuxCves) {
    try {
      const d = await get(`https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json`);
      for (const a of d.affected_release || []) {
        const m = /^Red Hat Enterprise Linux (8|9)$/.exec(a.product_name || '');
        if (!m || !a.advisory || !a.package) continue;
        const e = rh[m[1]].get(a.advisory) || { advisory: a.advisory, cves: new Set(), pkgs: new Set(), sev: [], date: a.release_date };
        e.cves.add(cve); e.pkgs.add(a.package); e.sev.push(d.threat_severity || 'Moderate');
        rh[m[1]].set(a.advisory, e);
        covered.add(cve);
      }
    } catch { /* Red Hat doesn't track it */ }
    try {
      const d = await get(`https://ubuntu.com/security/cves/${cve}.json`);
      const fixed = (d.packages || []).flatMap((p) => (p.statuses || []).filter((s) => s.release_codename === 'jammy' && s.status === 'released').map((s) => ({ name: p.name, version: s.description })));
      if (!fixed.length) continue;
      for (const n of d.notices || []) {
        const id = n.id || n;
        const e = usn.get(id) || { id, title: n.title || `${fixed[0].name} vulnerabilities`, cves: new Set(), pkgs: new Map(), prio: [], date: n.published };
        e.cves.add(cve); fixed.forEach((f) => e.pkgs.set(f.name, f.version)); e.prio.push(d.priority || 'medium');
        usn.set(id, e);
        covered.add(cve);
      }
    } catch { /* Ubuntu doesn't track it */ }
  }
  for (const major of [9, 8]) {
    for (const e of rh[major].values()) {
      const files = [...e.pkgs].map((p) => `${p.replace(/-\d+:/, '-')}.x86_64.rpm`);
      const pkg = [...e.pkgs][0].replace(/-\d+:.*$/, '');
      const sev = maxSev(e.sev);
      out[`RHEL${major}`].push({
        name: e.advisory, product: pkg, bulletin_id: e.advisory, title: `${sev}: ${pkg} security update`, severity: sev,
        classification: 'Security Advisory', release_date: e.date ? new Date(e.date).toISOString() : new Date().toISOString(),
        reboot_required: /^(kernel|glibc|systemd)$/.test(pkg), cves: [...e.cves].sort(), packages: files.slice(0, 6),
        source: `https://access.redhat.com/errata/${e.advisory}`,
      });
    }
  }
  for (const e of usn.values()) {
    const sev = maxSev(e.prio);
    out.UBUNTU.push({
      name: e.id, product: [...e.pkgs.keys()][0], bulletin_id: e.id, title: `${sev}: ${e.title}`, severity: sev,
      classification: 'Security Advisory', release_date: e.date ? `${String(e.date).slice(0, 19)}Z` : new Date().toISOString(),
      reboot_required: /^linux/.test([...e.pkgs.keys()][0]), cves: [...e.cves].sort(),
      packages: [...e.pkgs].slice(0, 6).map(([n, v]) => `${n}_${v}_amd64.deb`), source: `https://ubuntu.com/security/notices/${e.id}`,
    });
  }
  out.OL8 = oracleFrom(out.RHEL8);
  const missed = rows.filter((r) => !covered.has(r.cve));
  process.stdout.write(`  HAC CVEs: ${covered.size} of ${want.size} have a real vendor fix in the mock catalogs\n`);
  return { out, missed: missed.map((r) => [r.cve, r.category, r.name]) };
}

(async () => {
  const result = { fetched_at: new Date().toISOString(), months: MONTHS, families: {} };
  const step = async (fam, fn) => {
    try { result.families[fam] = await fn(); } catch (e) { console.error(`  ${fam} failed: ${e.message}`); }
  };
  console.log('Fetching real advisories...');
  await step('WINDOWS', windows);
  await step('RHEL9', () => redhat(9));
  await step('RHEL8', () => redhat(8));
  if (result.families.RHEL8) result.families.OL8 = oracleFrom(result.families.RHEL8);
  await step('UBUNTU', ubuntu);
  await step('SLES', suse);
  // HAC's own CVEs go first in each catalog, ahead of the recent advisories.
  const tfile = path.join(__dirname, '..', 'data', 'hac-vulnerabilities.json');
  if (fs.existsSync(tfile)) {
    console.log(`Looking up fixes for the CVEs in ${path.basename(tfile)}...`);
    try {
      const { out, missed } = await targeted(tfile);
      for (const [fam, list] of Object.entries(out)) {
        const names = new Set(list.map((p) => p.name));
        result.families[fam] = [...list.map((p) => ({ ...p, hac_target: true })), ...(result.families[fam] || []).filter((p) => !names.has(p.name))];
      }
      result.hac_unmatched = missed;
    } catch (e) { console.error(`  targeted lookup failed: ${e.message}`); }
  }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(result, null, 1));
  for (const [f, list] of Object.entries(result.families)) {
    console.log(`${f.padEnd(8)} ${String(list.length).padStart(3)} advisories, ${new Set(list.flatMap((p) => p.cves)).size} CVEs`);
  }
  console.log(`Saved ${OUT}. Run POST /mock/reset (or start with --reset) to rebuild the catalogs from it.`);
})();
