'use strict';
// Builds the initial mock TSSA world: servers, groups, depot, patch catalogs, jobs.
const { prng } = require('./util');

const DOMAIN = 'mock.lab';
const AGENT_VERSION = '26.3.00.130';

const SERVER_SPECS = [
  // name, family, os_version, env, app, location
  ['win-web-01', 'WINDOWS', 'Windows Server 2022 Datacenter 21H2', 'Production', 'Apex-Online', 'Houston-DC1'],
  ['win-web-02', 'WINDOWS', 'Windows Server 2022 Datacenter 21H2', 'Production', 'Apex-Online', 'Houston-DC1'],
  ['win-web-03', 'WINDOWS', 'Windows Server 2022 Datacenter 21H2', 'Staging', 'Apex-Online', 'Austin-DC2'],
  ['win-sql-01', 'WINDOWS', 'Windows Server 2019 Standard 1809', 'Production', 'Apex-Online-Core-Storage', 'Houston-DC1'],
  ['win-sql-02', 'WINDOWS', 'Windows Server 2019 Standard 1809', 'Production', 'Apex-Online-Core-Storage', 'Austin-DC2'],
  ['win-dc-01', 'WINDOWS', 'Windows Server 2022 Standard 21H2', 'Production', 'Apex-Online-Core-Infrastructure', 'Houston-DC1'],
  ['win-app-01', 'WINDOWS', 'Windows Server 2016 Standard 1607', 'Production', 'Apex-Mobile-Finance-Data-Ops', 'Houston-DC1'],
  ['win-app-02', 'WINDOWS', 'Windows Server 2016 Standard 1607', 'Staging', 'Apex-Mobile-Finance-Data-Ops', 'Austin-DC2'],
  ['win-app-03', 'WINDOWS', 'Windows Server 2016 Standard 1607', 'Development', 'Apex-Mobile-Finance-Data-Ops', 'Austin-DC2'],
  ['win-file-01', 'WINDOWS', 'Windows Server 2019 Datacenter 1809', 'Production', 'Email Service', 'Houston-DC1'],
  ['win-rds-01', 'WINDOWS', 'Windows Server 2022 Datacenter 21H2', 'Production', 'Apex-Online-Azure', 'Azure-eastus'],
  ['win-mgmt-01', 'WINDOWS', 'Windows Server 2025 Datacenter 24H2', 'Development', 'Apex-Online-Core-Infrastructure', 'AWS-us-east-1'],
  ['rhel-web-01', 'RHEL9', 'Red Hat Enterprise Linux 9.4 (Plow)', 'Production', 'Apex-Online', 'Houston-DC1'],
  ['rhel-web-02', 'RHEL9', 'Red Hat Enterprise Linux 9.4 (Plow)', 'Production', 'Apex-Online', 'Houston-DC1'],
  ['rhel-web-03', 'RHEL9', 'Red Hat Enterprise Linux 9.2 (Plow)', 'Staging', 'Apex-Online', 'Austin-DC2'],
  ['rhel-db-01', 'RHEL8', 'Red Hat Enterprise Linux 8.10 (Ootpa)', 'Production', 'Apex-Online-Core-Storage', 'Houston-DC1'],
  ['rhel-db-02', 'RHEL8', 'Red Hat Enterprise Linux 8.10 (Ootpa)', 'Production', 'Apex-Online-Core-Storage', 'Austin-DC2'],
  ['rhel-jump-01', 'RHEL9', 'Red Hat Enterprise Linux 9.4 (Plow)', 'Production', 'Apex-Online-Core-Infrastructure', 'AWS-us-east-1'],
  ['ol-app-01', 'OL8', 'Oracle Linux Server 8.9', 'Production', 'Apex-Online-GCP', 'GCP-us-central1'],
  ['ol-app-02', 'OL8', 'Oracle Linux Server 8.9', 'Development', 'Apex-Online-GCP', 'GCP-us-central1'],
  ['ubu-k8s-01', 'UBUNTU', 'Ubuntu 22.04.4 LTS (Jammy Jellyfish)', 'Production', 'Apex-Online-AWS', 'AWS-us-east-1'],
  ['ubu-k8s-02', 'UBUNTU', 'Ubuntu 22.04.4 LTS (Jammy Jellyfish)', 'Production', 'Apex-Online-AWS', 'AWS-us-east-1'],
  ['ubu-k8s-03', 'UBUNTU', 'Ubuntu 22.04.4 LTS (Jammy Jellyfish)', 'Staging', 'Apex-Online-AWS', 'AWS-us-east-1'],
  ['sles-sap-01', 'SLES', 'SUSE Linux Enterprise Server 15 SP5', 'Production', 'Apex-Online-Mainframe', 'Houston-DC1'],
];

const FAMILY = {
  WINDOWS: { os: 'Windows', platform: 'WINDOWS', arch: 'x86_64', catalog: 'Windows Patch Catalog' },
  RHEL9: { os: 'Linux', platform: 'LINUX', arch: 'x86_64', catalog: 'RHEL 9 x86_64 Patch Catalog' },
  RHEL8: { os: 'Linux', platform: 'LINUX', arch: 'x86_64', catalog: 'RHEL 8 x86_64 Patch Catalog' },
  OL8: { os: 'Linux', platform: 'LINUX', arch: 'x86_64', catalog: 'Oracle Linux 8 x86_64 Patch Catalog' },
  UBUNTU: { os: 'Linux', platform: 'LINUX', arch: 'x86_64', catalog: 'Ubuntu 22.04 Patch Catalog' },
  SLES: { os: 'Linux', platform: 'LINUX', arch: 'x86_64', catalog: 'SUSE 15 SP5 Patch Catalog' },
};

const SUPPLIER = { 'Houston-DC1': 'Dell', 'Austin-DC2': 'HPE', 'AWS-us-east-1': 'AWS', 'Azure-eastus': 'Microsoft', 'GCP-us-central1': 'Google' };

// --- Patch content ---------------------------------------------------------
const WIN_PRODUCTS = [
  ['Windows Server 2022', 'Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems', 'Critical', true, 410],
  ['Windows Server 2019', 'Cumulative Update for Windows Server 2019 for x64-based Systems', 'Critical', true, 690],
  ['Windows Server 2016', 'Cumulative Update for Windows Server 2016 for x64-based Systems', 'Critical', true, 1650],
  ['Windows Server 2025', 'Cumulative Update for Windows Server 2025 for x64-based Systems', 'Critical', true, 520],
  ['.NET Framework', 'Cumulative Update for .NET Framework 3.5, 4.8 and 4.8.1 for Microsoft server operating system', 'Important', false, 72],
  ['SQL Server 2019', 'Security Update for SQL Server 2019 RTM CU', 'Important', false, 590],
  ['Windows Malicious Software Removal Tool', 'Windows Malicious Software Removal Tool x64', 'Moderate', false, 78],
  ['Servicing Stack', 'Servicing Stack Update for Windows Server', 'Important', false, 14],
  ['Microsoft Edge', 'Security Update for Microsoft Edge (Chromium-based)', 'Important', false, 165],
  ['Microsoft Defender', 'Security Intelligence Update for Microsoft Defender Antivirus', 'Low', false, 112],
];

const MONTHS = ['2026-07', '2026-08', '2026-09', '2026-10'];

const LINUX_PKGS = ['kernel', 'openssl', 'glibc', 'openssh', 'sudo', 'curl', 'systemd', 'httpd', 'nginx', 'python3', 'bind', 'podman', 'git', 'libxml2', 'expat', 'vim', 'tar', 'krb5', 'polkit', 'rsync'];
const SEVERITIES = ['Critical', 'Important', 'Moderate', 'Low'];

function buildCatalogs(r, nextId) {
  const catalogs = [];
  const patches = [];
  const day = 86400000;
  const now = Date.now();

  const mkCatalog = (name, os, family, source, description) => {
    const c = {
      id: nextId(), name, os, family, source, description,
      group_path: `/Workspace/Patch Catalogs/${os === 'WINDOWS' ? 'Windows' : 'Linux'}`,
      last_updated: now - r.int(1, 6) * day,
      update_status: 'COMPLETED',
      patch_ids: [], containers: [],
      filters: os === 'WINDOWS'
        ? { products: ['Windows Server 2016', 'Windows Server 2019', 'Windows Server 2022', 'Windows Server 2025', '.NET Framework', 'SQL Server 2019'], languages: ['English'], classifications: ['Security Updates', 'Critical Updates', 'Update Rollups'] }
        : { architectures: ['x86_64', 'noarch'], channels: [`${family.toLowerCase()}-baseos`, `${family.toLowerCase()}-appstream`] },
    };
    catalogs.push(c);
    return c;
  };

  // Real vendor advisories with their real CVEs (tools/fetch-real-content.js), so HAC can automap
  // scanner vulnerabilities to these patches. Without the file, the made-up content below is used.
  const real = loadRealContent();
  if (real) {
    const SOURCES = {
      WINDOWS: ['Windows Patch Catalog', 'WINDOWS', 'Microsoft (online, via Windows Update metadata)'],
      RHEL9: ['RHEL 9 x86_64 Patch Catalog', 'LINUX', 'Red Hat CDN (cdn.redhat.com)'],
      RHEL8: ['RHEL 8 x86_64 Patch Catalog', 'LINUX', 'Red Hat CDN (cdn.redhat.com)'],
      OL8: ['Oracle Linux 8 x86_64 Patch Catalog', 'LINUX', 'Oracle ULN (linux.oracle.com)'],
      UBUNTU: ['Ubuntu 22.04 Patch Catalog', 'LINUX', 'Ubuntu archive (security.ubuntu.com)'],
      SLES: ['SUSE 15 SP5 Patch Catalog', 'LINUX', 'SUSE Customer Center (updates.suse.com)'],
    };
    for (const [family, [name, os, src]] of Object.entries(SOURCES)) {
      const c = mkCatalog(name, os, family, src, os === 'WINDOWS' ? 'Microsoft security updates and third-party application updates' : `${name} built from vendor repositories`);
      for (const x of real.families[family] || []) {
        const os2 = os === 'WINDOWS' && /^Windows Server/.test(x.product);
        const p = {
          id: nextId(), catalog_id: c.id, os, name: x.name, title: x.title, product: x.product, bulletin_id: x.bulletin_id,
          severity: x.severity, classification: x.classification, release_date: Date.parse(x.release_date) || now,
          size: (os2 ? r.int(300, 900) : /^kernel|^linux/.test(x.product) ? r.int(60, 110) : r.int(1, 60)) * 1048576 + r.int(0, 900000),
          reboot_required: !!x.reboot_required, cves: x.cves, packages: x.packages.length ? x.packages : [`${x.name}.bin`],
          superseded: false, source: x.source || null, hac_target: !!x.hac_target,
        };
        patches.push(p); c.patch_ids.push(p.id);
      }
    }
    addContainers(catalogs, patches, nextId);
    return { catalogs, patches };
  }

  // Windows
  const win = mkCatalog('Windows Patch Catalog', 'WINDOWS', 'WINDOWS', 'Microsoft (online, via Windows Update metadata)', 'Microsoft security and critical updates for Windows Server and server applications');
  let kb = 5063000;
  MONTHS.forEach((m, mi) => {
    WIN_PRODUCTS.forEach(([product, title, sev, reboot, mb]) => {
      if (product === 'Windows Server 2025' && mi < 1) return;
      kb += r.int(11, 97);
      const p = {
        id: nextId(), catalog_id: win.id, os: 'WINDOWS', name: `KB${kb}`,
        title: `${m} ${title} (KB${kb})`, product, bulletin_id: `MS${m.slice(2, 4)}-${['JUL', 'AUG', 'SEP', 'OCT'][mi]}`,
        severity: sev, classification: sev === 'Low' ? 'Definition Updates' : 'Security Updates',
        release_date: Date.parse(`${m}-${r.pick(['08', '09', '14'])}T17:00:00Z`),
        size: mb * 1048576 + r.int(0, 900000), reboot_required: reboot,
        cves: Array.from({ length: r.int(1, reboot ? 9 : 3) }, () => `CVE-2026-${r.int(20000, 59999)}`),
        packages: [`windows10.0-kb${kb}-x64.msu`], superseded: mi < MONTHS.length - 1 && reboot,
      };
      patches.push(p); win.patch_ids.push(p.id);
    });
  });

  const linuxCatalog = (name, family, src, prefix, distTag, advisory) => {
    const c = mkCatalog(name, 'LINUX', family, src, `${name} built from vendor repositories`);
    let seq = r.int(4000, 7000);
    MONTHS.forEach((m) => {
      r.sample(LINUX_PKGS, r.int(7, 10)).forEach((pkg) => {
        seq += r.int(3, 60);
        const sev = r.pick(SEVERITIES);
        const ver = pkg === 'kernel'
          ? (distTag.startsWith('el9') ? `5.14.0-${r.int(500, 611)}.${r.int(10, 60)}.1.${distTag}` : distTag.startsWith('el8') ? `4.18.0-553.${r.int(30, 90)}.1.${distTag}` : `5.15.0-${r.int(120, 140)}.${r.int(130, 160)}`)
          : `${r.int(1, 9)}.${r.int(0, 30)}.${r.int(0, 15)}-${r.int(1, 30)}.${distTag}`;
        const p = {
          id: nextId(), catalog_id: c.id, os: 'LINUX', name: advisory(m, seq),
          title: `${sev}: ${pkg} security update`, product: pkg, bulletin_id: advisory(m, seq),
          severity: sev, classification: 'Security Advisory',
          release_date: Date.parse(`${m}-${String(r.int(1, 28)).padStart(2, '0')}T12:00:00Z`),
          size: (pkg === 'kernel' ? r.int(60, 110) : r.int(1, 25)) * 1048576 + r.int(0, 900000),
          reboot_required: ['kernel', 'glibc', 'systemd'].includes(pkg),
          cves: Array.from({ length: r.int(1, 5) }, () => `CVE-2026-${r.int(20000, 59999)}`),
          packages: [`${pkg}-${ver}.${family === 'UBUNTU' ? 'amd64.deb' : 'x86_64.rpm'}`],
          superseded: false,
        };
        patches.push(p); c.patch_ids.push(p.id);
      });
    });
    return c;
  };

  linuxCatalog('RHEL 9 x86_64 Patch Catalog', 'RHEL9', 'Red Hat CDN (cdn.redhat.com)', 'RHSA', 'el9_4', (m, s) => `RHSA-2026:${s}`);
  linuxCatalog('RHEL 8 x86_64 Patch Catalog', 'RHEL8', 'Red Hat CDN (cdn.redhat.com)', 'RHSA', 'el8_10', (m, s) => `RHSA-2026:${s + 30}`);
  linuxCatalog('Oracle Linux 8 x86_64 Patch Catalog', 'OL8', 'Oracle ULN (linux.oracle.com)', 'ELSA', 'el8', (m, s) => `ELSA-2026-${s}`);
  linuxCatalog('Ubuntu 22.04 Patch Catalog', 'UBUNTU', 'Ubuntu archive (security.ubuntu.com)', 'USN', 'ubuntu22.04', (m, s) => `USN-${s + 3000}-1`);
  linuxCatalog('SUSE 15 SP5 Patch Catalog', 'SLES', 'SUSE Customer Center (updates.suse.com)', 'SUSE-SU', 'sle15sp5', (m, s) => `SUSE-SU-2026:${s}-1`);

  addContainers(catalogs, patches, nextId);
  return { catalogs, patches };
}

// Patch containers (smart groups within a catalog)
function addContainers(catalogs, patches, nextId) {
  const latest = Math.max(...patches.map((p) => p.release_date));
  const monthStart = Date.parse(`${new Date(latest).toISOString().slice(0, 7)}-01`);
  for (const c of catalogs) {
    const own = patches.filter((p) => p.catalog_id === c.id);
    c.containers = [
      { id: nextId(), name: 'All Patches', criteria: 'ALL', patch_ids: own.map((p) => p.id) },
      { id: nextId(), name: 'Critical and Important', criteria: "severity IN ('Critical','Important')", patch_ids: own.filter((p) => ['Critical', 'Important'].includes(p.severity)).map((p) => p.id) },
      { id: nextId(), name: `Monthly ${new Date(monthStart).toISOString().slice(0, 7)}`, criteria: `release_date >= ${new Date(monthStart).toISOString().slice(0, 10)}`, patch_ids: own.filter((p) => p.release_date >= monthStart).map((p) => p.id) },
    ];
  }
}

function loadRealContent() {
  const file = require('path').join(__dirname, '..', 'data', 'real-content.json');
  try { return JSON.parse(require('fs').readFileSync(file, 'utf8')); } catch { return null; }
}

// --- Depot ----------------------------------------------------------------
const SCRIPTS = [
  { key: 'disk', name: 'Get Disk Usage', platforms: ['WINDOWS', 'LINUX'], params: [], description: 'Reports file system usage on each target',
    content: '#!/bin/nsh\n# Report disk usage per file system\nif [ "$(uname -s)" = "WindowsNT" ]; then\n  nexec -e powershell -NoProfile -Command "Get-PSDrive -PSProvider FileSystem | Format-Table -AutoSize"\nelse\n  nexec -e df -hP -x tmpfs -x devtmpfs\nfi\n' },
  { key: 'health', name: 'Pre-Patch Health Check', platforms: ['WINDOWS', 'LINUX'], params: [{ name: 'MIN_FREE_GB', default: '5' }], description: 'Validates free disk, uptime and pending reboot before patching',
    content: '#!/bin/nsh\nMIN_FREE_GB=${1:-5}\necho "Running pre-patch health check on $(hostname)"\nagentinfo $(hostname)\n# disk, uptime, pending reboot checks\n...\n' },
  { key: 'postval', name: 'Post-Patch Validation', platforms: ['WINDOWS', 'LINUX'], params: [], description: 'Confirms services are running after patch remediation',
    content: '#!/bin/nsh\necho "Validating critical services on $(hostname)"\n...\n' },
  { key: 'restart', name: 'Restart Service', platforms: ['WINDOWS', 'LINUX'], params: [{ name: 'SERVICE_NAME', default: 'W3SVC' }], description: 'Restarts a named service',
    content: '#!/bin/nsh\nSVC=$1\nif [ "$(uname -s)" = "WindowsNT" ]; then\n  nexec -e powershell -Command "Restart-Service -Name $SVC -Force -PassThru"\nelse\n  nexec -e systemctl restart $SVC && nexec -e systemctl is-active $SVC\nfi\n' },
  { key: 'inventory', name: 'Collect System Inventory', platforms: ['WINDOWS', 'LINUX'], params: [], description: 'Collects OS, CPU, memory and uptime',
    content: '#!/bin/nsh\nagentinfo $(hostname)\nnexec -e uptime\n' },
  { key: 'reboot', name: 'Check Pending Reboot', platforms: ['WINDOWS'], params: [], description: 'Checks CBS / Windows Update pending reboot flags',
    content: '#!/bin/nsh\nnexec -e powershell -Command "Test-Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending\'"\n' },
  { key: 'tmp', name: 'Clear Temp Files', platforms: ['WINDOWS', 'LINUX'], params: [{ name: 'OLDER_THAN_DAYS', default: '7' }], description: 'Removes temporary files older than N days',
    content: '#!/bin/nsh\nDAYS=${1:-7}\n...\n' },
  { key: 'ntp', name: 'Verify NTP Sync', platforms: ['WINDOWS', 'LINUX'], params: [], description: 'Checks time synchronization status',
    content: '#!/bin/nsh\n...\n' },
  { key: 'yumclean', name: 'Clean Package Cache', platforms: ['LINUX'], params: [], description: 'Cleans yum/dnf/apt package caches',
    content: '#!/bin/nsh\nnexec -e sh -c "command -v dnf && dnf clean all || apt-get clean"\n' },
];

// More scripts and jobs for HAC's Adhoc Job Selections. addAdhocJobs adds them by name, so a data file
// from before they existed gets them at start-up and keeps its jobs and run history.
const ADHOC_SCRIPTS = [
  { key: 'certs', name: 'Check Certificate Expiry', platforms: ['WINDOWS', 'LINUX'], params: [{ name: 'WARN_DAYS', default: '30' }], description: 'Lists certificates that expire within N days',
    content: '#!/bin/nsh\nDAYS=${1:-30}\necho "Checking certificates expiring within $DAYS days on $(hostname)"\n...\n' },
  { key: 'logs', name: 'Rotate Application Logs', platforms: ['LINUX'], params: [{ name: 'LOG_DIR', default: '/var/log/app' }], description: 'Compresses and rotates application logs',
    content: '#!/bin/nsh\nDIR=${1:-/var/log/app}\nnexec -e logrotate -f /etc/logrotate.d/app\n' },
  { key: 'dns', name: 'Flush DNS Cache', platforms: ['WINDOWS'], params: [], description: 'Clears the DNS resolver cache',
    content: '#!/bin/nsh\nnexec -e ipconfig /flushdns\n' },
  { key: 'bundle', name: 'Collect Support Bundle', platforms: ['WINDOWS', 'LINUX'], params: [], description: 'Gathers logs and configuration for a support case',
    content: '#!/bin/nsh\necho "Collecting support bundle on $(hostname)"\n...\n' },
];

const ADHOC_NSH_JOBS = [
  ['Collect System Inventory - Production', 'inventory', 'Production', []],
  ['Clear Temp Files - Windows', 'tmp', 'All Windows Servers', ['7']],
  ['Verify NTP Sync - Production', 'ntp', 'Production', []],
  ['Clean Package Cache - Linux', 'yumclean', 'All Linux Servers', []],
  ['Restart Service - Print Spooler', 'restart', 'All Windows Servers', ['Spooler']],
  ['Check Certificate Expiry - Web Tier', 'certs', 'Web Tier', ['30']],
  ['Rotate Application Logs - Linux', 'logs', 'All Linux Servers', ['/var/log/app']],
  ['Flush DNS Cache - Windows', 'dns', 'All Windows Servers', []],
  ['Collect Support Bundle - Apex-Online', 'bundle', 'Apex-Online', []],
];

const ADHOC_DEPLOY_JOBS = [
  ['Deploy CrowdStrike Falcon Sensor', 'CrowdStrike Falcon Sensor 7.18', 'Production', 'Installs the Falcon sensor'],
  ['Deploy Java JDK 21', 'Java JDK 21.0.5', 'All Linux Servers', 'Installs JDK 21.0.5'],
  ['Deploy Corporate Hosts File', 'Corporate Hosts File Update', 'Production', 'Replaces the hosts file with the corporate copy'],
  ['Deploy Apache Tomcat Config', 'Apache Tomcat 10.1 Config', 'All Linux Servers', 'Replaces Tomcat configuration and restarts it'],
];

const ADHOC_BATCH_JOBS = [
  ['Weekly Health Check - Windows', 'All Windows Servers', 'Disk usage, pending reboot and time sync', ['Get Disk Usage - Windows', 'Check Pending Reboot - Windows', 'Verify NTP Sync - Production']],
  ['Weekly Health Check - Linux', 'All Linux Servers', 'Disk usage, time sync and package cache clean-up', ['Get Disk Usage - Linux', 'Verify NTP Sync - Production', 'Clean Package Cache - Linux']],
  ['New Server Baseline', 'Production', 'Monitoring agent, endpoint sensor and hosts file', ['Deploy Splunk Universal Forwarder', 'Deploy CrowdStrike Falcon Sensor', 'Deploy Corporate Hosts File']],
  ['Web Tier Hardening', 'Web Tier', 'IIS hardening, service restart and validation', ['Deploy IIS Baseline Hardening', 'Restart Service - IIS Web Tier', 'Post-Patch Validation - Web Tier']],
];

function addAdhocJobs(state, nextId) {
  const now = Date.now();
  const has = (name) => state.jobs.some((j) => j.name === name);
  const group = (name) => ({ server_ids: [], group_ids: [state.groups.find((g) => g.name === name).id] });
  const add = (o) => state.jobs.push({ id: nextId(), created_by: 'BLAdmin', date_created: now, last_modified: now, schedules: [], ...o });
  for (const sc of ADHOC_SCRIPTS) {
    if (state.scripts.some((x) => x.key === sc.key)) continue;
    state.scripts.push({
      id: nextId(), key: sc.key, name: sc.name, group_path: '/Depot/Scripts/Operations', description: sc.description,
      script_type: 'NSH_SCRIPT_TYPE_RUN_SCRIPT_ONCE_PER_TARGET', platforms: sc.platforms, parameters: sc.params,
      content: sc.content, version: 1, date_created: now, created_by: 'BLAdmin',
    });
  }
  for (const [name, key, target, args] of ADHOC_NSH_JOBS) {
    if (has(name)) continue;
    const script = state.scripts.find((x) => x.key === key);
    add({ name, type: 'NSH_SCRIPT_JOB', group_path: '/Workspace/Jobs/Operations', description: `Runs NSH script '${script.name}'`, targets: group(target), params: { script_id: script.id, arguments: args } });
  }
  for (const [name, pkg, target, description] of ADHOC_DEPLOY_JOBS) {
    if (has(name)) continue;
    add({ name, type: 'DEPLOY_JOB', group_path: '/Workspace/Jobs/Deploy', description, targets: group(target),
      params: { package_id: state.blpackages.find((p) => p.name === pkg).id, phases: ['SIMULATE', 'STAGE', 'COMMIT'] } });
  }
  for (const [name, target, description, members] of ADHOC_BATCH_JOBS) {
    if (has(name)) continue;
    const childIds = members.map((m) => state.jobs.find((j) => j.name === m).id);
    add({ name, type: 'BATCH_JOB', group_path: '/Workspace/Jobs/Batch', description, targets: group(target), params: { child_job_ids: childIds, stop_on_failure: false } });
  }
}

const BLPACKAGES = [
  { name: 'Splunk Universal Forwarder 9.3', platforms: ['WINDOWS', 'LINUX'], items: [['SOFTWARE', 'splunkforwarder-9.3.2-x64-release.msi / .rpm', 'INSTALL'], ['FILE', '/opt/splunkforwarder/etc/system/local/outputs.conf', 'ADD'], ['SERVICE', 'SplunkForwarder', 'START']] },
  { name: 'CrowdStrike Falcon Sensor 7.18', platforms: ['WINDOWS', 'LINUX'], items: [['SOFTWARE', 'FalconSensor_Windows.exe / falcon-sensor-7.18.0.x86_64.rpm', 'INSTALL'], ['SERVICE', 'CSFalconService', 'START']] },
  { name: 'SSH Hardening (sshd_config)', platforms: ['LINUX'], items: [['CONFIG', '/etc/ssh/sshd_config :: PermitRootLogin', 'MODIFY'], ['CONFIG', '/etc/ssh/sshd_config :: PasswordAuthentication', 'MODIFY'], ['SERVICE', 'sshd', 'RESTART']] },
  { name: 'IIS Baseline Hardening', platforms: ['WINDOWS'], items: [['REGISTRY', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server\\Enabled', 'MODIFY'], ['REGISTRY', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server\\Enabled', 'MODIFY'], ['SERVICE', 'W3SVC', 'RESTART']] },
  { name: 'Java JDK 21.0.5', platforms: ['WINDOWS', 'LINUX'], items: [['SOFTWARE', 'jdk-21.0.5_windows-x64_bin.msi / jdk-21.0.5_linux-x64_bin.rpm', 'INSTALL']] },
  { name: 'Corporate Hosts File Update', platforms: ['WINDOWS', 'LINUX'], items: [['FILE', 'hosts', 'REPLACE']] },
  { name: 'Apache Tomcat 10.1 Config', platforms: ['LINUX'], items: [['FILE', '/opt/tomcat/conf/server.xml', 'REPLACE'], ['FILE', '/opt/tomcat/conf/context.xml', 'REPLACE'], ['SERVICE', 'tomcat', 'RESTART']] },
];

const SOFTWARE = [
  { name: '7-Zip 24.08 x64', type: 'MSI', platforms: ['WINDOWS'], file: '7z2408-x64.msi', size: 1966080 },
  { name: 'Notepad++ 8.7.1', type: 'WINDOWS_INSTALLER', platforms: ['WINDOWS'], file: 'npp.8.7.1.Installer.x64.exe', size: 4718592 },
  { name: 'nginx 1.26.2', type: 'RPM', platforms: ['LINUX'], file: 'nginx-1.26.2-1.el9.ngx.x86_64.rpm', size: 1048576 },
  { name: 'Node.js 22 LTS', type: 'RPM', platforms: ['LINUX'], file: 'nodejs-22.11.0-1nodesource.x86_64.rpm', size: 39845888 },
];

const DEPOT_FILES = [
  { name: 'corp-ca-bundle.pem', path: '/Depot/Files/Certificates', size: 8192 },
  { name: 'motd.txt', path: '/Depot/Files/Linux', size: 412 },
  { name: 'hosts', path: '/Depot/Files/Common', size: 2048 },
];

const TEMPLATES = [
  { name: 'CIS - Windows Server 2022', platform: 'WINDOWS', rules: 212 },
  { name: 'DISA STIG - Windows Server 2019', platform: 'WINDOWS', rules: 268 },
  { name: 'CIS - Red Hat Enterprise Linux 9', platform: 'LINUX', rules: 241 },
  { name: 'PCI-DSS v4.0 - Linux', platform: 'LINUX', rules: 96 },
];

function seed() {
  const r = prng(38090426);
  let idSeq = 2000100;
  const nextId = () => (idSeq += r.int(1, 9));
  const now = Date.now();
  const day = 86400000;

  const state = {
    meta: { seeded_at: now, version: AGENT_VERSION },
    servers: [], groups: [], scripts: [], blpackages: [], software: [], depot_files: [],
    templates: [], catalogs: [], patches: [], missing: {}, jobs: [], runs: [],
  };

  // Servers
  SERVER_SPECS.forEach(([name, family, osVersion, env, app, loc], i) => {
    const f = FAMILY[family];
    const s = {
      id: nextId(), name: `${name}.${DOMAIN}`, short_name: name, family,
      ip_address: `10.${loc.startsWith('Houston') ? 20 : loc.startsWith('Austin') ? 30 : 40}.${f.os === 'Windows' ? 1 : 2}.${10 + i}`,
      os: f.os, platform: f.platform, os_version: osVersion, architecture: f.arch,
      agent_version: AGENT_VERSION, agent_port: 4750,
      agent_status: name === 'win-app-03' ? 'agent is not responding' : 'agent is alive',
      decommissioned: false, date_created: now - r.int(120, 900) * day,
      cpu_count: r.pick([2, 4, 8, 16]), memory_mb: r.pick([8192, 16384, 32768, 65536]),
      last_reboot: now - r.int(2, 60) * day,
      properties: {
        ENVIRONMENT: env, APPLICATION: app, LOCATION: loc, SUPPLIER: SUPPLIER[loc],
        CUSTOMER: 'Apex Global', OWNER: f.os === 'Windows' ? 'Windows Server Team' : 'Linux Platform Team',
        PATCH_WINDOW: env === 'Production' ? 'SAT-0200' : 'WED-2200',
      },
    };
    state.servers.push(s);
  });

  // Server groups (static + smart)
  const g = (name, path, type, criteria, members) => state.groups.push({ id: nextId(), name, path, group_type: type, object_type: 'SERVER', criteria, member_ids: members.map((s) => s.id) });
  const win = state.servers.filter((s) => s.os === 'Windows');
  const lin = state.servers.filter((s) => s.os === 'Linux');
  g('Windows', '/Servers/Windows', 'STATIC', null, win);
  g('Linux', '/Servers/Linux', 'STATIC', null, lin);
  g('All Windows Servers', '/Servers/Smart Groups/All Windows Servers', 'SMART', 'OS equals Windows', win);
  g('All Linux Servers', '/Servers/Smart Groups/All Linux Servers', 'SMART', 'OS equals Linux', lin);
  g('Production', '/Servers/Smart Groups/Production', 'SMART', 'ENVIRONMENT equals Production', state.servers.filter((s) => s.properties.ENVIRONMENT === 'Production'));
  g('Web Tier', '/Servers/Smart Groups/Web Tier', 'SMART', 'NAME contains -web-', state.servers.filter((s) => s.name.includes('-web-')));
  g('Apex-Online', '/Servers/Smart Groups/Apex-Online', 'SMART', 'APPLICATION starts with Apex-Online', state.servers.filter((s) => s.properties.APPLICATION.startsWith('Apex-Online')));

  // Depot
  SCRIPTS.forEach((sc) => state.scripts.push({
    id: nextId(), key: sc.key, name: sc.name, group_path: '/Depot/Scripts/Operations', description: sc.description,
    script_type: 'NSH_SCRIPT_TYPE_RUN_SCRIPT_ONCE_PER_TARGET', platforms: sc.platforms, parameters: sc.params,
    content: sc.content, version: 1, date_created: now - r.int(30, 400) * day, created_by: 'BLAdmin',
  }));
  BLPACKAGES.forEach((p) => state.blpackages.push({
    id: nextId(), name: p.name, group_path: '/Depot/Packages', description: `${p.name} (BLPackage)`, platforms: p.platforms,
    items: p.items.map(([type, path, action], i) => ({ id: i + 1, type, path, action })), version: r.int(1, 4),
    date_created: now - r.int(30, 400) * day, created_by: 'BLAdmin',
  }));
  SOFTWARE.forEach((s) => state.software.push({ id: nextId(), group_path: '/Depot/Software', ...s, date_created: now - r.int(30, 400) * day }));
  DEPOT_FILES.forEach((f) => state.depot_files.push({ id: nextId(), group_path: f.path, ...f, date_created: now - r.int(30, 400) * day }));
  TEMPLATES.forEach((t) => state.templates.push({ id: nextId(), group_path: '/Component Templates/Compliance', ...t }));

  // Patch catalogs
  const { catalogs, patches } = buildCatalogs(r, nextId);
  state.catalogs = catalogs;
  state.patches = patches;

  // Missing patches per server
  for (const s of state.servers) {
    const cat = catalogs.find((c) => c.name === FAMILY[s.family].catalog);
    s.catalog_id = cat.id;
    let pool = patches.filter((p) => p.catalog_id === cat.id);
    if (s.family === 'WINDOWS') {
      const ver = s.os_version.match(/20\d\d/)[0];
      // "Windows Server" alone (legacy bulletins such as MS08-067) applies to every version.
      pool = pool.filter((p) => !/^Windows Server \d/.test(p.product) || p.product === `Windows Server ${ver}`);
      if (!s.short_name.includes('sql')) pool = pool.filter((p) => !p.product.startsWith('SQL'));
      if (!s.short_name.includes('mail')) pool = pool.filter((p) => !p.product.startsWith('Exchange'));
    }
    const ratio = s.properties.ENVIRONMENT === 'Production' ? 0.35 : 0.55;
    // Patches that fix a CVE HAC already holds are missing on most servers, so automapped
    // vulnerabilities have remediation targets.
    state.missing[s.id] = pool.filter((p) => r.chance(p.hac_target ? 0.8 : ratio)).map((p) => p.id);
  }

  // Jobs
  const byName = (arr, n) => arr.find((x) => x.name === n);
  const grp = (n) => state.groups.find((x) => x.name === n);
  const catByFamily = (fam) => catalogs.find((c) => c.family === fam);
  const serversOf = (pred) => state.servers.filter(pred).map((s) => s.id);
  const job = (o) => {
    const j = {
      id: nextId(), description: '', created_by: 'BLAdmin', date_created: now - r.int(10, 200) * day,
      schedules: [], targets: { server_ids: [], group_ids: [] }, params: {}, ...o,
    };
    j.last_modified = j.date_created + r.int(0, 5) * day;
    state.jobs.push(j);
    return j;
  };

  const patchJobs = {};
  [['WINDOWS', 'Windows - Monthly Patch Analysis', (s) => s.os === 'Windows'],
    ['RHEL9', 'RHEL 9 - Patch Analysis', (s) => s.family === 'RHEL9'],
    ['RHEL8', 'RHEL 8 - Patch Analysis', (s) => s.family === 'RHEL8'],
    ['OL8', 'Oracle Linux 8 - Patch Analysis', (s) => s.family === 'OL8'],
    ['UBUNTU', 'Ubuntu 22.04 - Patch Analysis', (s) => s.family === 'UBUNTU'],
    ['SLES', 'SLES 15 - Patch Analysis', (s) => s.family === 'SLES'],
  ].forEach(([fam, name, pred]) => {
    patchJobs[fam] = job({
      name, type: 'PATCHING_JOB', group_path: `/Workspace/Jobs/Patching/${fam === 'WINDOWS' ? 'Windows' : 'Linux'}`,
      description: `Patch analysis against ${catByFamily(fam).name}`,
      targets: { server_ids: serversOf(pred), group_ids: [] },
      params: { catalog_id: catByFamily(fam).id, analysis_only: true, remediate: false, reboot: 'IF_REQUIRED', container: 'All Patches' },
      schedules: fam === 'WINDOWS' ? [{ id: 1, type: 'MONTHLY', description: 'Second Tuesday 23:00', next_run: now + r.int(2, 20) * day }] : [],
    });
  });
  const remWin = job({
    name: 'Windows - Patch Remediation (Web Tier)', type: 'PATCHING_JOB', group_path: '/Workspace/Jobs/Patching/Windows',
    description: 'Analyze and remediate critical/important patches on Windows web servers',
    targets: { server_ids: serversOf((s) => s.short_name.startsWith('win-web')), group_ids: [] },
    params: { catalog_id: catByFamily('WINDOWS').id, analysis_only: false, remediate: true, reboot: 'IF_REQUIRED', container: 'Critical and Important' },
  });
  job({
    name: 'RHEL 9 - Patch Remediation', type: 'PATCHING_JOB', group_path: '/Workspace/Jobs/Patching/Linux',
    description: 'Analyze and remediate all missing errata on RHEL 9 servers',
    targets: { server_ids: serversOf((s) => s.family === 'RHEL9'), group_ids: [] },
    params: { catalog_id: catByFamily('RHEL9').id, analysis_only: false, remediate: true, reboot: 'IF_REQUIRED', container: 'All Patches' },
  });

  const sj = (name, key, targets, args = []) => job({
    name, type: 'NSH_SCRIPT_JOB', group_path: '/Workspace/Jobs/Operations', description: `Runs NSH script '${byName(state.scripts, name.split(' - ')[0])?.name || key}'`,
    targets, params: { script_id: state.scripts.find((x) => x.key === key).id, arguments: args },
  });
  const health = sj('Pre-Patch Health Check - All', 'health', { server_ids: [], group_ids: [grp('Production').id] }, ['5']);
  sj('Get Disk Usage - Linux', 'disk', { server_ids: [], group_ids: [grp('All Linux Servers').id] });
  sj('Get Disk Usage - Windows', 'disk', { server_ids: [], group_ids: [grp('All Windows Servers').id] });
  sj('Restart Service - IIS Web Tier', 'restart', { server_ids: serversOf((s) => s.short_name.startsWith('win-web')), group_ids: [] }, ['W3SVC']);
  sj('Check Pending Reboot - Windows', 'reboot', { server_ids: [], group_ids: [grp('All Windows Servers').id] });
  const postval = sj('Post-Patch Validation - Web Tier', 'postval', { server_ids: [], group_ids: [grp('Web Tier').id] });

  job({ name: 'Deploy Splunk Universal Forwarder', type: 'DEPLOY_JOB', group_path: '/Workspace/Jobs/Deploy', description: 'Deploys Splunk UF BLPackage',
    targets: { server_ids: [], group_ids: [grp('Production').id] }, params: { package_id: byName(state.blpackages, 'Splunk Universal Forwarder 9.3').id, phases: ['SIMULATE', 'STAGE', 'COMMIT'] } });
  job({ name: 'Deploy SSH Hardening', type: 'DEPLOY_JOB', group_path: '/Workspace/Jobs/Deploy', description: 'Applies hardened sshd_config',
    targets: { server_ids: [], group_ids: [grp('All Linux Servers').id] }, params: { package_id: byName(state.blpackages, 'SSH Hardening (sshd_config)').id, phases: ['SIMULATE', 'STAGE', 'COMMIT'] } });
  job({ name: 'Deploy IIS Baseline Hardening', type: 'DEPLOY_JOB', group_path: '/Workspace/Jobs/Deploy', description: 'Disables TLS 1.0/1.1 on IIS',
    targets: { server_ids: serversOf((s) => s.short_name.startsWith('win-web')), group_ids: [] }, params: { package_id: byName(state.blpackages, 'IIS Baseline Hardening').id, phases: ['SIMULATE', 'STAGE', 'COMMIT'] } });

  job({ name: 'Distribute Corporate CA Bundle', type: 'FILE_DEPLOY_JOB', group_path: '/Workspace/Jobs/Deploy', description: 'Copies corp-ca-bundle.pem to all servers',
    targets: { server_ids: [], group_ids: [grp('Production').id] }, params: { file_id: state.depot_files[0].id, destination: '/etc/pki/ca-trust/source/anchors/ | C:\\ProgramData\\Corp\\certs\\' } });

  job({ name: 'CIS Windows Server 2022 Compliance', type: 'COMPLIANCE_JOB', group_path: '/Workspace/Jobs/Compliance', description: 'CIS benchmark compliance scan',
    targets: { server_ids: serversOf((s) => s.os_version.includes('2022')), group_ids: [] }, params: { template_id: state.templates[0].id } });
  job({ name: 'CIS RHEL 9 Compliance', type: 'COMPLIANCE_JOB', group_path: '/Workspace/Jobs/Compliance', description: 'CIS benchmark compliance scan',
    targets: { server_ids: serversOf((s) => s.family === 'RHEL9'), group_ids: [] }, params: { template_id: state.templates[2].id } });

  job({ name: 'Config Snapshot - Linux', type: 'SNAPSHOT_JOB', group_path: '/Workspace/Jobs/Snapshot', description: 'Snapshots /etc on Linux servers',
    targets: { server_ids: [], group_ids: [grp('All Linux Servers').id] }, params: {} });

  job({ name: 'Monthly Patch Window - Web Tier', type: 'BATCH_JOB', group_path: '/Workspace/Jobs/Batch', description: 'Health check, patch remediation, post validation',
    targets: { server_ids: [], group_ids: [grp('Web Tier').id] }, params: { child_job_ids: [health.id, remWin.id, postval.id], stop_on_failure: false } });

  addAdhocJobs(state, nextId);
  state.idSeq = idSeq;
  return state;
}

module.exports = { seed, addAdhocJobs, FAMILY, DOMAIN, AGENT_VERSION };
