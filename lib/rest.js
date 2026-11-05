'use strict';
// TSSA REST API emulation: https://<host>:9843/rest/api/{v1,v2}/...
const crypto = require('crypto');
const store = require('./store');
const engine = require('./engine');
const notify = require('./notify');
const { iso } = require('./util');

const JOB_TYPES = {
  'patching-jobs': 'PATCHING_JOB',
  'nshscript-jobs': 'NSH_SCRIPT_JOB',
  'nsh-script-jobs': 'NSH_SCRIPT_JOB',
  'deploy-jobs': 'DEPLOY_JOB',
  'batch-jobs': 'BATCH_JOB',
  'compliance-jobs': 'COMPLIANCE_JOB',
  'file-deploy-jobs': 'FILE_DEPLOY_JOB',
  'snapshot-jobs': 'SNAPSHOT_JOB',
  'catalog-update-jobs': 'CATALOG_UPDATE_JOB',
  jobs: null, // any type
};
// HAC's Adhoc Job Selections reads the job list from these keys, not from jobs.
const JOB_LIST_KEYS = { NSH_SCRIPT_JOB: 'nshscript_job_list', DEPLOY_JOB: 'deploy_job_list', BATCH_JOB: 'batch_job_list' };
const JOB_TYPE_LABEL = {
  PATCHING_JOB: 'Patching Job', NSH_SCRIPT_JOB: 'NSH Script Job', DEPLOY_JOB: 'BLPackage Deploy Job', BATCH_JOB: 'Batch Job',
  COMPLIANCE_JOB: 'Compliance Job', FILE_DEPLOY_JOB: 'File Deploy Job', SNAPSHOT_JOB: 'Snapshot Job', CATALOG_UPDATE_JOB: 'Patch Catalog Update Job',
};
// Policy service JobResponse.type is JobTypeDetail, the same { id, name } shape as a catalog type.
// A string such as "PATCHING_JOB" cannot be deserialized into that bean.
const JOB_TYPE_DETAIL = {
  PATCHING_JOB: { id: 205, name: 'Patching Job' },
  NSH_SCRIPT_JOB: { id: 200, name: 'NSH Script Job' },
  DEPLOY_JOB: { id: 30, name: 'Deploy Job' },
  BATCH_JOB: { id: 202, name: 'Batch Job' },
  COMPLIANCE_JOB: { id: 510, name: 'Compliance Job' },
  FILE_DEPLOY_JOB: { id: 220, name: 'File Deploy Job' },
  SNAPSHOT_JOB: { id: 400, name: 'Snapshot Job' },
  CATALOG_UPDATE_JOB: { id: 207, name: 'Patch Catalog Update Job' },
};
const MODEL_TYPE = {
  PATCHING_JOB: 'PATCHING_JOB_WINDOWS', NSH_SCRIPT_JOB: 'NSH_SCRIPT_JOB', DEPLOY_JOB: 'DEPLOY_JOB', BATCH_JOB: 'BATCH_JOB',
  COMPLIANCE_JOB: 'COMPLIANCE_JOB', FILE_DEPLOY_JOB: 'FILE_DEPLOY_JOB', SNAPSHOT_JOB: 'SNAPSHOT_JOB', CATALOG_UPDATE_JOB: 'PATCH_CATALOG_UPDATE_JOB',
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const ERR_NAMES = { 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 409: 'Conflict', 500: 'Internal Server Error' };

// --- serializers -----------------------------------------------------------
const dbkey = (kind, id) => `DBKey:${kind}:${id}-1-${id + 1}`;

// OS details in the form HAC stores for assets it imported from a real TSSA server
// (os_version "2022" / "Ubuntu 22.04", os_release "10.0" or a kernel, vendor "Microsoft" / "Ubuntu").
const OS_META = {
  WINDOWS: { vendor: 'Microsoft', release: '10.0' },
  RHEL9: { vendor: 'Red Hat', release: '5.14.0-427.13.1.el9_4.x86_64' },
  RHEL8: { vendor: 'Red Hat', release: '4.18.0-553.el8_10.x86_64' },
  OL8: { vendor: 'Oracle', release: '5.15.0-206.153.7.el8uek.x86_64' },
  UBUNTU: { vendor: 'Ubuntu', release: '5.15.0-119-generic' },
  SLES: { vendor: 'SUSE', release: '5.14.21-150500.55.65-default' },
};

function shortOsVersion(s) {
  if (s.family === 'WINDOWS') return (s.os_version.match(/20\d\d/) || [s.os_version])[0];
  if (s.family === 'UBUNTU') return (s.os_version.match(/Ubuntu \d+\.\d+/) || [s.os_version])[0];
  return s.os_version.replace(/\s*\(.*\)$/, '').replace(/Server /, '');
}

// Server properties as TSSA's [{name, value}] list: built-in property names (the ones HAC uses for
// remediation targeting: OS, OS_PLATFORM, OS_VERSION, OS_RELEASE, OS_VENDOR, OS_PATCH_LEVEL) plus custom ones.
function serverPropertyList(s) {
  const meta = OS_META[s.family] || {};
  const builtIn = {
    NAME: s.name, OS: s.os, OS_PLATFORM: s.architecture, OS_VERSION: shortOsVersion(s), OS_RELEASE: meta.release,
    OS_VENDOR: meta.vendor, OS_PATCH_LEVEL: s.family === 'WINDOWS' ? s.os_version : meta.release, IP_ADDRESS: s.ip_address,
    AGENT_STATUS: s.agent_status, AGENT_RELEASE: s.agent_version, AGENT_PORT: String(s.agent_port), IS_ONLINE: String(s.agent_status === 'agent is alive'),
  };
  return Object.entries({ ...builtIn, ...s.properties }).map(([name, value]) => ({ name, value: value == null ? '' : String(value) }));
}

// settings.server_fields (array of keys) limits what /servers returns to TSSA clients; strict clients
// such as HAC reject records with fields they don't know. The mock's own console always gets everything.
function sServer(s, req) {
  const full = sServerFull(s);
  const fields = store.settings.server_fields;
  if (!Array.isArray(fields) || !fields.length || req?.headers?.['x-mock-ui']) return full;
  return Object.fromEntries(fields.filter((k) => k in full).map((k) => [k, full[k]]));
}

function sServerFull(s) {
  const meta = OS_META[s.family] || {};
  return {
    id: s.id, server_id: s.id, name: s.name, server_name: s.name, ip_address: s.ip_address,
    os: s.os, os_name: s.os, os_version: shortOsVersion(s), os_version_full: s.os_version, os_release: meta.release,
    os_vendor: meta.vendor, vendor: meta.vendor, os_platform: s.architecture, platform: s.platform, architecture: s.architecture,
    os_architecture: s.architecture, device_type: 'server', device_state: s.decommissioned ? 'Decommissioned' : 'Enrolled',
    agent_status: s.agent_status, agent_version: s.agent_version, agent_port: s.agent_port,
    is_online: s.agent_status === 'agent is alive', is_decommissioned: !!s.decommissioned,
    date_created: iso(s.date_created), last_reboot: iso(s.last_reboot), cpu_count: s.cpu_count, memory_mb: s.memory_mb,
    properties: serverPropertyList(s), property_map: s.properties, db_key: dbkey('DeviceKeyImpl', s.id),
    patch_catalog: { id: s.catalog_id, name: store.catalog(s.catalog_id)?.name },
    missing_patch_count: (store.state.missing[s.id] || []).length,
    last_patch_analysis: s.last_analysis ? { job_run_id: s.last_analysis.run_id, date: iso(s.last_analysis.time), missing_patch_count: s.last_analysis.missing_patch_ids.length } : null,
  };
}

// --- real TSSA 26.3 shapes (copied from captures of a real server's REST responses) ---
const tssaDate = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
const tssaTime = (ms) => new Date(ms).toISOString().slice(0, 23).replace('T', ' ');
const nameRef = (id, name) => ({ id, name });
const BLADMIN = { user: nameRef(1000010, 'BLAdmin'), role: nameRef(1000010, 'BLAdmins') };
const guidOf = (id) => require('crypto').createHash('md5').update(`server-${id}`).digest('hex').toUpperCase();

// os_version as TSSA reports it: "2022", "Red Hat ES 9.6", "Ubuntu 24.04", "Oracle Enterprise Linux Server release 9.6".
function realOsVersion(s) {
  const n = (s.os_version.match(/\d+(\.\d+)?/) || [''])[0];
  if (s.family === 'WINDOWS') return shortOsVersion(s);
  if (s.family === 'RHEL9' || s.family === 'RHEL8') return `Red Hat ES ${n}`;
  if (s.family === 'OL8') return `Oracle Enterprise Linux Server release ${n}`;
  if (s.family === 'UBUNTU') return shortOsVersion(s);
  return s.os_version;
}

function agentVersionOf(v) {
  const [major, minor, patch, build] = String(v || '').split('.').map(Number);
  return { major_version: major || 0, minor_version: minor || 0, patch_version: patch || 0, build_version: build || 0 };
}

function realServerProperties(s) {
  const meta = OS_META[s.family] || {};
  const win = s.family === 'WINDOWS';
  const alive = s.agent_status === 'agent is alive';
  const host = s.name.split('.')[0];
  const av = agentVersionOf(s.agent_version);
  return {
    NAME: s.name, HOST: host, FQ_HOST: s.name, GUID: guidOf(s.id), IP_ADDRESS: s.ip_address, DESCRIPTION: '',
    OS: s.os, 'OS_ENUMERATED_VALUE*': s.os, OS_VENDOR: meta.vendor || '', OS_VERSION: realOsVersion(s), OS_RELEASE: meta.release || '',
    OS_PLATFORM: s.architecture, OS_PATCHLEVEL: win ? 'None' : meta.release || 'None',
    BUILD_ENVIRONMENT: win ? 'Windows2003-x86_64' : 'LinuxRedHatAS5-x86_64', RSCD_VERSION: s.agent_version,
    'AGENT_MAJOR_VERSION*': String(av.major_version), 'AGENT_MINOR_VERSION*': String(av.minor_version),
    'AGENT_PATCH_VERSION*': String(av.patch_version), 'AGENT_BUILD_VERSION*': String(av.build_version), 'AGENT_PLATFORM*': 'Unknown',
    AGENT_STATUS: alive ? 'Available' : 'Unavailable', AGENT_STATUS_REASON: alive ? '' : 'Connection refused', IS_ONLINE: 'true',
    STAGING_DIR: win ? '/temp/stage' : '/var/tmp/stage', 'PATCHING_TOOL*': win ? '' : s.family === 'UBUNTU' ? 'apt' : 'yum',
    DATE_CREATED: tssaDate(s.date_created), DATE_MODIFIED: tssaDate(s.date_created), ROLE_CREATED: 'BLAdmins', ROLE_MODIFIED: 'BLAdmins', USER_MODIFIED: 'BLAdmin',
    ...Object.fromEntries(Object.entries(s.properties || {}).map(([k, v]) => [k, v == null ? '' : String(v)])),
  };
}

// One server as GET /servers lists it. additional_detail=true adds the properties map.
function sServerReal(s, { withProps = false, acl = false } = {}) {
  const meta = OS_META[s.family] || {};
  const win = s.family === 'WINDOWS';
  const alive = s.agent_status === 'agent is alive';
  const aclId = 2001000 + (s.id % 1000);
  const out = {
    id: s.id, guid: guidOf(s.id), name: s.name, description: '', ip_address: s.ip_address,
    os: win ? { id: 1, name: 'Windows', nsh_name: 'WindowsNT' } : { id: 3, name: 'Linux', nsh_name: 'Linux' },
    os_release: meta.release || '', os_vendor: meta.vendor || '', os_version: realOsVersion(s),
    build_environment: win ? 'Windows2003-x86_64' : 'LinuxRedHatAS5-x86_64', agent_version: agentVersionOf(s.agent_version),
    subnet_mask: '255.255.240.0', ip_address_in_use: false, pm_device_id: 0,
    device_type: { id: 1, name: 'Server' },
    device_state: s.decommissioned ? { id: 60, name: 'Decommissioned' } : { id: 50, name: 'Enrolled' },
    agent_state: alive ? { id: 100, name: 'Available' } : { id: 50, name: 'Unavailable' },
    agent_platform: { id: 0, name: 'Unknown' },
    is_repeater: false, repeater_name: '', repeater_staging_directory: '/tmp/stage', repeater_cache_max_size: 0,
    staging_directory: win ? '/temp/stage' : '/var/tmp/stage',
    date_created: tssaDate(s.date_created), date_modified: tssaDate(s.date_created),
    role_created: BLADMIN.role, role_modified: BLADMIN.role, user_created: BLADMIN.user, user_modified: BLADMIN.user,
    ...(acl
      ? { acl: { acl_id: aclId, aces: [{ role_id: 1000010, role_name: 'BLAdmins', authorization_id: 2900, authorization_name: 'Server.*' }], acl_policies: [] } }
      : { acl_id: aclId }),
    os_platform: s.architecture, os_patch_level: win ? 'None' : meta.release || 'None',
    smart_hub_name: ' ', smart_agent_state: { id: 25, name: 'Unknown' },
  };
  if (withProps) out.properties = realServerProperties(s);
  return out;
}

const CATALOG_ACL = {
  acl_id: 2000065,
  aces: [
    { role_id: 1000008, role_name: 'Everyone', authorization_id: 10105, authorization_name: 'PatchCatalog.Read' },
    { role_id: 1000010, role_name: 'BLAdmins', authorization_id: 10100, authorization_name: 'PatchCatalog.*' },
  ],
  acl_policies: [],
};
const PATCH_ACL = (win) => (win
  ? { acl_id: 2000021, aces: [{ role_id: 1000010, role_name: 'BLAdmins', authorization_id: 5900, authorization_name: 'WindowsSoftware.*' }], acl_policies: [] }
  : { acl_id: 2000023, aces: [{ role_id: 1000010, role_name: 'BLAdmins', authorization_id: 5700, authorization_name: 'LinuxSoftware.*' }], acl_policies: [] });
const depotDate = (ms) => `${tssaDate(ms)}.0`;
const patchTypeOf = (p) => (/security/i.test(p.classification) ? 'security_patch' : 'non_security_patch');
const DEPOT_FOLDER = { WINDOWS: 'Windows', RHEL9: 'Redhat', RHEL8: 'Redhat', OL8: 'OracleLinux', UBUNTU: 'Ubuntu', SLES: 'SuSE' };
const saveIn = (c) => `Depot/MyCatalogs/${DEPOT_FOLDER[c.family] || 'Linux'}/${c.name}`;
// os_arch on Linux catalog items, as TSSA writes it: "RHES9x86_64"
const OS_ARCH = { RHEL9: 'RHES9x86_64', RHEL8: 'RHES8x86_64', OL8: 'OEL8x86_64', SLES: 'SLES15x86_64', UBUNTU: 'UBUNTU2204x86_64' };

// Common depot-object fields of catalog items (patches and bulletin/errata containers).
function depotFields(c, x, objectType, softwareType, created) {
  const win = c.family === 'WINDOWS';
  return {
    id: x.id, version_id: 1, bl_value_id: 2100000 + (x.id % 100000), name: x.name, description: x.description,
    parent_group_id: c.id, save_in: saveIn(c), object_type: objectType,
    user_created: BLADMIN.user, role_created: BLADMIN.role, user_modified: BLADMIN.user, role_modified: BLADMIN.role,
    bl_acl: win ? 2000021 : 2000023, date_created: `${tssaDate(created)}.587`, date_modified: `${tssaDate(created)}.647`, is_external_repository: false,
    software_type: softwareType, os: win ? { id: 1, name: 'Windows' } : { id: 3, name: 'Linux' }, acl: PATCH_ACL(win),
  };
}

// One container per bulletin/advisory id, numbered in order of first appearance.
function bulletinGroups(c) {
  const groups = new Map();
  for (const p of c.patch_ids.map((id) => store.patch(id)).filter(Boolean)) {
    if (!groups.has(p.bulletin_id)) groups.set(p.bulletin_id, { id: c.id * 10 + groups.size + 1, name: p.bulletin_id, patches: [] });
    groups.get(p.bulletin_id).patches.push(p);
  }
  return groups;
}

// "libxml2-2.9.13-10.el9_6.x86_64.rpm" -> { package, version, release, arch }
function rpmParts(file) {
  const m = String(file).replace(/\.rpm$/, '').match(/^(.+)-([^-]+)-([^-]+)\.([^.]+)$/);
  return m ? { package: m[1], version: m[2], release: m[3], arch: m[4] } : { package: file, version: '', release: '', arch: 'x86_64' };
}

// GET /api/v2/catalogs/{id}/patches item, as captured from a real server: Windows { hotfix: {...} },
// Red Hat { rpms: {...} }. Ubuntu is not captured; it uses { debian_package } as a guess.
function sPatchV2(c, p, groups = bulletinGroups(c)) {
  const created = c.last_updated || p.release_date;
  const g = groups.get(p.bulletin_id);
  const containers = g ? [{ id: g.id, name: g.name }] : [];
  if (c.family === 'WINDOWS') {
    const kb = p.name.replace(/^KB/, '');
    return {
      hotfix: {
        patch_product: { id: 2000003, name: p.product }, language: { id: 8, code: '0409', name: 'English', extension: 'en' },
        service_pack: { id: 2, name: 'Gold' }, hotfix_type: { id: 0, name: 'Windows Patch', bl_value_id: 8101 },
        bulletin_id: p.bulletin_id, patch_guid: guidOf(p.id).toLowerCase().replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'),
        patch_name: p.packages[0], shavlik_file_name: p.packages[0], custom_install: false, q_number: `Q${kb}`,
        cve_url: '', kb_url: `https://support.microsoft.com/kb/${kb}`, patch_impact: p.severity, vendor_name: 'Microsoft', patch_type: patchTypeOf(p),
        shavlik_download_url: `https://catalog.s.download.windowsupdate.com/${p.packages[0]}`, date_posted: depotDate(p.release_date),
        superseded_by: p.superseded ? 'superseded' : '',
        ...depotFields(c, { id: p.id, name: `${p.packages[0]}-${p.bulletin_id}-en-${p.product}-Gold`, description: p.title }, { id: 114, name: 'Hotfix Windows Installable' }, { id: 100005, name: 'Hotfix', location: '' }, created),
        install_command: '"??SOURCE??" /quiet /norestart', uninstall_command: '',
        containers, cve_ids: (p.cves || []).join(','), size: p.size, reboot_required: !!p.reboot_required, uninstallable: false,
      },
    };
  }
  if (c.family === 'UBUNTU') {
    return {
      debian_package: {
        package_name: p.product, file_name: p.packages[0], errata_id: p.bulletin_id, vendor_name: 'Ubuntu',
        patch_type: patchTypeOf(p), patch_impact: p.severity, date_posted: depotDate(p.release_date), arch: 'amd64',
        ...depotFields(c, { id: p.id, name: p.packages[0].replace(/\.deb$/, ''), description: p.title }, { id: 60102, name: 'Debian Package Installable' }, { id: 100010, name: 'Debian Package', location: '' }, created),
        containers, cve_ids: (p.cves || []).join(', '), size: p.size, reboot_required: !!p.reboot_required, uninstallable: true,
      },
    };
  }
  const r = rpmParts(p.packages[0]);
  return {
    rpms: {
      os_arch: OS_ARCH[c.family] || 'x86_64', summary: p.title.replace(/^\w+: /, ''), rpm_group: 'Unspecified',
      build_date: depotDate(p.release_date), vendor_name: c.family === 'OL8' ? 'Oracle America' : c.family === 'SLES' ? 'SUSE LLC' : 'Red Hat, Inc.',
      license: 'GPLv2+', size: String(p.size), package: r.package, rpm_arch: r.arch, rpm_release: r.release, rpm_version: r.version,
      ...depotFields(c, { id: p.id, name: p.packages[0], description: p.title }, { id: 68, name: 'RPM Installable' }, { id: 200003, name: 'RPM', location: '' }, created),
      install_command: 'rpm -Uiv ??SOURCE??', uninstall_command: 'rpm -e ??PACKAGENAME??', containers,
    },
  };
}

// GET /api/v1/catalogs/{id}/containers item, as captured from a real server: one { bulletin } (Windows)
// or { errata } (Red Hat) per bulletin/advisory id.
const ERRATA_TYPE = (p) => (/security/i.test(p.classification) ? 'security advisory' : /enhancement/i.test(p.classification) ? 'product enhancement advisory' : 'bug fix advisory');
function catalogContainers(c) {
  const created = c.last_updated || Date.now();
  return [...bulletinGroups(c).values()].map(({ id, name: bid, patches: ps }) => {
    const p = ps[0];
    const cveList = [...new Set(ps.flatMap((x) => x.cves || []))];
    const posted = depotDate(Math.min(...ps.map((x) => x.release_date)));
    if (c.family === 'WINDOWS') {
      return {
        bulletin: {
          bulletin_id: bid, vendor_name: 'Microsoft', patch_type: patchTypeOf(p), kb_url: `https://msrc.microsoft.com/update-guide/releaseNote/${bid}`,
          cve_ids: cveList.join(','), date_posted: posted, vendor_impact: p.severity, q_numbers: `[${ps.map((x) => `Q${x.name.replace(/^KB/, '')}`).join(', ')}]`, bulletin_title: p.title,
          superceded_by: '', is_obsolete_bulletin: ps.every((x) => x.superseded), iava_id: '',
          ...depotFields(c, { id, name: bid, description: p.title }, { id: 308, name: 'Windows Bulletin Installable' }, { id: 100006, name: 'Windows Bulletin', location: '' }, created),
          install_command: '"??SOURCE??" /quiet /norestart', uninstall_command: '', container_ids: [],
        },
      };
    }
    const sev = ['Critical', 'Important', 'Moderate', 'Low'].includes(p.severity) ? p.severity : 'None';
    return {
      errata: {
        advisory: bid, synopsis: p.title.replace(/^\w+: /, ''), issue_date: posted, errata_type: ERRATA_TYPE(p),
        topic: `An update for ${p.product} is now available for ${c.name.replace(/ Patch Catalog$/, '')}.`, severity: sev,
        os_arch: OS_ARCH[c.family] || 'x86_64', cve_ids: cveList.join(', '),
        ...depotFields(c, { id, name: bid, description: p.title }, { id: 305, name: 'Red Hat Errata Installable' }, { id: 200007, name: 'Red Hat Errata', location: '' }, created),
        install_command: 'rpm -Uiv ??SOURCE??', uninstall_command: 'rpm -e ??PACKAGENAME??', container_ids: [],
      },
    };
  });
}

// Parent of "/Workspace/Jobs/Patching" is "/Workspace/Jobs"; parent of "/Foo" and of "/" is null
// (the caller substitutes a root parent so Group.getParent() is never null).
function parentPathOf(path) {
  if (!path || path === '/') return null;
  const i = String(path).lastIndexOf('/');
  return i <= 0 ? '/' : path.slice(0, i);
}

function parentRef(path, find) {
  const pp = parentPathOf(path);
  // The Jobs root has no real parent. Policy service still calls getParent().getPath() on every
  // group (including that root) while it searches for the default "/<id>_<role>" folder.
  if (!pp) return { id: 0, name: '', path: '/' };
  const known = find ? find(pp) : null;
  return {
    id: known?.id || 0,
    name: known?.name ?? (pp === '/' ? '/' : pp.split('/').pop()),
    path: known?.path || pp,
  };
}

function sGroup(g) {
  const parent = parentRef(g.path, (p) => store.state.groups.find((x) => x.path === p));
  return {
    id: g.id, name: g.name, path: g.path, group_path: g.path, type: g.group_type, object_type: g.object_type,
    criteria: g.criteria, member_count: (g.member_ids || []).length,
    db_key: dbkey(g.group_type === 'SMART' ? 'SSmartServerGroupKeyImpl' : 'SStaticServerGroupKeyImpl', g.id),
    parent_group_id: parent.id, parent, parent_group: parent,
  };
}

function sRunBrief(r) {
  if (!r) return null;
  return { job_run_id: r.id, id: r.id, status: engine.status(r), start_time: iso(r.start_time), end_time: engine.status(r) === 'RUNNING' ? null : iso(r.aborted_at || r.end_time) };
}

// Policy service JobResponse.id is JobResponse.Id, and that bean has only job_id and job_version.
// A bare number fails, and an extra "id" property is rejected as unrecognized.
function jobResponseId(id) {
  return { job_id: id, job_version: 1 };
}

function sJob(j) {
  const runs = store.state.runs.filter((r) => r.job_id === j.id);
  const last = runs[runs.length - 1];
  const out = {
    id: jobResponseId(j.id), job_id: j.id, name: j.name, job_name: j.name, type: JOB_TYPE_DETAIL[j.type] || { id: 0, name: JOB_TYPE_LABEL[j.type] || j.type }, job_type: j.type, job_type_label: JOB_TYPE_LABEL[j.type], model_type: MODEL_TYPE[j.type],
    group_path: j.group_path, group_name: j.group_path, path: j.group_path, group: { path: j.group_path }, description: j.description, created_by: j.created_by,
    date_created: iso(j.date_created), last_modified: iso(j.last_modified), db_key: dbkey('SJobModelKeyImpl', j.id),
    targets: {
      servers: (j.targets.server_ids || []).map((id) => store.server(id)).filter(Boolean).map((s) => ({ id: s.id, name: s.name })),
      groups: (j.targets.group_ids || []).map((id) => store.group(id)).filter(Boolean).map((g) => ({ id: g.id, name: g.name, path: g.path, type: g.group_type })),
      server_groups: (j.targets.group_ids || []).map((id) => store.group(id)).filter(Boolean).map((g) => ({ id: g.id, path: g.path })),
    },
    schedules: (j.schedules || []).map(({ fired, next_run: next, ...s }) => (next ? { ...s, next_run: iso(next) } : s)),
    is_generated: !!j.generated, run_count: runs.length, last_job_run: sRunBrief(last),
  };
  const p = j.params || {};
  if (p.catalog_id) { const c = store.catalog(p.catalog_id); out.catalog = { id: c.id, name: c.name, path: c.group_path, os: c.os }; out.analysis_only = !!p.analysis_only; out.remediate = !!p.remediate; out.reboot_option = p.reboot; out.patch_container = p.container; }
  if (p.script_id) {
    const sc = store.script(p.script_id);
    out.nsh_script = { id: sc.id, name: sc.name, group_path: sc.group_path }; out.arguments = p.arguments || [];
    out.script_parameters_details = (sc.parameters || []).map((x, i) => ({ name: x.name, value: p.arguments?.[i] ?? x.default ?? '' }));
  }
  if (p.package_id) {
    const b = store.blpackage(p.package_id);
    out.blpackage = { id: b.id, name: b.name, group_path: b.group_path }; out.phases = p.phases;
    out.software_list = [{ id: b.id, name: b.name, properties: [] }];   // HAC's wizard reads software_list[0] and basic.job_options
    out.basic = { job_options: { reboot_options: 'use_item_defined' } };
  }
  if (p.template_id) { const t = store.template(p.template_id); out.template = { id: t.id, name: t.name }; out.templates = [{ id: t.id, name: t.name, version_id: t.id, group: { path: t.group_path } }]; }
  if (p.child_job_ids) {
    const children = p.child_job_ids.map((id) => store.job(id)).filter(Boolean);
    out.member_jobs = children.map((c) => ({ id: c.id, name: c.name, type: JOB_TYPE_DETAIL[c.type] || { id: 0, name: c.type } }));
    out.members = children.map((c, i) => ({ id: c.id, name: c.name, path: c.group_path, sequence_id: i + 1, type: JOB_TYPE_DETAIL[c.type] || { id: 0, name: c.type } }));   // bean BatchJob
    out.is_job_targets = true;
  }
  if (p.patch_map) out.remediation_patch_count = Object.values(p.patch_map).reduce((a, x) => a + x.length, 0);
  return out;
}

// A run started by PATCH has no stored schedule. On a real TSSA that Execute Now is its own one-time
// schedule, so the run id serves as its id.
const scheduleIdOf = (r) => r.schedule_id || r.id;

function sRun(r) {
  const st = engine.status(r);
  const ev = engine.visibleEvents(r);
  const done = !['RUNNING', 'NOT_STARTED'].includes(st);
  const counts = { total: r.target_ids.length, succeeded: 0, failed: 0, warnings: 0, in_progress: 0 };
  if (done) for (const res of Object.values(r.results)) {
    if (res.status === 'FAILED') counts.failed++; else if (res.status === 'COMPLETED_WITH_WARNINGS') counts.warnings++; else counts.succeeded++;
  } else counts.in_progress = r.target_ids.length;
  const hadErrors = ev.some((e) => e.severity === 'ERROR');
  const hadWarnings = ev.some((e) => e.severity === 'WARNING');
  const stopped = st === 'ABORTED' || st === 'CANCELLED';
  return {
    id: r.id, job_run_id: r.id, job_id: r.job_id, job_name: r.job_name, job_type: r.job_type, group_path: r.job_group_path,
    status: st, job_run_status: st, is_running: st === 'RUNNING',
    had_errors: hadErrors, had_warnings: hadWarnings,
    // The fields of a real job run: the GET .../jobruns sample in BMC's "Examples of REST APIs".
    // HAC's policy Sync reads these and fails with an NPE when one is missing.
    object_type: JOB_TYPE_DETAIL[r.job_type] || { id: 0, name: r.job_type },
    job_run: { job_run_id: r.id }, job: { job_id: r.job_id, job_version: 1 },
    role_executed: { ...BLADMIN.role, name: r.role || BLADMIN.role.name }, user_executed: { ...BLADMIN.user, name: r.executed_by || BLADMIN.user.name },
    progress_status: !done ? 'running' : st === 'FAILED' || stopped ? 'failed' : 'complete',
    has_errors: hadErrors, has_warnings: hadWarnings, is_cancelled: stopped, is_reset: false, is_reboot: false,
    schedule_id: scheduleIdOf(r),
    start_time: iso(r.start_time), end_time: done ? iso(r.aborted_at || r.end_time) : null,
    progress: engine.progress(r), executed_by: r.executed_by, user_name: r.executed_by, role_name: r.role,
    application_server: r.app_server, target_counts: counts,
    targets: r.target_ids.map((id) => store.server(id)).filter(Boolean).map((s) => ({ id: s.id, name: s.name })),
    parent_job_run_id: r.parent_run_id, child_job_runs: r.child_run_ids.map((id) => store.run(id)).filter(Boolean).map((c) => ({ ...sRunBrief(c), job_id: c.job_id, job_name: c.job_name, job_type: c.job_type })),
    db_key: dbkey('SJobRunKeyImpl', r.id),
  };
}

// A job run for a TSSA client, which gets real TSSA times. The console keeps ISO times.
function sRunFor(req, r) {
  const out = sRun(r);
  if (req.headers['x-mock-ui']) return out;
  return { ...out, start_time: tssaTime(r.start_time), end_time: out.end_time ? tssaTime(r.aborted_at || r.end_time) : out.end_time };
}

function sEvent(e) {
  return { id: e.id, event_id: e.id, date: iso(e.time), time: iso(e.time), type: e.severity, severity: e.severity, log_type: e.severity, server: e.server, server_name: e.server, message: e.message };
}

function sResults(r) {
  const done = !['RUNNING', 'NOT_STARTED'].includes(engine.status(r));
  return r.target_ids.map((id) => {
    const s = store.server(id);
    const res = r.results[id] || {};
    return {
      server_id: id, server_name: s?.name, status: done ? (res.status || 'NOT_RUN') : 'RUNNING', exit_code: done ? res.exit_code ?? null : null,
      ...(done && res.output !== undefined ? { output: res.output } : {}),
      ...(done && res.missing_patch_ids ? { missing_patch_count: res.missing_count, critical_count: res.critical, important_count: res.important } : {}),
      ...(done && res.compliant !== undefined ? { compliant: res.compliant, non_compliant: res.non_compliant, not_applicable: res.not_applicable } : {}),
      ...(done && res.installed_patch_ids ? { installed_patch_count: res.installed_patch_ids.length, rebooted: !!res.rebooted } : {}),
    };
  });
}

function sPatch(p, extra = {}) {
  return {
    id: p.id, patch_id: p.id, name: p.name, patch_name: p.name, title: p.title, bulletin_id: p.bulletin_id, vendor_severity: p.severity, severity: p.severity,
    classification: p.classification, product: p.product, os: p.os, release_date: iso(p.release_date), size_bytes: p.size,
    reboot_required: p.reboot_required, superseded: p.superseded, cve_ids: p.cves, packages: p.packages, catalog_id: p.catalog_id, ...extra,
  };
}

// Catalog types and object types. Windows, Red Hat and Ubuntu ids were observed on a real TSSA 26.3
// server; Oracle Linux, SUSE and RPM/errata ids are best guesses.
const CATALOG_TYPE = {
  WINDOWS: { type: { id: 5022, name: 'Windows Catalog' }, os_type: 'Windows', objects: [{ id: 114, name: 'Hotfix Windows Installable' }, { id: 308, name: 'Windows Bulletin Installable' }] },
  RHEL9: { type: { id: 5020, name: 'Red Hat Catalog' }, os_type: 'Red Hat', objects: [{ id: 60, name: 'RPM Installable' }, { id: 5103, name: 'Red Hat Errata' }] },
  RHEL8: { type: { id: 5020, name: 'Red Hat Catalog' }, os_type: 'Red Hat', objects: [{ id: 60, name: 'RPM Installable' }, { id: 5103, name: 'Red Hat Errata' }] },
  OL8: { type: { id: 5021, name: 'Oracle Enterprise Linux Catalog' }, os_type: 'Oracle Enterprise Linux', objects: [{ id: 60, name: 'RPM Installable' }, { id: 5104, name: 'Oracle Enterprise Linux Errata' }] },
  UBUNTU: { type: { id: 7042, name: 'Ubuntu Catalog' }, os_type: 'Ubuntu', objects: [{ id: 60102, name: 'Debian Package Installable' }] },
  SLES: { type: { id: 5023, name: 'SuSE Catalog' }, os_type: 'SuSE', objects: [{ id: 60, name: 'RPM Installable' }, { id: 5105, name: 'SuSE Patch' }] },
};

// Java Date.toString() in UTC, as TSSA prints it: "Tue Oct 27 09:50:21 UTC 2026"
const javaDate = (ms) => {
  const d = new Date(ms);
  const [dow, mon, day, year, time] = d.toUTCString().replace(',', '').split(' ').map((x, i, a) => a[[0, 2, 1, 3, 4][i]]);
  return `${dow} ${mon} ${day} ${time} UTC ${year}`;
};

function catalogStatus(c, lastRun) {
  if (!lastRun) return undefined;
  const st = engine.status(lastRun);
  const running = st === 'RUNNING' || st === 'NOT_STARTED';
  const added = lastRun.effects?.find((e) => e.type === 'catalog_update')?.added || 0;
  const end = lastRun.aborted_at || lastRun.end_time;
  const meta = CATALOG_TYPE[c.family];
  const summary = running ? [] : meta.objects.flatMap((o, i) => ['ADDED', 'DOWNLOADED', 'UPDATED', 'OBSOLETED', 'FAILED', 'FAILED_TO_DOWNLOAD', 'INVALID_URL']
    .map((s) => ({ object_type: o, status: s, total_count: i === 0 && (s === 'ADDED' || s === 'DOWNLOADED') ? added : 0 })));
  return {
    progress_status: running ? 'running' : 'complete', is_usable: true,
    start_time: javaDate(lastRun.start_time), ...(running ? {} : { end_time: javaDate(end) }),
    ...(running ? {} : { result: { status: st === 'COMPLETED' ? 'passed' : 'failed', summary } }),
    start_time_epoch: lastRun.start_time, ...(running ? {} : { end_time_epoch: end }), job_run_id: lastRun.id,
  };
}

// Catalog update schedules as returned by GET /catalogs/{id}. HAC's Add Catalog form reads
// `schedules.length` and pre-fills a single daily/weekly/monthly entry. The monthly shape is copied
// from a schedule HAC stored for a real TSSA Windows catalog; Linux catalogs have none.
function catalogSchedules(c) {
  if (Array.isArray(c.schedules)) return c.schedules;
  if (c.os !== 'WINDOWS') return [];
  return [{ id: 45, monthly: { time: '00:01', week: { week_day: 'Wednesday', week_of_month: 'Second' }, is_last_of_month: false }, timezone: 'America/New_York', priority: 'NORMAL' }];
}

// Catalog filters in the shape HAC stored for catalogs from a real TSSA server (Windows: product
// category + language; Ubuntu: one entry per repo distribution). RPM-based catalog filter type ids are
// not known, so those use the Ubuntu-style entry with RPM repo URLs.
function catalogFilters(c) {
  if (c.family === 'WINDOWS') {
    const opts = [{ id: 15, value: 'English', type_id: 10, type_desc: 'windows language' }];
    let id = 16;
    for (const v of ['2016', '2019', '2022', '2025']) opts.push({ id: id++, value: `Microsoft Windows Server ${v}`, type_id: 14, type_desc: 'windows prodcut catagory name' });
    return [{ id: 5, type: 10, options: opts, description: 'Windows product category' }];
  }
  // Red Hat filter as a real TSSA 26.3 server returns it (Redhat9 catalog capture).
  if (c.family === 'RHEL9' || c.family === 'RHEL8') {
    const v = c.family === 'RHEL9' ? '9' : '8';
    let oid = 920;
    return [{
      id: 247, type: 6,
      options: [
        { value: 'x86_64', type_id: 2, type_desc: 'arch' }, { value: `RHES${v}`, type_id: 1, type_desc: 'os' },
        { value: '7', type_id: 5, type_desc: 'redhat errata type' }, { value: '15', type_id: 6, type_desc: 'redhat errata severity' },
        { value: `Red Hat Enterprise Linux Server (v. ${v} for 64-bit x86_64)`, type_id: 7, type_desc: 'redhat channel name' },
        { value: `rhel-${v}-for-x86_64-baseos-rpms`, type_id: 13, type_desc: 'redhat channel lable' },
        { value: '1', type_id: 39, type_desc: 'redhat repo type' },
        { value: `https://cdn.redhat.com/content/dist/rhel${v}/${v}/x86_64/baseos/os`, type_id: 40, type_desc: 'redhat channel url' },
      ].map((o) => ({ id: oid++, ...o })),
      description: 'Redhat errata type',
    }];
  }
  const repo = {
    UBUNTU: { flavor: 'Ubuntu', ver: '22.04', base: 'http://archive.ubuntu.com/ubuntu/', dists: ['jammy', 'jammy-updates', 'jammy-security'] },
    RHEL9: { flavor: 'Red Hat', ver: '9', base: 'https://cdn.redhat.com/content/dist/rhel9/9/x86_64/', dists: ['baseos', 'appstream'] },
    RHEL8: { flavor: 'Red Hat', ver: '8', base: 'https://cdn.redhat.com/content/dist/rhel8/8/x86_64/', dists: ['baseos', 'appstream'] },
    OL8: { flavor: 'Oracle Linux', ver: '8', base: 'https://yum.oracle.com/repo/OracleLinux/OL8/', dists: ['baseos/latest', 'appstream'] },
    SLES: { flavor: 'SUSE', ver: '15 SP5', base: 'https://updates.suse.com/SUSE/Updates/SLE-Product-SLES/15-SP5/x86_64/', dists: ['update'] },
  }[c.family];
  let oid = 449;
  return repo.dists.map((dist, i) => ({
    id: 54 + i, type: 24, description: `${repo.flavor} os arch`,
    options: [
      { value: repo.flavor, type_id: 32, type_desc: 'Debian flavor' }, { value: repo.ver, type_id: 33, type_desc: 'debian os version' },
      { value: 'x86_64', type_id: 2, type_desc: 'arch' }, { value: repo.base, type_id: 34, type_desc: 'debian baseurl' },
      { value: dist, type_id: 35, type_desc: 'debian disribution' }, { value: 'Main', type_id: 36, type_desc: 'debian component' },
      { value: `${repo.base}dists/${dist}/main/binary-amd64/Packages.gz`, type_id: 37, type_desc: 'debian metadata url' },
      { value: repo.base, type_id: 38, type_desc: 'debian payload url' },
    ].map((o) => ({ id: oid++, ...o })),
  }));
}

function sCatalog(c, req, detail = false) {
  const runs = store.state.runs.filter((r) => r.job_type === 'CATALOG_UPDATE_JOB' && store.job(r.job_id)?.params.catalog_id === c.id);
  const last = runs[runs.length - 1];
  const meta = CATALOG_TYPE[c.family];
  const groupPath = c.group_path;
  // A real 26.3 server sends no status on catalogs; settings.catalog_status adds the mock's guessed one.
  const withStatus = last && (store.settings.catalog_status || req?.headers['x-mock-ui']);
  // GET /catalogs/{id} on a real server returns only these fields (no type, group or description).
  if (detail && !req?.headers['x-mock-ui']) {
    return {
      id: c.id, name: c.name, is_usable: c.patch_ids.length > 0, schedules: catalogSchedules(c), acl: CATALOG_ACL, filters: catalogFilters(c),
      ...(withStatus ? { status: catalogStatus(c, last) } : {}),
    };
  }
  // Field set and order match a real TSSA /api/v1/catalogs response.
  const out = {
    id: c.id, name: c.name, description: c.description, type: meta.type, os_type: meta.os_type,
    group: { id: 2000154 + (c.family === 'WINDOWS' ? 0 : 1), name: c.name, path: groupPath },
    ...(withStatus ? { status: catalogStatus(c, last) } : {}), acl_id: 2000064,
    ...(detail ? { schedules: catalogSchedules(c), filters: catalogFilters(c) } : {}),
  };
  if (!req || !req.headers['x-mock-ui']) return out;
  // Extra fields for the mock's own console only.
  return {
    ...out, os: c.os, family: c.family, group_path: groupPath, source: c.source, filters: c.filters, patch_count: c.patch_ids.length,
    last_updated: iso(c.last_updated), update_status: last ? engine.status(last) : c.update_status,
    containers: c.containers.map((k) => ({ id: k.id, name: k.name, patch_count: k.patch_ids.length })),
    db_key: dbkey('SPatchCatalogKeyImpl', c.id), last_update_job_run: sRunBrief(last),
  };
}

const sScript = (x, full) => ({ id: x.id, name: x.name, group_path: x.group_path, description: x.description, script_type: x.script_type, platforms: x.platforms, parameters: x.parameters, version: x.version, created_by: x.created_by, date_created: iso(x.date_created), db_key: dbkey('DepotObjectKeyImpl', x.id), ...(full ? { script_content: x.content } : {}) });
const sPkg = (x) => ({ id: x.id, name: x.name, group_path: x.group_path, description: x.description, platforms: x.platforms, version: x.version, item_count: x.items.length, items: x.items, created_by: x.created_by, date_created: iso(x.date_created), db_key: dbkey('DepotObjectKeyImpl', x.id) });

// --- helpers ---------------------------------------------------------------
function paginate(req, key, items) {
  const q = req.query;
  const asked = Number(q.size || q.limit || q.page_size || 500);
  const size = Math.max(1, asked === 0 ? items.length : asked);   // HAC sends size=0 for everything
  const page = Math.max(0, Number(q.page || 0));
  const offset = q.offset !== undefined ? Number(q.offset) : page * size;
  const slice = items.slice(offset, offset + size);
  const last = Math.max(0, Math.ceil(items.length / size) - 1);
  // Shape observed from a real TSSA 26.3 server: { <key>: [...], total_records, links: [{ rel, href }] }
  const base = `https://${req.headers.host || 'localhost'}${req.path}`;
  const link = (p) => `${base}?page=${p}&size=${size}`;
  const links = [{ rel: 'self', href: link(page) }, { rel: 'last', href: link(last) }, { rel: 'first', href: link(0) }];
  if (page > 0) links.push({ rel: 'previous', href: link(page - 1) });
  if (page < last) links.push({ rel: 'next', href: link(page + 1) });
  return { [key]: slice, total_records: items.length, links };
}

function filterByName(req, items, field = 'name') {
  const n = req.query.name || req.query.filter;
  if (!n) return items;
  const needle = String(n).toLowerCase().replace(/\*/g, '');
  return items.filter((x) => String(x[field]).toLowerCase().includes(needle));
}

const must = (v, what) => { if (!v) throw new HttpError(404, `${what} not found`); return v; };

function jobOf(type, id) {
  const j = must(store.job(id), `Job with id ${id}`);
  // HAC runs a compliance remediation job through deploy-jobs but reads its runs through compliance-jobs.
  const remediation = type === 'COMPLIANCE_JOB' && j.params?.compliance_remediation;
  if (type && j.type !== type && !remediation) throw new HttpError(404, `Job with id ${id} is not of type ${type}`);
  return j;
}

function runOf(job, rid) {
  const r = must(store.run(rid), `Job run with id ${rid}`);
  if (job && r.job_id !== job.id) throw new HttpError(404, `Job run ${rid} does not belong to job ${job.id}`);
  engine.materialize(r);
  return r;
}

// Callback settings in a job create/execute body: {notifications:{notification_url:{url,...}}}, the
// same shape HAC uses in catalog schedules, a bare notification_url, or the PATCH execute body
// itself ({url, accept, retry_count, retry_pause, retry_timeout} for /policies/notify).
function notificationsOf(b) {
  if (!b || typeof b !== 'object') return null;
  const n = b.notifications?.notification_url || b.notification_url || b.schedules?.find?.((s) => s?.notifications)?.notifications?.notification_url;
  if (n) return { notification_url: typeof n === 'string' ? { url: n } : n };
  if (typeof b.url === 'string' && /^https?:\/\//i.test(b.url)) return { notification_url: b };
  return null;
}

function jobGroupRef(job) {
  const list = ensureFolders('job');
  const g = list.find((x) => x.path === job.group_path);
  const path = job.group_path || '/';
  return { id: g?.id || 0, name: g?.name ?? (path === '/' ? '' : path.split('/').pop()), path };
}

function execute(req, job) {
  const targets = store.parseTargets(req.body);
  const run = engine.startRun(job, { targets, user: req.session.user, role: req.session.role, notifications: notificationsOf(req.body) });
  const runBody = sRun(run);
  const end = runBody.end_time || '';
  // Policy service does json.get(field).asText() and NPEs when the field is absent.
  // Without schedule_id it rejects the execute whatever the HTTP status is, and reports message as
  // the error (HTTP 400, errors: [message]). Keep message empty.
  const jobRun = {
    job_run_id: run.id, id: run.id, name: job.name, job_name: job.name,
    status: runBody.status, start_time: runBody.start_time, end_time: end,
  };
  return {
    status: 202,
    body: {
      ...sJob(job),
      group: jobGroupRef(job),
      schedule_id: runBody.schedule_id,
      job_run_id: run.id,
      job_run: jobRun,
      status: runBody.status,
      job_run_status: runBody.status,
      start_time: runBody.start_time,
      end_time: end,
      is_running: runBody.is_running,
      executed_by: run.executed_by, user_name: run.executed_by, role_name: run.role,
      message: '',
    },
  };
}

// Job and depot folders are a real tree (root "/", then every ancestor of a job or depot path).
// HAC's policy service builds each group's full path as parent.getPath() + "/" + name, and creates
// the default policy folder "/<securityGroupId>_<role>" under the Jobs root. A null parent NPEs:
// Group$Parent.getPath() because Group.getParent() is null.
const FOLDER_KIND = {
  job: { key: 'job_groups', object_type: 'JOB', db: 'SJobGroupKeyImpl' },
  depot: { key: 'depot_groups', object_type: 'DEPOT', db: 'SDepotGroupKeyImpl' },
};

function folderKind(type) {
  const t = String(type || '').toLowerCase();
  if (t === 'job' || t === 'jobs') return 'job';
  if (t === 'depot' || t === 'depots') return 'depot';
  return null;
}

function folderSources(kind) {
  if (kind === 'job') return store.state.jobs.map((j) => j.group_path).filter(Boolean);
  return [...store.state.scripts, ...store.state.blpackages, ...store.state.software, ...store.state.depot_files, ...store.state.templates]
    .map((x) => x.group_path).filter(Boolean);
}

function ensureFolders(kind) {
  const meta = FOLDER_KIND[kind];
  if (!store.state[meta.key]) store.state[meta.key] = [];
  const list = store.state[meta.key];
  const have = new Set(list.map((g) => g.path));
  // Both trees have a root "/". HAC passes its id as parent_group_id when it creates a default folder.
  const want = new Set(['/']);
  for (const raw of folderSources(kind)) {
    let p = raw;
    while (p && p !== '/') {
      want.add(p);
      const next = parentPathOf(p);
      if (!next || next === p) break;
      p = next;
    }
  }
  let added = false;
  const ordered = [...want].sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b));
  for (const path of ordered) {
    if (have.has(path)) continue;
    list.push({
      id: store.nextId(),
      name: path === '/' ? '' : path.split('/').pop(),
      path,
      group_type: 'STATIC',
      object_type: meta.object_type,
      description: '',
    });
    have.add(path);
    added = true;
  }
  if (added) store.saveSoon();
  return list;
}

function sFolder(g, list, kind) {
  const meta = FOLDER_KIND[kind];
  const parent = parentRef(g.path, (p) => list.find((x) => x.path === p));
  return {
    id: g.id, name: g.name, path: g.path, group_path: g.path, description: g.description || '',
    type: g.group_type || 'STATIC', object_type: g.object_type || meta.object_type,
    parent_group_id: parent.id, parent, parent_group: parent,
    db_key: dbkey(meta.db, g.id),
  };
}

function folderById(id) {
  const n = Number(id);
  if (!Number.isFinite(n) || !n) return null;
  for (const kind of Object.keys(FOLDER_KIND)) {
    const list = ensureFolders(kind);
    const g = list.find((x) => x.id === n);
    if (g) return { g, list, kind };
  }
  return null;
}

function parentFromBody(list, b) {
  const explicit = b.parent_group_id ?? b.parentGroupId ?? b.parent?.id ?? b.parent_group?.id;
  if (explicit !== undefined && explicit !== null && String(explicit) !== '') {
    const id = Number(explicit);
    if (!id) return list.find((g) => g.path === '/') || null;
    return list.find((g) => g.id === id) || null;
  }
  const ppath = b.parent_path || b.parent?.path || b.parent_group?.path || b.parent_group_path;
  if (ppath) return list.find((g) => g.path === ppath) || null;
  return list.find((g) => g.path === '/') || null;
}

function createFolder(kind, b) {
  const list = ensureFolders(kind);
  const meta = FOLDER_KIND[kind];
  const name = b.name || String(b.path || b.group_path || '').split('/').filter(Boolean).pop();
  if (!name) throw new HttpError(400, 'name is required');
  let path = b.path || b.group_path || null;
  if (!path) {
    const parent = parentFromBody(list, b) || list.find((g) => g.path === '/');
    const pp = parent?.path || '/';
    path = pp === '/' ? `/${name}` : `${pp}/${name}`;
  }
  let g = list.find((x) => x.path === path);
  if (!g) {
    const missing = [];
    let p = parentPathOf(path);
    while (p) {
      if (!list.some((x) => x.path === p)) missing.push(p);
      p = parentPathOf(p);
    }
    for (const anc of missing.reverse()) {
      list.push({
        id: store.nextId(), name: anc === '/' ? '' : anc.split('/').pop(), path: anc,
        group_type: 'STATIC', object_type: meta.object_type, description: '',
      });
    }
    g = { id: store.nextId(), name, path, group_type: 'STATIC', object_type: meta.object_type, description: b.description || '' };
    list.push(g);
    store.saveSoon();
  }
  // HAC needs the wrapper: a flat group fails with "Error while creating Group", whatever the status.
  return { status: 200, body: { group: { id: g.id, name: g.name, path: g.path } } };
}

// Group a new job is saved in. HAC sends the folder it just created as group_id / group.path.
function jobGroupPath(b) {
  const direct = b.group_path || b.group_name || b.job_group_path;
  if (typeof direct === 'string' && direct) return direct;
  const ref = b.group || b.job_group;
  if (typeof ref === 'string' && ref) return ref;
  if (ref && typeof ref === 'object') {
    if (ref.path || ref.group_path) return ref.path || ref.group_path;
    if (ref.id) {
      const hit = folderById(ref.id);
      if (hit) return hit.g.path;
    }
  }
  const id = b.group_id ?? b.job_group_id;
  if (id) {
    const hit = folderById(id);
    if (hit) return hit.g.path;
  }
  return null;
}

const withScheduleIds = (list) => (Array.isArray(list) ? list : []).map((s) => ({ ...s, id: s.id || store.nextId() }));

function createJob(req, type) {
  const b = req.body || {};
  if (!b.name && !b.job_name) throw new HttpError(400, 'name is required');
  const t = type || b.type || b.job_type;
  if (!t) throw new HttpError(400, 'job type is required');
  const ref = (v) => (v && typeof v === 'object' ? v.id ?? v.name : v);
  const params = {};
  if (t === 'PATCHING_JOB') {
    const c = must(store.catalog(ref(b.catalog ?? b.catalog_id ?? b.catalog_name)), 'Catalog');
    Object.assign(params, { catalog_id: c.id, analysis_only: b.analysis_only ?? !(b.remediate ?? b.remediation), remediate: !!(b.remediate ?? b.remediation), reboot: b.reboot_option || b.reboot || 'IF_REQUIRED', container: b.patch_container || b.container || 'All Patches' });
  } else if (t === 'NSH_SCRIPT_JOB') {
    const s = must(store.script(ref(b.nsh_script ?? b.script_id ?? b.script_name)), 'NSH script');
    Object.assign(params, { script_id: s.id, arguments: b.arguments || b.parameters || [] });
  } else if (t === 'DEPLOY_JOB') {
    const p = must(store.blpackage(ref(b.blpackage ?? b.package_id ?? b.package_name)), 'BLPackage');
    Object.assign(params, { package_id: p.id, phases: b.phases || ['SIMULATE', 'STAGE', 'COMMIT'] });
  } else if (t === 'COMPLIANCE_JOB') {
    // HAC sends templates: [{ id }]. The mock evaluates one template per job.
    const wanted = ref(b.template ?? b.template_id ?? b.templates?.[0]);
    const tp = must(store.template(wanted) || store.state.templates.find((x) => x.name === wanted), 'Template');
    params.template_id = tp.id;
  } else if (t === 'BATCH_JOB') {
    params.child_job_ids = (b.member_jobs || b.child_job_ids || b.jobs || []).map(ref).map((x) => store.job(x)?.id).filter(Boolean);
    params.stop_on_failure = !!b.stop_on_failure;
  } else if (t === 'FILE_DEPLOY_JOB') {
    params.file_id = store.state.depot_files[0].id;
  }
  const now = Date.now();
  const job = {
    id: store.nextId(), name: b.name || b.job_name, type: t, group_path: jobGroupPath(b) || '/Workspace/Jobs/Created via REST',
    description: b.description || '', created_by: req.session.user, date_created: now, last_modified: now, schedules: withScheduleIds(b.schedules),
    targets: store.parseTargets(b) || { server_ids: [], group_ids: [] }, params, notifications: notificationsOf(b),
  };
  store.state.jobs.push(job);
  store.saveSoon();
  if (b.execute_now) {
    const scheduleId = store.nextId();
    engine.startRun(job, { user: req.session.user, role: req.session.role, notifications: notificationsOf(b), scheduleId });
    return { status: 201, body: { ...sJob(job), execute_now_schedule_id: scheduleId } };
  }
  return { status: 201, body: sJob(job) };
}

function updateJob(req, job) {
  const b = req.body || {};
  if (b.name) job.name = b.name;
  if (b.description !== undefined) job.description = b.description;
  const t = store.parseTargets(b);
  if (t) job.targets = t;
  if (b.remediate !== undefined || b.remediation) job.params.remediate = !!(b.remediate ?? b.remediation);
  if (b.analysis_only !== undefined) job.params.analysis_only = !!b.analysis_only;
  if (Array.isArray(b.schedules)) job.schedules = withScheduleIds(b.schedules);
  job.notifications = notificationsOf(b) || job.notifications;
  if (b.arguments) job.params.arguments = b.arguments;
  job.last_modified = Date.now();
  store.saveSoon();
  return sJob(job);
}

function analysis(run) {
  const r = run.job_type === 'PATCHING_JOB' ? run : null;
  if (!r) throw new HttpError(400, 'Analysis results are only available for patching job runs');
  const servers = [];
  const byPatch = new Map();
  for (const [sid, res] of Object.entries(r.results)) {
    const s = store.server(sid);
    const missing = res.missing_patch_ids || [];
    servers.push({ server_id: Number(sid), server_name: s?.name, status: res.status, missing_patch_count: missing.length, critical_count: res.critical || 0, important_count: res.important || 0 });
    for (const pid of missing) {
      if (!byPatch.has(pid)) byPatch.set(pid, []);
      byPatch.get(pid).push({ id: Number(sid), name: s?.name });
    }
  }
  const patches = [...byPatch.entries()].map(([pid, srv]) => sPatch(store.patch(pid), { missing_on_server_count: srv.length, missing_on_servers: srv }));
  return { servers, patches };
}

// One row of list, which HAC reads from GET .../results/analysis/servers. The shape follows the beans
// TSSAResultResponse and TSSAJobRunResult in the connector's bsa-connector-common jar. HAC counts these
// rows for scanned_targets, and marks the run FAILED when there are none.
function sAnalysisServer(r, x) {
  const failed = x.status === 'FAILED';
  return {
    ...x, id: x.server_id, name: x.server_name, status: failed ? 'FAILED' : 'SUCCESS', server: { id: x.server_id, name: x.server_name },
    job_run_id: r.id, has_errors: failed, has_warnings: false, progress_status: failed ? 'failed' : 'complete', is_attempted: true, is_reboot: false,
    missing_patches: x.missing_patch_count, scanned_patches: x.missing_patch_count, installed_patches: 0,
  };
}

// HAC's compliance asset table: bean ComplianceJobRunSummaryByTarget, with sAnalysisServer's run flags.
function sComplianceServer(r, x) {
  const failed = x.status === 'FAILED';
  return {
    ...x, id: x.server_id, name: x.server_name, status: failed ? 'FAILED' : 'SUCCESS', server: { id: x.server_id, name: x.server_name },
    job_run_id: r.id, has_errors: failed, has_warnings: false, progress_status: failed ? 'failed' : 'complete', is_attempted: true,
    compliant_rules: x.compliant ?? 0, non_compliant_rules: x.non_compliant ?? 0, indeterminate_rules: x.not_applicable ?? 0, compliant_with_exception_rules: 0,
  };
}

// HAC's Sync accepts compliant, noncompliant and indeterminate in any case, and rejects non_compliant even
// though its error message lists NON_COMPLIANT. The asset page matches the lowercase words exactly.
function sRuleResult(y) {
  const id = 3000000 + Object.values(engine.RULES).flat().indexOf(y.rule_name);
  return { ...y, id, name: y.rule_name, rule_id: id, status: y.status.replace('_', '').toLowerCase() };
}

const ANALYSIS_PAGE_MAX = 250;
const SEVERITY_RANK = { Critical: 0, High: 1, Important: 1, Medium: 2, Moderate: 2, Low: 3 };

// Orders rows so that any first N give each server a turn, most severe patches first.
function fairRows(rows) {
  const turns = new Map();
  return [...rows]
    .sort((x, y) => (SEVERITY_RANK[x.severity] ?? 4) - (SEVERITY_RANK[y.severity] ?? 4))
    .map((row) => { const turn = turns.get(row.server_id) || 0; turns.set(row.server_id, turn + 1); return { row, turn }; })
    .sort((x, y) => x.turn - y.turn)
    .map((x) => x.row);
}

// HAC's severity scale is Info, Low, Medium, High, Critical. A patch_list row with any other word, such
// as Microsoft's "Important", stops HAC building its patch report, and the dashboard stays empty.
const HAC_SEVERITY = { Important: 'High', Moderate: 'Medium', None: 'Info', Unspecified: 'Info' };
const hacSeverity = (s) => HAC_SEVERITY[s] || s;

// One row of patch_list, the list HAC reads from GET .../results/analysis. patch_status is an uppercase
// enum: HAC drops a row with any other value.
function sPatchListItem(r) {
  const severity = hacSeverity(r.severity);
  const server = { id: r.server_id, name: r.server_name };
  const patch = { id: r.patch_id, name: r.patch_name, title: r.title, severity };
  return { ...r, id: r.patch_id, name: r.patch_name, patch_status: r.status, severity, severity_string: severity, server, patch };
}

// The summary a real server returns from GET .../jobruns/{id}/results (BMC "Examples of REST APIs").
function patchRunSummary(r) {
  const { servers, patches } = analysis(r);
  const scanned = servers.filter((s) => s.status !== 'FAILED').length;
  return {
    id: r.id,
    analysis: {
      id: r.id,
      patches: { type: { id: 114, name: 'Hotfix Windows Installable' }, missing: patches.length, installed: 0 },
      containers: { type: { id: 308, name: 'Windows Bulletin Installable' }, missing: 0, installed: 0 },
      scanned_machines: scanned, not_scanned_machines: servers.length - scanned,
    },
    remediation: r.child_run_ids.map((id) => store.run(id)).filter((c) => c?.job_type === 'DEPLOY_JOB').map(sRemediationRun),
  };
}

// One row of list in GET .../results/remediation: the beans TSSAResultResponse and TSSAJobRunResult.
function sRemediationServer(c, x) {
  const failed = x.status === 'FAILED';
  return {
    id: x.server_id, name: x.server_name, status: failed ? 'FAILED' : 'SUCCESS', server: { id: x.server_id, name: x.server_name },
    job_run_id: c.id, result_id: x.server_id, attempt_id: 1, error_code: String(x.exit_code ?? 0), start_time: tssaTime(c.start_time), end_time: tssaTime(c.end_time),
    has_errors: failed, has_warnings: false, progress_status: failed ? 'failed' : 'complete', is_attempted: true, is_reboot: false,   // HAC reads true as "pending reboot"; the mock's run has already rebooted
    object_type: JOB_TYPE_DETAIL.DEPLOY_JOB, installed_patches: x.installed_patch_count || 0, missing_patches: 0,
  };
}

function sRemediationRun(c) {
  const n = sRun(c).target_counts;
  return {
    id: c.id, download: {},
    deploy: {
      all: n.total, failed: n.failed, not_started: 0, paused: 0, pending_reboot: 0, pending_targets: 0,
      running_targets: n.in_progress, successful_targets: n.succeeded, success_with_warnings: n.warnings,
    },
  };
}

// --- routing ---------------------------------------------------------------
const routes = [];
const route = (method, pattern, handler, opts = {}) => {
  const keys = [];
  const re = new RegExp(`^${pattern.replace(/\/$/, '').replace(/\{(\w+)\}/g, (_, k) => { keys.push(k); return '([^/]+)'; })}/?$`);
  routes.push({ method, re, keys, handler, auth: opts.auth !== false, pattern });
};

// Sessions / about / configs
route('POST', '/api/v{v}/sessions', (req) => {
  const b = req.body || {};
  const user = b.user_name || b.username || b.userName || b.user;
  const { session, error } = store.login(user, b.password, b.role_name || b.role || b.roleName, b.authentication_type || b.authenticationType);
  if (error || !user) throw new HttpError(401, error || 'user_name is required');
  // Field set and order of a real TSSA 26.3 login response.
  return { status: 200, headers: { 'session-id': session.id }, body: {
    session_id: session.id, roles: session.roles, expiration_time: tssaDate(session.expires), default_role: session.role, user_name: session.user, links: [],
  } };
}, { auth: false });
route('POST', '/api/v{v}/sessions/pki', (req) => {
  const { session } = store.login('BLAdmin', null, (req.body || {}).role_name);
  return { status: 200, headers: { 'session-id': session.id }, body: { session_id: session.id, roles: session.roles, expiration_time: iso(session.expires) } };
}, { auth: false });
route('GET', '/api/v{v}/sessions', (req) => ({
  session_id: req.session.id, roles: req.session.roles, expiration_time: tssaDate(req.session.expires), default_role: req.session.role,
  service_ticket: Buffer.from(`mock-service-ticket:${req.session.id}`).toString('base64'), user_name: req.session.user, links: [],
}));
route('DELETE', '/api/v{v}/sessions', (req) => { store.sessions.delete(req.session.id); return { status: 200, body: { message: 'Session terminated' } }; });
route('GET', '/api/about', () => about(), { auth: false });
route('GET', '/api/v{v}/about', () => about(), { auth: false });
route('GET', '/api/v{v}/version', () => about(), { auth: false });
route('GET', '/api/v{v}/configs/timezones', () => ({ timezones: ['UTC', 'America/Chicago', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 'Asia/Kolkata'] }));
route('GET', '/api/v{v}/configs/automation_console', () => ({ enabled: true, auth_type: 'SRP', application_server: store.settings.app_server_name, version: store.settings.tssa_version, public_key: 'MOCK-PUBLIC-KEY' }), { auth: false });
route('GET', '/api/v{v}/configs/automation_console/encrypt', (req) => ({ encrypted_session_id: Buffer.from(`enc:${req.session.id}`).toString('base64') }));
route('GET', '/api/v{v}/roles', () => ({ total_records: 3, roles: [{ id: 1, name: 'BLAdmins' }, { id: 2, name: 'RBACAdmins' }, { id: 3, name: 'BLOperators' }] }));

// Servers
// HAC's collection calls: ?device_type=server&device_state=Enrolled&page=0&size=1000&additional_detail=true&os_name=Windows
route('GET', '/api/v{v}/servers', (req) => {
  let list = store.state.servers;
  const os = req.query.os || req.query.os_name;
  if (os) list = list.filter((s) => s.os.toLowerCase() === String(os).toLowerCase());
  // HAC lists Linux servers one vendor at a time: &os_name=Linux&os_vendor=Red Hat
  if (req.query.os_vendor) list = list.filter((s) => String(OS_META[s.family]?.vendor).toLowerCase() === String(req.query.os_vendor).toLowerCase());
  if (req.query.device_type && String(req.query.device_type).toLowerCase() !== 'server') list = [];
  if (req.query.device_state) {
    const want = String(req.query.device_state).toLowerCase();
    list = list.filter((s) => (s.decommissioned ? 'decommissioned' : 'enrolled') === want);
  } else if (req.query.include_decommissioned !== 'true' && req.query.decommissioned !== 'true') {
    list = list.filter((s) => !s.decommissioned);
  }
  list = filterByName(req, list);
  if (req.headers['x-mock-ui']) return paginate(req, 'servers', list.map((x) => sServer(x, req)));
  // Real TSSA: { server_list: [...], total_records, links: [] }; properties only with additional_detail=true.
  const withProps = String(req.query.additional_detail) === 'true';
  return { ...paginate(req, 'server_list', list.map((x) => sServerReal(x, { withProps }))), links: [] };
});
route('GET', '/api/v{v}/servers/{id}', (req) => {
  const s = must(store.server(req.params.id), `Server ${req.params.id}`);
  if (req.headers['x-mock-ui']) return sServer(s, req);
  return { server: sServerReal(s, { acl: true }), properties: realServerProperties(s), links: [] };
});
route('GET', '/api/v{v}/servers/{id}/properties', (req) => must(store.server(req.params.id), 'Server').properties);
route('GET', '/api/v{v}/servers/{id}/missing-patches', (req) => {
  const s = must(store.server(req.params.id), 'Server');
  return paginate(req, 'patches', (store.state.missing[s.id] || []).map((id) => store.patch(id)).filter(Boolean).map((p) => sPatch(p)));
});
route('POST', '/api/v{v}/servers', (req) => {
  const b = req.body || {};
  const name = b.name || b.server_name;
  if (!name) throw new HttpError(400, 'name is required');
  if (store.server(name)) throw new HttpError(409, `Server ${name} already exists`);
  const linux = /linux|rhel|ubuntu/i.test(b.os || name);
  const s = {
    id: store.nextId(), name, short_name: name.split('.')[0], family: linux ? 'RHEL9' : 'WINDOWS', ip_address: b.ip_address || '10.99.0.10',
    os: linux ? 'Linux' : 'Windows', platform: linux ? 'LINUX' : 'WINDOWS', os_version: linux ? 'Red Hat Enterprise Linux 9.4 (Plow)' : 'Windows Server 2022 Datacenter 21H2',
    architecture: 'x86_64', agent_version: store.settings.tssa_version, agent_port: 4750, agent_status: 'agent is alive', decommissioned: false,
    date_created: Date.now(), last_reboot: Date.now(), cpu_count: 4, memory_mb: 16384, properties: { ENVIRONMENT: 'Development', ...(b.properties || {}) },
  };
  s.catalog_id = store.state.catalogs.find((c) => c.family === s.family).id;
  store.state.servers.push(s);
  store.state.missing[s.id] = [];
  store.saveSoon();
  return { status: 201, body: sServer(s) };
});
route('DELETE', '/api/v{v}/servers/{id}', (req) => {
  const s = must(store.server(req.params.id), 'Server');
  s.decommissioned = true;
  store.saveSoon();
  return { message: `Server ${s.name} decommissioned` };
});

// Groups & smart groups
route('GET', '/api/v{v}/groups/{type}', (req) => {
  const kind = folderKind(req.params.type);
  if (kind) {
    const list = ensureFolders(kind);
    return paginate(req, 'groups', filterByName(req, list.map((g) => sFolder(g, list, kind))));
  }
  const t = req.params.type.toLowerCase();
  if (t === 'server' || t === 'servers') return paginate(req, 'groups', filterByName(req, store.state.groups).map(sGroup));
  const hit = folderById(req.params.type);
  if (hit) return sFolder(hit.g, hit.list, hit.kind);
  const g = store.group(req.params.type);
  if (g) return sGroup(g);
  throw new HttpError(400, `Unsupported group type '${req.params.type}'`);
});
route('POST', '/api/v{v}/groups/{type}', (req) => {
  const b = req.body || {};
  const kind = folderKind(req.params.type);
  if (kind) return createFolder(kind, b);
  if (!b.name) throw new HttpError(400, 'name is required');
  const parent = store.group(b.parent_group_id) || store.group(b.parent_path || b.parent?.path || b.parent_group?.path);
  const base = parent?.path || b.parent_path || b.group_path || '/Servers';
  const g = { id: store.nextId(), name: b.name, path: base === '/' ? `/${b.name}` : `${base}/${b.name}`, group_type: 'STATIC', object_type: 'SERVER', criteria: null, member_ids: (store.parseTargets(b)?.server_ids) || [] };
  store.state.groups.push(g); store.saveSoon();
  return { status: 201, body: sGroup(g) };
});
route('PUT', '/api/v{v}/groups/{id}', (req) => {
  const g = must(store.group(req.params.id), 'Group');
  const t = store.parseTargets(req.body);
  if (t) g.member_ids = t.server_ids;
  if (req.body?.name) g.name = req.body.name;
  store.saveSoon();
  return sGroup(g);
});
route('GET', '/api/v{v}/smart-groups/{type}', (req) => paginate(req, 'smart_groups', filterByName(req, store.state.groups.filter((g) => g.group_type === 'SMART')).map(sGroup)));
const groupMembers = (req) => {
  const g = must(store.group(req.params.id), 'Server group');
  return paginate(req, 'servers', g.member_ids.map((id) => store.server(id)).filter(Boolean).map((x) => sServer(x, req)));
};
route('GET', '/api/v{v}/smart-groups/{type}/{id}/members', groupMembers);
route('GET', '/api/v{v}/groups/{type}/{id}/members', groupMembers);

// Depot
route('GET', '/api/v{v}/nshscripts', (req) => paginate(req, 'nsh_scripts', filterByName(req, store.state.scripts).map((x) => sScript(x))));
route('GET', '/api/v{v}/nshscripts/{id}', (req) => sScript(must(store.script(req.params.id), 'NSH script'), true));
route('GET', '/api/v{v}/blpackages', (req) => paginate(req, 'blpackages', filterByName(req, store.state.blpackages).map(sPkg)));
route('GET', '/api/v{v}/blpackages/{id}', (req) => sPkg(must(store.blpackage(req.params.id), 'BLPackage')));
route('POST', '/api/v{v}/blpackages', (req) => {
  const b = req.body || {};
  const p = { id: store.nextId(), name: b.name || 'New BLPackage', group_path: b.group_path || '/Depot/Packages', description: b.description || '', platforms: ['WINDOWS', 'LINUX'], items: (b.items || []).map((it, i) => ({ id: i + 1, type: it.type || 'FILE', path: it.path || it.name, action: it.action || 'ADD' })), version: 1, date_created: Date.now(), created_by: req.session.user };
  store.state.blpackages.push(p); store.saveSoon();
  return { status: 201, body: sPkg(p) };
});
// HAC's remediation content picker: POST /depots/search?size=10&page=0&type=NSHSCRIPT. HAC reads
// { depot_object_list: [{ depot_object: { id, name, description, save_in } }], total_records } and shows
// name + save_in (Path). Types come from HAC's list: NSHSCRIPT, BLPACKAGE, PATCH, MSI_WINDOWS_INSTALLABLE,
// INSTALLSHIELD_WINDOWS_INSTALLABLE, SERVICEPACK_WINDOWS_INSTALLABLE, RPM_INSTALLABLE, CUSTOM_SOFTWARE_INSTALLABLE.
const SOFTWARE_DEPOT_TYPE = { MSI: 'MSI_WINDOWS_INSTALLABLE', RPM: 'RPM_INSTALLABLE', WINDOWS_INSTALLER: 'CUSTOM_SOFTWARE_INSTALLABLE' };
function depotObjects(type) {
  const t = String(type || '').toUpperCase();
  const obj = (x, objectType, description) => ({
    id: x.id, name: x.name, description: description ?? x.description ?? '', save_in: x.group_path, object_type: objectType,
    db_key: dbkey('SDepotObjectKeyImpl', x.id), date_created: iso(x.date_created), created_by: x.created_by || 'BLAdmin',
  });
  const scripts = () => store.state.scripts.map((x) => obj(x, 'NSHSCRIPT'));
  const pkgs = () => store.state.blpackages.map((x) => obj(x, 'BLPACKAGE'));
  const software = (want) => store.state.software.filter((x) => !want || SOFTWARE_DEPOT_TYPE[x.type] === want)
    .map((x) => obj(x, SOFTWARE_DEPOT_TYPE[x.type] || 'CUSTOM_SOFTWARE_INSTALLABLE', `${x.file} (${x.platforms.join(', ')})`));
  if (t === 'NSHSCRIPT' || t === 'NSH_SCRIPT') return scripts();
  if (t === 'BLPACKAGE') return pkgs();
  if (Object.values(SOFTWARE_DEPOT_TYPE).includes(t)) return software(t);
  if (t === 'INSTALLSHIELD_WINDOWS_INSTALLABLE' || t === 'SERVICEPACK_WINDOWS_INSTALLABLE') return [];
  if (!t) return [...scripts(), ...pkgs(), ...software()];
  return [];
}
route('POST', '/api/v{v}/depots/search', (req) => {
  const b = req.body || {};
  const name = String(b.depotName || b.depot_name || b.name || req.query.name || '').toLowerCase().replace(/\*/g, '');
  const items = depotObjects(req.query.type || b.type).filter((o) => !name || o.name.toLowerCase().includes(name));
  const page = paginate(req, 'depot_object_list', items.map((o) => ({ depot_object: o })));
  return page;
});
route('GET', '/api/v{v}/software-packages', (req) => paginate(req, 'software_packages', filterByName(req, store.state.software).map((x) => ({ ...x, date_created: iso(x.date_created) }))));
route('GET', '/api/v{v}/depot-files', (req) => paginate(req, 'depot_files', filterByName(req, store.state.depot_files).map((x) => ({ ...x, date_created: iso(x.date_created) }))));
route('GET', '/api/v{v}/templates', (req) => paginate(req, 'templates', filterByName(req, store.state.templates)));
route('GET', '/api/v{v}/templates/{id}', (req) => must(store.template(req.params.id), 'Template'));

// Patch catalogs
route('GET', '/api/v{v}/catalogs', (req) => {
  let list = store.state.catalogs;
  if (req.query.os) list = list.filter((c) => c.os === String(req.query.os).toUpperCase());
  if (req.query.type) list = list.filter((c) => [String(CATALOG_TYPE[c.family].type.id), CATALOG_TYPE[c.family].type.name, CATALOG_TYPE[c.family].os_type].includes(String(req.query.type)));
  return paginate(req, 'catalogs', filterByName(req, list).map((c) => sCatalog(c, req)));
});
route('GET', '/api/v{v}/catalogs/{id}', (req) => sCatalog(must(store.catalog(req.params.id), 'Catalog'), req, true));
route('PATCH', '/api/v{v}/catalogs/{id}', (req) => {
  const c = must(store.catalog(req.params.id), 'Catalog');
  const run = engine.catalogUpdate(c, { user: req.session.user, role: req.session.role });
  return { status: 202, body: { ...sRun(run), catalog_id: c.id, message: `Catalog update started for '${c.name}'` } };
});
// HAC sends {"schedules":[...]} when saving an Add Catalog schedule, and {"schedules":[]} before
// deleting a catalog. Unknown ids (catalogs from a previous TSSA server that HAC still lists) are
// accepted as a no-op so those stale HAC records can be deleted.
route('PUT', '/api/v{v}/catalogs/{id}/schedules', (req) => {
  const schedules = Array.isArray(req.body) ? req.body : req.body?.schedules;
  if (!Array.isArray(schedules)) throw new HttpError(400, 'schedules array is required');
  const c = store.catalog(req.params.id);
  if (!c) return { catalog_id: Number(req.params.id), schedules: [], message: 'Catalog not present on this server; nothing to update' };
  c.schedules = schedules;
  store.saveSoon();
  // HAC marks the catalog "In Progress" on save and waits for TSSA's callback, so run an update now
  // (its notification goes to the schedule's notification_url when it finishes).
  if (store.settings.update_on_schedule_save && schedules.some((s) => s?.notifications?.notification_url?.url)) {
    engine.catalogUpdate(c, { user: req.session.user, role: req.session.role, startAt: Date.now() + 2000 });
  }
  return { catalog_id: c.id, schedules };
});
route('GET', '/api/v{v}/catalogs/{id}/schedules', (req) => ({ schedules: catalogSchedules(must(store.catalog(req.params.id), 'Catalog')) }));
route('GET', '/api/v{v}/catalogs/{id}/containers', (req) => {
  const c = must(store.catalog(req.params.id), 'Catalog');
  if (req.headers['x-mock-ui']) return paginate(req, 'containers', c.containers.map((k) => ({ id: k.id, name: k.name, criteria: k.criteria, patch_count: k.patch_ids.length })));
  // Real TSSA returns every container in one response: { patch_containers, total_records, links: [] }.
  const all = catalogContainers(c);
  return { patch_containers: all, total_records: all.length, links: [] };
});
route('GET', '/api/v{v}/catalogs/{id}/patches', (req) => {
  const c = must(store.catalog(req.params.id), 'Catalog');
  let list = c.patch_ids.map((id) => store.patch(id)).filter(Boolean);
  if (req.query.severity) list = list.filter((p) => p.severity.toLowerCase() === String(req.query.severity).toLowerCase());
  // v2 is what HAC calls; a real server returns { patches: [{ hotfix: {...} }], total_records } with no links.
  if (req.params.v === '2' && !req.headers['x-mock-ui']) {
    const { patches, total_records } = paginate(req, 'patches', filterByName(req, list));
    const groups = bulletinGroups(c);
    return { patches: patches.map((p) => sPatchV2(c, p, groups)), total_records };
  }
  return paginate(req, 'patches', filterByName(req, list).map((p) => sPatch(p, { missing_on_server_count: Object.values(store.state.missing).filter((m) => m.includes(p.id)).length })));
});
route('GET', '/api/v{v}/catalogs/{id}/jobruns', (req) => {
  const c = must(store.catalog(req.params.id), 'Catalog');
  return paginate(req, 'job_runs', store.state.runs.filter((r) => r.job_type === 'CATALOG_UPDATE_JOB' && store.job(r.job_id)?.params.catalog_id === c.id).reverse().map(sRun));
});
route('GET', '/api/v{v}/catalogs/{id}/jobruns/{rid}', (req) => sRun(runOf(null, req.params.rid)));
route('GET', '/api/v{v}/catalogs/{id}/jobruns/{rid}/events', (req) => paginate(req, 'events', engine.visibleEvents(runOf(null, req.params.rid)).map(sEvent)));

// Generic job-run access (handy for clients that only know a run id)
route('GET', '/api/v{v}/jobruns', (req) => {
  let list = store.state.runs.slice().reverse();
  list.forEach((r) => engine.materialize(r));
  if (req.query.status) list = list.filter((r) => engine.status(r) === String(req.query.status).toUpperCase());
  return paginate(req, 'job_runs', list.map(sRun));
});
route('GET', '/api/v{v}/jobruns/{rid}', (req) => sRun(runOf(null, req.params.rid)));
route('GET', '/api/v{v}/jobruns/{rid}/events', (req) => paginate(req, 'events', engine.visibleEvents(runOf(null, req.params.rid)).map(sEvent)));
route('GET', '/api/v{v}/jobruns/{rid}/results', (req) => paginate(req, 'results', sResults(runOf(null, req.params.rid))));
route('GET', '/api/v{v}/jobruns/{rid}/log', (req) => {
  const r = runOf(null, req.params.rid);
  return { status: 200, text: engine.visibleEvents(r).map((e) => `${iso(e.time)}\t${e.severity.padEnd(7)}\t${e.server || '-'}\t${e.message}`).join('\n') };
});

// Execution tasks (minimal)
route('GET', '/api/v{v}/execution-tasks', (req) => paginate(req, 'execution_tasks', (store.state.tasks || [])));
// HAC's ad hoc operations are execution tasks: { name, job: { id, path }, group, targets }. It reads the
// task's id from execution_task_id (bean ExecutionTask), and Execute Now is a PUT with a once schedule.
function sTask(t) {
  const job = store.job(t.job_id);
  return { ...(job ? sJob(job) : {}), id: jobResponseId(t.id), execution_task_id: t.id, name: t.name, job: job ? { id: job.id, path: job.group_path } : null, schedules: t.schedules || [], created_by: t.created_by };
}

route('POST', '/api/v{v}/execution-tasks', (req) => {
  store.state.tasks = store.state.tasks || [];
  const job = store.job(req.body?.job?.id ?? req.body?.job_id);
  const t = { id: store.nextId(), name: req.body?.name || 'Execution Task', job_id: job?.id || null, targets: store.parseTargets(req.body), created_by: req.session.user };
  store.state.tasks.push(t); store.saveSoon();
  return { status: 201, body: sTask(t) };
});
route('GET', '/api/v{v}/execution-tasks/{id}', (req) => sTask(must((store.state.tasks || []).find((t) => t.id === Number(req.params.id)), 'Execution task')));
route('PUT', '/api/v{v}/execution-tasks/{id}', (req) => {
  const t = must((store.state.tasks || []).find((x) => x.id === Number(req.params.id)), 'Execution task');
  if (Array.isArray(req.body?.schedules)) t.schedules = withScheduleIds(req.body.schedules);
  store.saveSoon();
  return sTask(t);
});
route('DELETE', '/api/v{v}/execution-tasks/{id}', (req) => { store.state.tasks = (store.state.tasks || []).filter((t) => t.id !== Number(req.params.id)); return { message: 'Deleted' }; });
route('PATCH', '/api/v{v}/execution-tasks/{id}', (req) => {
  const t = must((store.state.tasks || []).find((x) => x.id === Number(req.params.id)), 'Execution task');
  const job = must(store.job(t.job_id), 'Job');
  req.body = { ...(req.body || {}), ...(t.targets ? { targets: t.targets } : {}) };
  return execute(req, job);
});

// Metrics (minimal)
route('GET', '/api/v{v}/metrics/all', () => ({ application_servers: [{ name: store.settings.app_server_name, type: 'JOB_AND_CONFIG', status: 'RUNNING', heap_used_mb: 2840, heap_max_mb: 8192, running_jobs: store.state.runs.filter((r) => engine.status(r) === 'RUNNING').length, work_item_threads: 100 }] }));
route('GET', '/api/v{v}/metrics/listAllJobsWaiting', () => ({ jobs_waiting: [] }));

// Job endpoints for every job-type slug
for (const [slug, type] of Object.entries(JOB_TYPES)) {
  const base = `/api/v{v}/${slug}`;
  route('GET', base, (req) => {
    let list = store.state.jobs.filter((j) => (!type || j.type === type));
    if (req.query.include_generated !== 'true') list = list.filter((j) => !j.generated || type === 'DEPLOY_JOB');
    if (req.query.group_path) list = list.filter((j) => j.group_path.startsWith(req.query.group_path));
    // HAC's Adhoc Job Selections asks for sub_type=Basic: jobs people made, not ones generated by a remediation.
    if (req.query.sub_type) list = list.filter((j) => !j.generated && !j.params?.compliance_remediation);
    const page = paginate(req, 'jobs', filterByName(req, list).map(sJob));
    return JOB_LIST_KEYS[type] ? { ...page, [JOB_LIST_KEYS[type]]: page.jobs } : page;
  });
  route('POST', base, (req) => createJob(req, type));
  route('GET', `${base}/{id}`, (req) => sJob(jobOf(type, req.params.id)));
  route('PUT', `${base}/{id}`, (req) => updateJob(req, jobOf(type, req.params.id)));
  route('DELETE', `${base}/{id}`, (req) => {
    const j = jobOf(type, req.params.id);
    store.state.jobs = store.state.jobs.filter((x) => x !== j);
    store.saveSoon();
    return { message: `Job '${j.name}' deleted` };
  });
  route('PATCH', `${base}/{id}`, (req) => execute(req, jobOf(type, req.params.id)));
  route('POST', `${base}/{id}/execute`, (req) => execute(req, jobOf(type, req.params.id)));
  route('PUT', `${base}/{id}/schedules`, (req) => {
    const j = jobOf(type, req.params.id);
    const list = Array.isArray(req.body) ? req.body : req.body?.schedules || [];
    j.schedules = list.map((s, i) => ({ id: i + 1, type: s.type || s.schedule_type || 'ONCE', description: s.description || '', next_run: Date.parse(s.start_time || s.date || '') || Date.now() + 86400000 }));
    store.saveSoon();
    return sJob(j);
  });
  route('GET', `${base}/{id}/jobruns`, (req) => {
    const j = jobOf(type, req.params.id);
    const runs = store.state.runs.filter((r) => r.job_id === j.id).reverse();
    runs.forEach((r) => engine.materialize(r));
    return paginate(req, 'job_runs', runs.map((r) => sRunFor(req, r)));
  });
  route('GET', `${base}/{id}/jobruns/latest`, (req) => {
    const j = jobOf(type, req.params.id);
    const runs = store.state.runs.filter((r) => r.job_id === j.id);
    return sRunFor(req, must(runs[runs.length - 1], 'Job run'));
  });
  route('GET', `${base}/{id}/jobruns/{rid}`, (req) => sRunFor(req, runOf(jobOf(type, req.params.id), req.params.rid)));
  route('PATCH', `${base}/{id}/jobruns/{rid}`, (req) => {
    const j = jobOf(type, req.params.id);
    const prev = runOf(j, req.params.rid);
    const mode = String(req.body?.rerun_type || req.body?.rerun_on || req.body?.type || 'FAILED').toUpperCase();
    const ids = mode.includes('FAIL') ? Object.entries(prev.results).filter(([, r]) => r.status === 'FAILED').map(([k]) => Number(k)) : prev.target_ids;
    if (!ids.length) throw new HttpError(400, 'No failed targets to re-run');
    req.body = { targets: { server_ids: ids } };
    return execute(req, j);
  });
  route('PATCH', `${base}/{id}/jobruns/{rid}/abort`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    if (!engine.abortRun(r, 'abort')) throw new HttpError(400, `Job run ${r.id} is not running`);
    return sRun(r);
  });
  route('PATCH', `${base}/{id}/jobruns/{rid}/cancel`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    if (!engine.abortRun(r, 'cancel')) throw new HttpError(400, `Job run ${r.id} is not running`);
    return sRun(r);
  });
  route('GET', `${base}/{id}/jobruns/{rid}/events`, (req) => {
    let ev = engine.visibleEvents(runOf(jobOf(type, req.params.id), req.params.rid));
    if (req.query.type || req.query.severity) ev = ev.filter((e) => e.severity === String(req.query.type || req.query.severity).toUpperCase());
    if (req.query.server_name) ev = ev.filter((e) => e.server === req.query.server_name);
    const page = paginate(req, 'events', ev.map(sEvent));
    return { ...page, job_run_events: page.events };   // HAC reads job_run_events
  });
  route('GET', `${base}/{id}/jobruns/{rid}/log`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    return { status: 200, text: engine.visibleEvents(r).map((e) => `${iso(e.time)}\t${e.severity.padEnd(7)}\t${e.server || '-'}\t${e.message}`).join('\n') };
  });
  route('GET', `${base}/{id}/jobruns/{rid}/results`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    const list = paginate(req, 'results', sResults(r));
    if (r.job_type !== 'PATCHING_JOB') return { ...list, list: list.results.map((x) => sRemediationServer(r, x)) };
    return { ...list, ...patchRunSummary(r) };
  });
  route('GET', `${base}/{id}/jobruns/{rid}/results/servers`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    const page = paginate(req, 'servers', sResults(r));
    return r.job_type === 'COMPLIANCE_JOB' ? { ...page, list: page.servers.map((x) => sComplianceServer(r, x)) } : page;
  });
  // Real TSSA (PatchingJobs#getAnalysisResultForPatchingJobAndJobRun) returns patch-level results that
  // can be filtered by server, patch, patch status and patch type; HAC reads this after a patching run.
  route('GET', `${base}/{id}/jobruns/{rid}/results/analysis`, (req) => {
    const a = analysis(runOf(jobOf(type, req.params.id), req.params.rid));
    const q = req.query;
    const has = (v, s) => !v || String(s ?? '').toLowerCase().includes(String(v).toLowerCase());
    const rows = a.patches.flatMap((p) => p.missing_on_servers.map((s) => ({
      server_id: s.id, server_name: s.name, patch_id: p.id, patch_name: p.name, bulletin_id: p.bulletin_id, title: p.title,
      severity: p.severity, patch_type: p.classification, status: 'MISSING', catalog_id: p.catalog_id, release_date: p.release_date,
      reboot_required: p.reboot_required, cve_ids: p.cve_ids,
    }))).filter((r) => (!q.server_id || r.server_id === Number(q.server_id)) && has(q.server_name, r.server_name) && has(q.patch_name || q.name, r.patch_name)
      && has(q.status || q.patch_status, r.status) && has(q.patch_type || q.type, r.patch_type) && has(q.severity, r.severity));
    if (req.headers['x-mock-ui']) return { ...paginate(req, 'analysis_results', rows), servers: a.servers, patches: a.patches };
    // HAC asks for one page of 5000 and never a second, but more than about 256 rows in the response stops
    // its patch report updating, with no error. So it gets a capped page, shared across the servers.
    const size = Math.min(Number(req.query.size) || ANALYSIS_PAGE_MAX, ANALYSIS_PAGE_MAX);
    const page = paginate({ query: { ...req.query, size }, headers: req.headers, path: req.path }, 'analysis_results', fairRows(rows));
    return { patch_list: page.analysis_results.map(sPatchListItem), total_records: page.total_records, links: page.links };
  });
  route('GET', `${base}/{id}/jobruns/{rid}/results/analysis/servers`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    const page = paginate(req, 'servers', analysis(r).servers);
    return req.headers['x-mock-ui'] ? page : { ...page, list: page.servers.map((x) => sAnalysisServer(r, x)) };
  });
  const remediationOf = (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    const child = r.child_run_ids.map((id) => store.run(id)).find((c) => c && c.job_type === 'DEPLOY_JOB');
    const results = child ? sResults(child) : [];
    return { child, results, list: results.map((x) => sRemediationServer(child, x)) };
  };
  route('GET', `${base}/{id}/jobruns/{rid}/results/remediation`, (req) => {
    const { child, results, list } = remediationOf(req);
    const body = { remediation_job_run: child ? sRun(child) : null, results };
    return req.headers['x-mock-ui'] ? body : { ...body, list, total_records: list.length };
  });
  route('GET', `${base}/{id}/jobruns/{rid}/results/remediation/servers`, (req) => {
    const { list } = remediationOf(req);
    return { list, total_records: list.length };
  });
  // Real TSSA (ComplianceJobs#getCompliancesJobRuleResultList) returns rule-level results, filterable
  // by server and rule. A rule is non-compliant on a server when the run's log reported it so.
  route('GET', `${base}/{id}/jobruns/{rid}/results/rules`, (req) => {
    const r = runOf(jobOf(type, req.params.id), req.params.rid);
    const q = req.query;
    const job = store.job(r.job_id);
    const tpl = store.template(job?.params?.template_id) || store.state.templates[0];
    const done = !['RUNNING', 'NOT_STARTED'].includes(engine.status(r));
    const rows = [];
    for (const x of done ? sResults(r) : []) {
      if (x.compliant === undefined) continue;
      const s = store.server(x.server_id);
      const nonc = new Set(r.events.filter((e) => e.server === x.server_name && /Non-compliant: /.test(e.message)).map((e) => e.message.split('Non-compliant: ')[1]));
      for (const rule of engine.RULES[s?.platform] || engine.RULES.LINUX) {
        rows.push({ server_id: x.server_id, server_name: x.server_name, template_id: tpl?.id, template_name: tpl?.name, rule_name: rule,
          status: nonc.has(rule) ? 'NON_COMPLIANT' : 'COMPLIANT', compliant: !nonc.has(rule) });
      }
    }
    const has = (v, s) => !v || String(s ?? '').toLowerCase().includes(String(v).toLowerCase());
    const list = rows.filter((x) => (!q.server_id || x.server_id === Number(q.server_id)) && has(q.server_name, x.server_name) && has(q.rule_name || q.name, x.rule_name) && has(q.status, x.status));
    const body = { ...paginate(req, 'rules', list), summary: sResults(r).map((x) => ({ server_id: x.server_id, server_name: x.server_name, compliant: x.compliant, non_compliant: x.non_compliant, not_applicable: x.not_applicable })) };
    if (req.headers['x-mock-ui']) return body;
    // HAC reads a flat list of rule rows, groups them by server_id and pages until a page is empty. A
    // server with no rows fails its Sync, so a server that couldn't be scanned reports indeterminate rules.
    const unknown = done ? sResults(r).filter((x) => x.compliant === undefined).flatMap((x) => (engine.RULES[store.server(x.server_id)?.platform] || engine.RULES.LINUX)
      .map((rule) => ({ server_id: x.server_id, server_name: x.server_name, template_id: tpl?.id, template_name: tpl?.name, rule_name: rule, status: 'INDETERMINATE', compliant: false }))) : [];
    return { ...body, ...paginate(req, 'list', [...rows, ...unknown].map(sRuleResult)) };
  });
}

// HAC creates a compliance remediation job here and passes a callback_url. Building the job takes a real
// TSSA a while, so the reply is only a key for GET remediate-async/{key}.
const remediationKeys = new Map();
const REMEDIATION_CALLBACK_MS = 5000;

function createComplianceRemediation(req) {
  const b = req.body || {};
  if (!b.name) throw new HttpError(400, 'name is required');
  const source = store.run(b.job_run_id);
  const now = Date.now();
  const job = {
    id: store.nextId(), name: b.name, type: 'DEPLOY_JOB', group_path: jobGroupPath(b) || '/Workspace/Jobs/Created via REST', description: b.description || '',
    created_by: req.session.user, date_created: now, last_modified: now, schedules: withScheduleIds(b.schedules),
    targets: store.parseTargets(b) || { server_ids: [], group_ids: [] }, notifications: notificationsOf(b),
    params: { compliance_remediation: { job_run_id: b.job_run_id, template_id: store.job(source?.job_id)?.params?.template_id }, phases: ['SIMULATE', 'STAGE', 'COMMIT'] },
  };
  store.state.jobs.push(job);
  store.saveSoon();
  return job;
}

route('POST', '/api/v{v}/compliance-jobs/remediate-async', (req) => {
  const job = createComplianceRemediation(req);
  const key = crypto.randomUUID();
  remediationKeys.set(key, job.id);
  // HAC holds the operation in AWAITING_CREATION until this arrives, so give its own call time to finish first.
  if (req.body.callback_url) setTimeout(() => notify.sendJobCallback(job, req.body.callback_url, sJob(job)), REMEDIATION_CALLBACK_MS);
  return { status: 200, body: { cache_key: key, cacheKey: key, status: 'IN_PROGRESS', message: '' } };
});

route('GET', '/api/v{v}/compliance-jobs/remediate-async/{key}', (req) => {
  const job = store.job(remediationKeys.get(req.params.key));
  if (!job) throw new HttpError(404, 'Remediation request not found');
  return { ...sJob(job), cache_key: req.params.key, cacheKey: req.params.key, status: 'COMPLETED', message: '' };
});

route('POST', '/api/v{v}/compliance-jobs/remediate', (req) => {
  const j = store.state.jobs.find((x) => x.type === 'DEPLOY_JOB' && !x.generated);
  return execute(req, j);
});

function about() {
  return { product: 'BMC TrueSight Server Automation (MOCK)', version: store.settings.tssa_version, build: store.settings.tssa_version, application_server: store.settings.app_server_name, rest_api_versions: ['v1', 'v2'], mock: true };
}

function sessionFrom(req) {
  const h = req.headers;
  let id = h['session-id'] || h['sessionid'] || h['x-session-id'] || h['session_id'] || req.query.session_id || req.query.sessionId;
  const auth = h.authorization || '';
  if (!id && /^(bearer|sessionid)\s+/i.test(auth)) id = auth.split(/\s+/)[1];
  let s = store.getSession(id);
  if (!s && /^basic\s+/i.test(auth)) {
    const [u, p] = Buffer.from(auth.split(/\s+/)[1], 'base64').toString().split(':');
    s = store.login(u, p, h.role).session || null;
  }
  if (s && h.role && s.roles.includes(h.role)) s = { ...s, role: h.role };
  return s;
}

// Returns null when no route matches.
// Spring Boot actuator endpoints of the TSSA REST service. HAC calls /rest/actuator/info each
// collection cycle (no auth needed there).
function actuator(req) {
  const p = req.path.replace(/\/+$/, '');
  if (req.method !== 'GET' || !/^(\/rest)?\/actuator\/(info|health)$/.test(p)) return null;
  const v = store.settings.tssa_version;
  const body = p.endsWith('/health')
    ? { status: 'UP' }
    : (() => {
      // Real TSSA 26.3: {"version":{"version":"26.3.00.130","major_version":26,"minor_version":3,"service_pack":0,"build_number":130}}
      const [major, minor, sp, build] = String(v).split('.').map(Number);
      return { version: { version: v, major_version: major || 0, minor_version: minor || 0, service_pack: sp || 0, build_number: build || 0 } };
    })();
  return { status: 200, body, matched: true, route: '/actuator/info' };
}

async function handle(req) {
  const act = actuator(req);
  if (act) return act;
  const m = req.path.match(/^\/rest(\/api\/.*)$/) || req.path.match(/^(\/api\/.*)$/);
  if (!m) return null;
  const sub = m[1].replace(/\/+$/, '') || '/';
  req.basePath = req.path.startsWith('/rest') ? '/rest' : '';
  const candidates = routes.filter((r) => r.re.test(sub.replace(/^\/api\/v(\d+)/, '/api/v{v}')));
  if (!candidates.length) return null;
  const rt = candidates.find((r) => r.method === req.method);
  if (!rt) return { status: 405, body: errBody(405, `Method ${req.method} not allowed`, req.path), matched: true };
  const norm = sub.replace(/^\/api\/v(\d+)/, '/api/v{v}');
  const vals = norm.match(rt.re).slice(1);
  req.params = Object.fromEntries(rt.keys.map((k, i) => [k, decodeURIComponent(vals[i])]));
  req.params.v = sub.match(/^\/api\/v(\d+)/)?.[1];
  if (rt.auth) {
    req.session = sessionFrom(req);
    if (!req.session) return { status: 401, body: errBody(401, 'Session is invalid or has expired. Create a session using POST /api/v1/sessions', req.path), matched: true };
  } else {
    req.session = sessionFrom(req) || { user: 'anonymous', role: 'BLAdmins', roles: [] };
  }
  try {
    const out = await rt.handler(req);
    if (out && out.status && (out.body !== undefined || out.text !== undefined)) return { ...out, matched: true, route: rt.pattern };
    return { status: 200, body: out, matched: true, route: rt.pattern };
  } catch (e) {
    const st = e.status || 500;
    if (st === 500) console.error(e);
    return { status: st, body: errBody(st, e.message, req.path), matched: true, route: rt.pattern };
  }
}

function errBody(status, message, path) {
  return { timestamp: iso(Date.now()), status, error: ERR_NAMES[status] || 'Error', message, path };
}

function listRoutes() {
  return routes.map((r) => `${r.method.padEnd(6)} /rest${r.pattern.replace('{v}', '1')}`);
}

module.exports = { handle, listRoutes, errBody, sRun, sJob, sServer, sCatalog, sPatch, sEvent, sResults };
