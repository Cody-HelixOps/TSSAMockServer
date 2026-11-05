# Mock TSSA – TrueSight Server Automation emulator for Helix Automation Console

> Unofficial test tool. It isn't made, endorsed or supported by BMC. It holds only fake servers and fake
> data. While the tunnel is on, its address is public and it uses default credentials, so keep it to test use.

## Quick start

You need [Node.js 18 or later](https://nodejs.org).

- **Windows:** double-click `start-windows.bat`.
- **macOS:** Control-click `start-macos.command` and choose **Open**, or run `bash start-macos.command` in Terminal.
- **Any system:** run `node start.js`. Add `--no-tunnel` to stay local, or `--no-browser` to skip opening the console.

The first run downloads `cloudflared`, starts the mock and opens `http://localhost:9842`. The window shows the
Host Name to enter in HAC. Press Ctrl+C there to stop. Default sign-in: `BLAdmin`, role `BLAdmins`, password
`password`.

The [project site](https://cody-helixops.github.io/TSSAMockServer/) has a walkthrough and a status table.

## About

A self-contained, zero-dependency Node.js service that pretends to be a TrueSight Server
Automation (TSSA) 26.3 application server. Point the HAC **Server Automation Connector**
(`tssa-connector`) at it and you get servers, Windows/Linux patch catalogs, NSH scripts,
BLPackages, jobs and job runs with realistic, streaming job logs, without a real TSSA install.

| Listener | Default | Serves |
|---|---|---|
| HTTPS | `9843` | TSSA REST API `/rest/api/v1` + `/rest/api/v2`, BLCLI SOAP `/services/*`, web console `/`, endpoint list `/rest/apidocs` |
| HTTP | `9842` | Same content without TLS, for local browsing and testing (`MOCK_HTTP_PORT=0` disables it) |

## What's inside

- **24 servers.** 12 Windows (2016/2019/2022/2025) and 12 Linux (RHEL 8/9, Oracle Linux 8,
  Ubuntu 22.04, SLES 15). Each server has properties (ENVIRONMENT, APPLICATION, LOCATION,
  SUPPLIER, CUSTOMER, OWNER, PATCH_WINDOW) and a missing-patch state. One server
  (`win-app-03`) has a dead agent so you can see failures.
- **Server groups.** Static groups plus smart groups: All Windows, All Linux, Production,
  Web Tier, Apex-Online.
- **6 patch catalogs.**
  - Windows: cumulative updates, .NET, SQL, Edge, Defender, servicing stack. Uses KB numbers,
    bulletin IDs and CVEs.
  - Linux: RHEL 9, RHEL 8, Oracle Linux 8, Ubuntu 22.04 and SUSE 15. Uses RHSA/ELSA/USN/SUSE-SU
    advisories with real-looking package names.
  - Each catalog has containers (All, Critical and Important, Monthly). A catalog update job
    adds new patches and marks some servers as missing them.
- **Depot.**
  - 13 NSH scripts that produce real-looking output (df, Get-PSDrive, health checks, chrony,
    w32tm, and others).
  - 7 BLPackages, software packages (MSI/RPM), depot files, and 4 compliance templates.
- **45 jobs.**
  - Patching jobs: analysis only, and analysis plus remediation.
  - NSH script jobs, BLPackage deploy jobs, file deploy, compliance, snapshot, and a batch job
    (health check → patch → validate).
  - About two weeks of run history is generated on first start.
- **Job engine.** Each run plans a timeline per target:
  - Connect to the agent, then analysis.
  - A generated remediation deploy job runs as a child run: Simulate → Stage → Commit,
    installs each patch with exit codes 0 or 3010, then reboots.
  - Logs appear progressively while the run executes.
  - Runs can be aborted, cancelled, or re-run on failed targets.
  - Results persist: a successful remediation removes the patches from the server's missing list.
- **Failure simulation.** You set the per-target failure rate. Failures include WUA errors
  `0x80244022`, MSI `1603`, curl timeouts and RPM conflicts, and each failure triggers a rollback.
- **API Inspector.** Every request the connector sends is recorded with headers, body and
  response. Requests the mock does not implement are flagged **NOT IMPLEMENTED**, so you can see
  exactly what the connector expects.

State is saved to `data/state.json`, so it survives restarts. Use **Settings → Reset all data**
or `npm run reset` to reseed it.

## Run it

Requires Node.js 18 or later. There are no npm dependencies.

```bash
cd mock-tssa
node server.js
```

Then open `http://localhost:9842/`, or `https://<host>:9843/` and accept the self-signed
certificate.

On Windows, `start-mock.ps1` does all of this in one step. It starts the mock (hidden, logging to
`data/mock-console.log`) if it isn't already running, waits for the Cloudflare tunnel, checks that
the public URL reaches the mock, opens the console, and prints the URL (the host name is also
copied to the clipboard):

```powershell
powershell -ExecutionPolicy Bypass -File .\start-mock.ps1
# The tunnel URL stopped working (for example a VPN dropped it): start a new tunnel and write
# its host into the connector's config\application.properties. Then restart the connector and
# click Update on the connector in HAC so it picks up the new host.
powershell -ExecutionPolicy Bypass -File .\start-mock.ps1 -NewTunnel -ConnectorDir C:\path\to\connector
```

On first start the mock generates `certs/mock-tssa.crt` and `certs/mock-tssa.key` with OpenSSL.
The certificate's SAN covers `localhost`, the machine hostname, every local IPv4 address and
anything listed in `MOCK_HOSTNAMES`. On Windows, Git for Windows' bundled `openssl.exe` is found
automatically.

| Env var | Default | Meaning |
|---|---|---|
| `MOCK_HTTPS_PORT` | `9843` | TSSA application port |
| `MOCK_HTTP_PORT` | `9842` | Plain-HTTP console port (`0` disables it) |
| `MOCK_BIND` | `0.0.0.0` | Bind address |
| `MOCK_HOSTNAMES` | – | Extra comma-separated DNS names for the cert SAN (the first one is also the CN) |
| `MOCK_CERT` / `MOCK_KEY` | `certs/mock-tssa.*` | Use your own PEM cert and key |
| `MOCK_TUNNEL` | `cloudflare` | Starts a Cloudflare Tunnel on boot; `off` disables it |
| `MOCK_TUNNEL_TOKEN` | – | Run a *named* Cloudflare tunnel (fixed hostname) instead of a quick tunnel |
| `MOCK_TUNNEL_HOSTNAME` | – | The public hostname routed to that named tunnel (shown on the dashboard) |
| `MOCK_CLOUDFLARED` | `bin/cloudflared.exe` | Path to the `cloudflared` binary (PATH is also searched) |

### Users, sessions and authentication

The mock has three built-in users. Users you add in **Settings** are merged with these defaults, not used instead of them.

| User | Roles | Password |
|---|---|---|
| `BLAdmin` | `BLAdmins`, `RBACAdmins` | `password` |
| `HACService` | `BLAdmins` | `password` |
| `Liam` | `BLAdmins` | `password` |

- `POST /rest/api/v1/sessions` with `"authentication_type": "RSSO"` succeeds for any configured user without checking the password, because RSSO carries an SSO token the mock does not validate. With strict auth on, unknown RSSO users are rejected.
- With strict auth off, a session id the mock never issued (16+ characters of letters, digits, `_` or `-`) is accepted as `BLAdmin`/`BLAdmins` instead of returning `401`. The HAC connector caches session ids and validates them with `GET /rest/api/v1/sessions`.
- Sessions are saved to `data/sessions.json` and survive mock restarts.

### Cloudflare Tunnel (on by default)

On start the mock launches `cloudflared` (from `bin/` or PATH) as a detached process. It publishes the
HTTPS port at a public `https://<random>.trycloudflare.com` URL, which is logged to the console and
shown on the dashboard. The tunnel's pid and URL are saved in `data/tunnel.json`.

- **Restarting the mock keeps the tunnel and its URL.** The mock re-adopts its own `cloudflared`. It
  checks the process's command line first, so it never touches other `cloudflared` tunnels on the
  machine.
- **If `cloudflared` dies, the mock starts a new one,** and a quick tunnel gets a new URL.
- **To stop the tunnel:** `node server.js --stop-tunnel`. Killing the whole process tree, as some
  process managers do, also stops it.

- **HAC values:** Host Name = the `*.trycloudflare.com` host, Application Port = `443`. Cloudflare
  presents a publicly trusted certificate, so no truststore import is needed.
- **Quick-tunnel hostnames change every time the mock (or the tunnel) restarts.** Update the HAC
  connector's Host Name after each restart. For a stable hostname, create a named tunnel in the
  Cloudflare Zero Trust dashboard with its public hostname pointing at `https://localhost:9843`
  (enable *No TLS Verify*). Then start the mock with `MOCK_TUNNEL_TOKEN=<token>` and
  `MOCK_TUNNEL_HOSTNAME=<hostname>`.
- **The mock is reachable from the internet while the tunnel runs.** Turn on *Strict
  authentication* in Settings and use the same password in HAC to stop anonymous logins.

Run the smoke test against a running instance:

```bash
node test/smoke.js https://localhost:9843
```

## Connecting Helix Automation Console

The on-prem `tssa-connector` (Java) makes outbound HTTPS calls to the TSSA application server, so
the mock only needs to be reachable **from the connector host** on port 9843.

1. **Choose where to run the mock.** The simplest option is the connector host itself (in your
   tenant that is `EC2AMAZ-NCG7RNE`). Any VM the connector can reach also works.
2. **Open the port** if you run it on a different host (elevated PowerShell):
   ```powershell
   New-NetFirewallRule -DisplayName "Mock TSSA 9843" -Direction Inbound -Protocol TCP -LocalPort 9843 -Action Allow
   ```
3. **Generate the cert for the name HAC will use.** Delete `certs/`, then start the mock with
   `MOCK_HOSTNAMES=<that name>`:
   ```powershell
   $env:MOCK_HOSTNAMES="mock-tssa.lab.local"; node server.js
   ```
4. **Trust the cert if the connector rejects it.** BMC ships TSSA with self-signed certs, so the
   connector normally accepts them. If the connector log shows `PKIX path building failed`, import
   the mock cert into the JRE the connector uses (the path is in `checkEnv.bat`/`checkEnv.sh`),
   then restart the connector service:
   ```powershell
   keytool -importcert -noprompt -alias mock-tssa -file certs\mock-tssa.crt -keystore "<JAVA_HOME>\lib\security\cacerts" -storepass changeit
   ```
5. **Fill in the connector in HAC.** Go to **Configuration → Connectors → Server Automation
   Connector → Edit**:

   | HAC field | Value |
   |---|---|
   | Truesight Server Automation Host Name | mock host name or IP (must match the cert SAN) |
   | Truesight Server Automation Application Port | `9843` |
   | Truesight Server Automation Role Name | `BLAdmins` |
   | Truesight Server Automation Version | `26.3.00.130` (configurable in Settings) |
   | User Name / Password | `BLAdmin` / anything (or the password set in Settings when *Strict authentication* is on) |
   | Role | `BLAdmins` |
   | Authentication Method | Secure Remote Password |
   | TSSA Properties | e.g. `ENVIRONMENT,APPLICATION,LOCATION,SUPPLIER` |
   | Collection Mode | `5` minutes or more |

6. **Watch it connect.** Open the console's **API Inspector**. Every call the connector makes
   shows up there.

> ⚠️ **Re-pointing an existing connector.** BMC documents that switching the TSSA connector to an
> application server that is not part of the same load balancer or DR set **duplicates asset data**
> in HAC. The mock's 24 `*.mock.lab` servers, patches and jobs will be added alongside whatever the
> real TSSA (`WIN-APP`) already sent. Use a sandbox or demo tenant, or accept the extra mock
> assets. Note the current connector settings before you change them so you can switch back.

### Job callbacks (catalog sync)

HAC doesn't poll for catalog syncs. When you save a catalog schedule, HAC sends TSSA a callback URL
in `notifications.notification_url` (for example
`https://tssa.connector.bmc.com/forward?url=/api/v2/catalogs/notify?...`) and shows the catalog as
"In Progress" until TSSA posts to it. A real TSSA server resolves `tssa.connector.*` through a
hosts-file entry that points at the connector machine. The connector's `/forward` endpoint then
relays the post to HAC.

The mock does the same:

- When HAC saves a schedule that has a callback URL, the mock runs a catalog update straight away
  (setting `update_on_schedule_save`).
- When a catalog update or a job run starts and finishes, the mock POSTs
  `{jobId, jobRunId, jobName, jobType, progressStatus: RUNNING|COMPLETE|FAILED, status, catalogId,
  startTime, endTime}` to the callback URL. Jobs pick up a callback URL from
  `notifications.notification_url` in their create or execute body.
- It sends `tssa.connector.*` URLs to the `connector_url` setting (default
  `https://localhost:8443`) instead, so no hosts-file entry is needed.
- It retries as the URL's `retry_count` and `retry_pause` ask.
- While the real connector (the Java process from the zip) listens on its `server.port`, the mock's
  built-in Helix worker stands by, because two workers with one worker id race for requests. Callbacks
  then go to the real connector's `/forward` (`https://127.0.0.1:<port>`). When it stops, the built-in
  worker takes over within 30 seconds.

The console's **Callbacks** page shows each post with its payload and HAC's response, and lets you
resend it. `POST /mock/catalogs/{id}/update` starts a catalog update by hand.

### Response formats copied from a real TSSA 26.3 server

`tools/capture-real-tssa.ps1` saves the GET responses HAC reads from a real server. The mock now
returns those shapes to TSSA clients (requests without the console's `x-mock-ui` header):

- `GET /servers`: `{server_list, total_records, links: []}`, with nested `os`, `agent_state`,
  `device_state` and `agent_version` objects. `additional_detail=true` adds a `properties` map.
- `GET /servers/{id}`: `{server: {..., acl}, properties, links: []}`.
- `GET /catalogs/{id}`: `id, name, is_usable, schedules, acl, filters`, plus a `status` object for
  the latest catalog update (setting `catalog_status`, on by default). The capture had no `status`,
  but HAC's Add Catalog refuses a catalog unless its latest update passed.
- `GET /catalogs/{id}/containers`: `{patch_containers: [{bulletin: {...}}], total_records, links: []}`.
- `GET /api/v2/catalogs/{id}/patches`: `{patches: [{hotfix: {...}}], total_records}`.
- `POST` and `GET /sessions`, `GET /actuator/info`: the real field sets.

Only Windows catalogs were captured. Linux containers (`{errata}`) and patches (`{rpm}` /
`{debian_package}`) follow the same pattern but are guesses.

### Patch policies in HAC

Run a policy with **Execute Now**, wait for the run to finish, then click **Sync**. HAC then shows the
scan run, each asset's status, its logs and its missing patches, and fills the dashboard's Patch tab.

To install patches, create a remediation operation (dashboard **Remediate**, or **Create Operation**), then
use **Execute Now** on it. HAC schedules the job about 90 seconds ahead. When the run has finished, click
**Sync** on the operation to bring in the results.

To skip clicking **Sync**, open **HAC Auto-Sync** in the mock console and follow the steps there. You paste
a script into the console of your signed-in HAC tab, and it calls Sync every 30 seconds on patch policies and
patching operations with a TSSA job (a job name starting `TS_`) and on compliance scan policies. Keep that tab open. Reloading HAC stops
the script, and it stops by itself after 8 hours. A Sync with nothing new costs one `GET jobruns` per policy
on the mock, so expect about 8 extra lines a minute in the API Inspector. Each Sync also updates the
operation's `modified_at` in HAC.

The script is [public/hac-auto-sync.js](public/hac-auto-sync.js). HAC's content security policy blocks both
loading it from the mock and calling the mock from the page, so it has to be pasted, and it can't wait for a
"run finished" signal.

Compliance works the same way. Create a policy under **Manage > Compliance Scan Policies**, use **Execute
Now**, then **Sync**. HAC then shows the scan run, each asset's rule counts, the rules for an asset, the logs
and the dashboard's Compliance tab. If a Sync fails on a run, HAC keeps that half-read run and won't read it
again, so the next attempt needs a new run.

To remediate compliance, select the policy on the dashboard's Compliance tab, click **Remediate** and finish
the wizard. HAC creates the job through `remediate-async` and waits for the mock's `notifyop` callback, which
takes a few seconds. Then use **Execute Now** and **Sync**. The servers that were fixed scan as fully compliant
from then on. To demo it again, click **Undo compliance remediation** under Settings in the mock console.

Ad hoc jobs are under **Create Operation > Adhoc Job Selections**: NSH Script (15 jobs), Deploy (7) and Batch (5).
Pick a job and a "Save Job in" folder. HAC makes an execution task from it and schedules Execute Now about 90
seconds ahead. Jobs added to the seed reach an existing data file at start-up, without a reset.

What HAC reads, and where each shape comes from:

| Call | HAC needs | Source |
|---|---|---|
| `PATCH /patching-jobs/{id}` | `schedule_id`. Without it HAC returns 400 with `message` as the error | BMC "Examples of REST APIs", then tested |
| `GET .../jobruns` | `job_run`, `job`, `schedule_id`, `role_executed`, `user_executed`, `YYYY-MM-DD HH:mm:ss.SSS` times, lowercase `progress_status` | BMC "Examples of REST APIs" |
| `GET .../jobruns/{id}/results` | `analysis.patches.missing`, `analysis.scanned_machines` | BMC "Examples of REST APIs" |
| `GET .../results/analysis` | `patch_list`. Each row needs an uppercase `patch_status` and a severity of Info, Low, Medium, High or Critical | Tested against HAC |
| `GET .../results/analysis/servers/` | `list`. `has_errors` and `progress_status` decide each asset's result. With no rows HAC marks the run FAILED | Tested against HAC, bean `TSSAResultResponse` |
| `GET .../jobruns/{id}/events` | `job_run_events` | Tested against HAC |
| `POST /groups/{job or depot}` | `{ "group": { id, name, path } }`. A flat group fails with "Error while creating Group", whatever the status | Tested against HAC |
| `GET .../results/remediation` and `.../results/remediation/servers/` | `list` of per-server results (bean `TSSAJobRunResult`) | Tested against HAC |
| `PUT /patching-jobs/{id}` | The job's `schedules`, each with an `id`. Execute Now on an operation sends `{ once: { datetime }, timezone }`, and the server runs it then | BMC "Examples of REST APIs", then tested |
| `POST /compliance-jobs/remediate-async` | Any 200, then a `POST` of the job object to `callback_url` (`/api/v2/policies/notifyop`). Any other body sets the operation to `CREATION_FAILED`. HAC then runs it through `deploy-jobs` and reads its runs through `compliance-jobs` | Bean `ComplianceRemediationJob`, then tested |
| `GET .../results?size=0` on a deploy, NSH or batch run | `list` and `total_records`, with `size=0` meaning all rows | Bean `TSSAResultResponse`, then tested |
| `GET /nshscript-jobs`, `/deploy-jobs`, `/batch-jobs` | The wizard reads `nshscript_job_list`, `deploy_job_list` or `batch_job_list`, not `jobs` | HAC's page code |
| `GET /{type}-jobs/{id}` | `targets.server_groups`, `script_parameters_details`, deploy `software_list[0]` and `basic`, batch `members` | HAC's page code, bean `BatchJob` |
| `POST` and `PUT /execution-tasks` | Reply with `execution_task_id`. `POST` carries `job: { id }`, and `PUT` carries the Execute Now schedule | Bean `ExecutionTask`, then tested |
| `POST /compliance-jobs` | Reads `templates: [{ id }]`. Without a match the mock answers 404 "Template not found", which HAC shows as the error | Tested against HAC |
| `GET .../results/servers/` on a compliance run | `list`, one row per server with `id`, `name`, `compliant_rules`, `non_compliant_rules` and `indeterminate_rules`. With no rows HAC marks the run FAILED | Bean `ComplianceJobRunSummaryByTarget`, then tested |
| `GET .../results/rules` | `list`, a flat list of rule rows with `server_id`, `server_name`, `rule_id`, `rule_name` and `status`. HAC groups them by server, and a server with no rows fails the Sync. `status` must be `compliant`, `noncompliant` or `indeterminate`. HAC's error message lists `NON_COMPLIANT`, but it rejects that spelling | Tested against HAC |

`results/analysis` and `results/analysis/servers/` have no published sample. HAC reads them in the
background, so a failure in either doesn't show as an error: assets or the dashboard just stay empty.

Known gaps:

- **Results don't arrive by themselves.** `POST /api/v2/policies/notify` returns an empty 500, also through
  the real connector, so **Sync** is needed after each run. Until then an executed operation still shows
  as not scheduled. The mock can't call Sync itself, which is why HAC Auto-Sync runs in your browser: HAC's
  Sync needs a console session with a TSSA site, and only a browser sign-in gets one. With a Helix access key, `verify-context` answers
  "Login to TSSA Connector failed." without calling the mock, and Sync fails on `getActiveSite()`. Through
  the connector's `/forward`, Sync fails with "Connector not found for connectorID :null".
- **HAC gets at most 250 patch rows per run.** With more than about 256 rows in one `results/analysis`
  response, HAC's patch report stops updating with no error, and HAC never asks for a second page. A
  Windows run has about 350 rows, so the mock sends the first 250, shared across the servers with the
  most severe patches first. The dashboard and asset lists show that subset; the mock console shows all.
- **The asset table's Missing Patches and Installed Patches columns show 0.** Opening an asset lists its
  patches. HAC ignored about 60 field names in `results/analysis/servers/` rows, nested `patches` and `analysis`
  objects, and `result_id` on both the server and patch rows, so the source of these counts is still unknown.
- **Daily, weekly and monthly schedules don't run.** The mock only runs `once` schedules, so a compliance
  policy set to "Daily at 22:00" saves and shows that schedule but runs only with **Execute Now**.
- **An asset's rule list is a sample.** An asset reports counts out of the template's full rule total (212
  for CIS Windows), but its rule list shows only the mock's sample rules (7 on Windows), so the two don't add up.
- **Ad hoc Deploy operations don't sync.** They create, execute and run on the mock, but **Sync** fails with
  "Index 0 out of bounds for length 0" just after HAC reads `deploy-jobs/.../results`, so the operation stays
  Awaiting Execution in HAC. NSH and Batch operations sync. Adding `remediation` to the reply and a package
  property to the operation didn't change it. The same reply works for compliance remediation jobs.
- **The synchronous `POST /compliance-jobs/remediate` is a stub.** It only starts a deploy job. HAC uses
  `remediate-async`.
- **Remediation really removes patches.** A successful run clears the servers' missing patches, as on a real
  server, so another run has nothing to deploy and its results show no assets.
- **The dashboard keeps older patches for failed assets.** An asset that fails in the latest run keeps its
  patches from the run before, so dashboard totals can be a little above the latest run's.

### Real patch content and CVEs (for HAC vulnerability automapping)

HAC maps scanner vulnerabilities to patches by CVE, so the catalogs are built from real vendor
advisories with their real CVE ids:

- `data/hac-vulnerabilities.json`: the CVEs HAC holds, from HAC's
  `POST /ui/api/v4/violations/search/vulnerabilities`.
- `node tools/fetch-real-content.js` writes `data/real-content.json`. It contains:
  - the vendor fix for each HAC CVE: MSRC KBs; legacy bulletins MS08-067 and MS13-098; third-party
    Windows apps (Java, Chrome, Edge, Firefox, Adobe Reader) at the fixed versions the scanner
    findings name; Red Hat RHSAs from the per-CVE API; Oracle ELSAs, which reuse the RHSA numbers;
    Ubuntu USNs for jammy;
  - recent advisories from the last 4 months: MSRC, Red Hat, Ubuntu, and SUSE CSAF for SLES 15 SP5.
- Restart the mock with `--reset` (or `POST /mock/reset` after a restart) to rebuild the catalogs.
  Patches that fix a HAC CVE are missing on about 80% of matching servers.
- Catalog updates no longer invent patches while the content is real.

`hac_unmatched` in `real-content.json` lists the HAC CVEs no OS catalog fixes. These include
network and protocol findings, appliances such as ESXi, FortiOS, IOS XE and NetScaler, and the
generic "Other" findings.

### When the connector calls something the mock doesn't implement

BMC does not publish the exact calls the HAC connector makes. The mock implements the documented
TSSA REST API (sessions, servers, groups, smart groups, catalogs, patches, every job type with
jobruns/events/results/abort/cancel/re-run, BLPackages, NSH scripts, templates, execution tasks)
plus the BLCLI SOAP services. If the connector asks for something else:

1. Open **API Inspector** and tick **Only not-implemented** to see the method, path, query,
   headers and body.
2. For REST, add a `route(...)` in `lib/rest.js`. For a BLCLI command, add an entry to
   `COMMANDS` in `lib/soap.js`. Restart the mock.

## REST API quick reference

Authenticate, then send the session ID in a `session-id` header. `Authorization: Bearer <id>` and
HTTP Basic are also accepted.

```bash
curl -k -X POST https://localhost:9843/rest/api/v1/sessions -H "Content-Type: application/json" -d "{\"user_name\":\"BLAdmin\",\"password\":\"password\",\"role_name\":\"BLAdmins\",\"authentication_type\":\"SRP\"}"
curl -k https://localhost:9843/rest/api/v1/patching-jobs -H "session-id: <id>"
curl -k -X PATCH https://localhost:9843/rest/api/v2/patching-jobs/<job_id> -H "session-id: <id>" -H "Content-Type: application/json" -d "{}"
curl -k https://localhost:9843/rest/api/v1/patching-jobs/<job_id>/jobruns/<run_id>/events -H "session-id: <id>"
curl -k https://localhost:9843/rest/api/v1/jobruns/<run_id>/log -H "session-id: <id>"
```

Lists are paginated with `page` and `size` and return `total_records` plus `links`. The full
endpoint list is at `/rest/apidocs` and on the console's **Settings** page.

**BLCLI SOAP:**
- `POST /services/LoginService` → `loginUsingUserCredential`
- `POST /services/AssumeRoleService` → `assumeRole`
- `POST /services/CLITunnelService` → `executeCommandByParamList`

Implemented commands include `Server listAllServers`, `Server listServersInGroup`,
`*Job getDBKeyByGroupAndName`, `Job execute`, `JobRun getLatestJobRunIdByJobKey`,
`JobRun getLogItemsByJobRunId`, `PatchCatalog executeCatalogUpdateJob`, and more.

## Layout

```
server.js        HTTP/HTTPS listeners, TLS cert generation, request inspector, console control API (/mock/*)
lib/seed.js      Seed data: servers, groups, depot, patch catalogs, jobs
lib/store.js     State, persistence (data/), sessions, settings
lib/engine.js    Job run simulator: timelines, log messages, results, side effects
lib/rest.js      TSSA REST API (/rest/api/v1|v2)
lib/soap.js      BLCLI SOAP web services
public/          Web console (vanilla JS)
test/smoke.js    End-to-end smoke test
```
