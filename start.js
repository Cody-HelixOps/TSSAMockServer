#!/usr/bin/env node
'use strict';
// One-step launcher for Windows, macOS and Linux. start-windows.bat and start-macos.command call this.
//   node start.js               start the mock, download cloudflared if needed, open the console
//   node start.js --no-tunnel   local only: no Cloudflare tunnel, nothing downloaded
//   node start.js --no-browser  don't open the console
const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const HTTP_PORT = Number(process.env.MOCK_HTTP_PORT || 9842);
const CONSOLE_URL = `http://localhost:${HTTP_PORT}/`;
const WAIT_SECONDS = 60;
const args = new Set(process.argv.slice(2));

async function mockInfo() {
  try {
    const res = await fetch(`${CONSOLE_URL}mock/info`, { signal: AbortSignal.timeout(2000) });
    return res.ok ? await res.json() : null;
  } catch { return null; }
}

function openBrowser() {
  if (args.has('--no-browser')) return;
  const [cmd, cmdArgs] = process.platform === 'win32' ? ['cmd', ['/c', 'start', '', CONSOLE_URL]]
    : [process.platform === 'darwin' ? 'open' : 'xdg-open', [CONSOLE_URL]];
  spawn(cmd, cmdArgs, { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
}

function showDetails(info) {
  const tunnel = info?.tunnel;
  console.log('\n----------------------------------------------------------------');
  console.log(` Mock TSSA console: ${CONSOLE_URL}`);
  if (tunnel?.host) console.log(` HAC connector:     Host Name = ${tunnel.host}, Application Port = 443`);
  else console.log(` HAC connector:     no tunnel, so use this computer's name and port ${info?.https_port ?? 9843}`);
  console.log(' To stop:           press Ctrl+C here, or close this window');
  console.log('----------------------------------------------------------------\n');
}

function cloudflaredOnPath() {
  return spawnSync('cloudflared', ['--version'], { stdio: 'ignore' }).status === 0;
}

// The official release from Cloudflare's GitHub project.
function cloudflaredAsset() {
  const arch = process.arch === 'arm64' ? 'arm64' : 'amd64';
  if (process.platform === 'win32') return { asset: 'cloudflared-windows-amd64.exe', file: 'cloudflared.exe' };
  if (process.platform === 'darwin') return { asset: `cloudflared-darwin-${arch}.tgz`, file: 'cloudflared', tgz: true };
  return { asset: `cloudflared-linux-${arch}`, file: 'cloudflared' };
}

async function ensureCloudflared() {
  const { asset, file, tgz } = cloudflaredAsset();
  const bin = path.join(ROOT, 'bin');
  const target = path.join(bin, file);
  if (fs.existsSync(target) || cloudflaredOnPath()) return true;
  console.log(`Downloading cloudflared (about 40 MB, first run only): ${asset}`);
  try {
    const res = await fetch(`https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    fs.mkdirSync(bin, { recursive: true });
    const data = Buffer.from(await res.arrayBuffer());
    if (tgz) {
      const archive = path.join(bin, asset);
      fs.writeFileSync(archive, data);
      const out = spawnSync('tar', ['-xzf', archive, '-C', bin], { stdio: 'inherit' });
      fs.unlinkSync(archive);
      if (out.status !== 0) throw new Error('could not unpack the download');
    } else {
      fs.writeFileSync(target, data);
    }
    fs.chmodSync(target, 0o755);
    return true;
  } catch (e) {
    console.warn(`Couldn't download cloudflared (${e.message}). Starting without a tunnel.`);
    return false;
  }
}

async function main() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 18) {
    console.error(`Node.js 18 or later is required; this is ${process.version}. Get it from https://nodejs.org`);
    process.exit(1);
  }

  const running = await mockInfo();
  if (running) {
    console.log('Mock TSSA is already running.');
    showDetails(running);
    openBrowser();
    return;
  }

  const tunnel = !args.has('--no-tunnel') && await ensureCloudflared();
  const env = { ...process.env, ...(tunnel ? {} : { MOCK_TUNNEL: 'off' }) };
  const server = spawn(process.execPath, ['server.js'], { cwd: ROOT, stdio: 'inherit', env });
  server.on('exit', (code) => process.exit(code ?? 0));

  let info = null;
  for (let i = 0; i < WAIT_SECONDS; i++) {
    await new Promise((res) => setTimeout(res, 1000));
    info = await mockInfo();
    if (info && (!tunnel || info.tunnel?.host || info.tunnel?.status === 'error')) break;
  }
  if (!info) {
    console.error('The mock did not answer. See the messages above.');
    return;
  }
  showDetails(info);
  openBrowser();
}

main();
