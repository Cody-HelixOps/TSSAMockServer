#!/usr/bin/env node
'use strict';
// Creates the GitHub repo, pushes this folder's main branch and turns on GitHub Pages from /docs.
// Run it yourself. The token stays in an environment variable and is never saved:
//   PowerShell:  $env:GITHUB_TOKEN = '<token>'; node tools/publish-to-github.js
//   macOS/Linux: GITHUB_TOKEN=<token> node tools/publish-to-github.js
// The token needs the "repo" scope (classic), or Administration, Contents and Pages write (fine-grained).
// Options: --name <repo> (default TSSAMockServer), --private (GitHub Pages then needs a paid plan).
const { spawnSync } = require('child_process');
const path = require('path');

const token = process.env.GITHUB_TOKEN;
if (!token) { console.error('Set GITHUB_TOKEN first.'); process.exit(1); }
const flag = (name) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : null; };
const repo = flag('--name') || 'TSSAMockServer';
const isPrivate = process.argv.includes('--private');
const root = path.join(__dirname, '..');

async function gh(method, url, body) {
  const res = await fetch(`https://api.github.com${url}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'mock-tssa-publish', 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: res.status, json };
}

function stop(step, r) {
  console.error(`${step} failed: HTTP ${r.status} ${r.json?.message || ''}`);
  if (r.status === 403 || r.status === 404) console.error('The token probably lacks the permissions listed at the top of this script.');
  process.exit(1);
}

(async () => {
  const me = await gh('GET', '/user');
  if (me.status !== 200) stop('Sign-in', me);
  const owner = me.json.login;

  const existing = await gh('GET', `/repos/${owner}/${repo}`);
  if (existing.status === 404) {
    const made = await gh('POST', '/user/repos', { name: repo, private: isPrivate, has_wiki: false, description: 'Unofficial mock TrueSight Server Automation server for testing BMC Helix Automation Console' });
    if (made.status !== 201) stop('Creating the repo', made);
    console.log(`Created ${owner}/${repo}`);
  } else {
    console.log(`Using the existing repo ${owner}/${repo}`);
  }

  // The token goes to git through its environment, so it isn't saved in .git/config.
  const basic = Buffer.from(`x-access-token:${token}`).toString('base64');
  const push = spawnSync('git', ['push', `https://github.com/${owner}/${repo}.git`, 'HEAD:main'], {
    cwd: root, stdio: 'inherit',
    env: { ...process.env, GIT_CONFIG_COUNT: '2', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0: `Authorization: Basic ${basic}`,
      GIT_CONFIG_KEY_1: 'safe.directory', GIT_CONFIG_VALUE_1: root.replace(/\\/g, '/') },
  });
  if (push.status !== 0) { console.error('git push failed.'); process.exit(1); }

  const pages = await gh('POST', `/repos/${owner}/${repo}/pages`, { source: { branch: 'main', path: '/docs' } });
  if (![201, 409].includes(pages.status)) stop('Turning on GitHub Pages', pages);

  console.log(`\nRepo:  https://github.com/${owner}/${repo}`);
  console.log(`Pages: https://${owner.toLowerCase()}.github.io/${repo}/  (the first build takes a minute or two)`);
})().catch((e) => { console.error(e.message); process.exit(1); });
