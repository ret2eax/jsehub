#!/usr/bin/env node
// tools/fetch_diffs.js
// Pre-fetch the diff for each verified (high-confidence) ITW patch map into a same-origin
// file the CVE modal can load on demand: public/api/diff/<cve>.json.
//
// Why build-time + same-origin: fetching GitHub diffs live from the browser fails (the .diff
// endpoint sends no CORS headers; the API is rate-limited). Fetching once here, with the CI
// token, and serving the result from our own origin sidesteps both, and keeps the page light
// (the modal loads a diff only when a CVE is opened).
//
// GitHub-hosted engines only (v8/v8, WebKit/WebKit, mozilla-firefox/firefox). chromium/src
// rows (Gitiles) stay link-only. Failures are per-CVE and non-fatal so this never blocks deploy.

import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = process.cwd();
const DATA = path.join(ROOT, 'data');
const OUT = path.join(ROOT, 'public', 'api', 'diff');
const GH_API = 'https://api.github.com';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

const REPO = {
  'v8/v8': 'v8/v8',
  'webkit/webkit': 'WebKit/WebKit',
  'mozilla-firefox/firefox': 'mozilla-firefox/firefox',
};
const SOURCES = [
  ['cves.json', 'itw_chrome_related'],
  ['jsc_cves.json', 'itw_related'],
  ['sm_cves.json', 'itw_related'],
];
const MAX_DIFF_LINES = 600;   // truncate the rare large fix; modal links out for the full diff
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function readJSON(file, fb) { try { return JSON.parse(await fs.readFile(path.join(DATA, file), 'utf8')); } catch { return fb; } }

async function ghJSON(url) {
  const r = await fetch(url, { headers: { 'User-Agent': 'js-engine-hub/diffs', Accept: 'application/vnd.github+json', ...GH_AUTH } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// Build a renderable unified diff from the compare API's per-file patches.
function buildDiffText(files) {
  const parts = [];
  for (const f of files) {
    parts.push(`diff --git a/${f.file} b/${f.file}`);
    if (f.status === 'added') parts.push('new file');
    if (f.status === 'removed') parts.push('deleted file');
    if (f.patch) parts.push(f.patch);
    else parts.push('@@ (no inline patch: binary or too large) @@');
  }
  return parts.join('\n');
}

async function main() {
  await fs.mkdir(OUT, { recursive: true });
  if (!GH_TOKEN) console.log('[diffs] WARN: no token; compare API is rate-limited.');

  // de-dupe rows across files by CVE; keep the confident, github-hosted ones with both commits
  const rows = new Map();
  for (const [file, key] of SOURCES) {
    const arr = (await readJSON(file, {}))[key] || [];
    for (const x of arr) {
      const proj = x.patchmap?.project;
      if (x.patchmap?.confident && x.patched_commit && x.unpatched_commit && REPO[proj] && !rows.has(x.cve)) {
        rows.set(x.cve, { cve: x.cve, project: proj, repo: REPO[proj], unpatched: x.unpatched_commit, patched: x.patched_commit });
      }
    }
  }

  let ok = 0, fail = 0;
  for (const r of rows.values()) {
    try {
      const cmp = await ghJSON(`${GH_API}/repos/${r.repo}/compare/${r.unpatched}...${r.patched}`);
      const files = (cmp.files || []).map(f => ({
        file: f.filename, status: f.status, additions: f.additions || 0, deletions: f.deletions || 0, patch: f.patch || null,
      }));
      let diff = buildDiffText(files);
      const lines = diff.split('\n');
      const truncated = lines.length > MAX_DIFF_LINES;
      if (truncated) diff = lines.slice(0, MAX_DIFF_LINES).join('\n');

      const out = {
        cve: r.cve,
        project: r.project,
        url: `https://github.com/${r.repo}/compare/${r.unpatched}...${r.patched}`,
        additions: files.reduce((n, f) => n + f.additions, 0),
        deletions: files.reduce((n, f) => n + f.deletions, 0),
        files: files.map(({ file, status, additions, deletions }) => ({ file, status, additions, deletions })),
        diff,
        truncated,
      };
      await fs.writeFile(path.join(OUT, `${r.cve}.json`), JSON.stringify(out));
      ok++;
    } catch (e) {
      fail++;
      console.error(`[diffs] ${r.cve}: ${e?.message || e}`);
    }
    await sleep(60);
  }
  console.log(`[diffs] wrote ${ok} diff(s) to public/api/diff/ (${fail} failed, chromium/src skipped).`);
}

main().catch(e => { console.error('[diffs] non-fatal error:', e?.message || e); /* never block deploy */ });
