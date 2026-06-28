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
  ['chrome_disclosures.json', 'items'],
  ['jsc_disclosures.json', 'items'],
  ['sm_disclosures.json', 'items'],
];
const MAX_DIFF_LINES = 600;   // truncate the rare large fix; modal links out for the full diff
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function readJSON(file, fb) { try { return JSON.parse(await fs.readFile(path.join(DATA, file), 'utf8')); } catch { return fb; } }

async function ghJSON(url) {
  const r = await fetch(url, { headers: { 'User-Agent': 'js-engine-hub/diffs', Accept: 'application/vnd.github+json', ...GH_AUTH } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// Gitiles serves chromium/src commits as JSON (no diff, but the full commit message). We use this
// to give chromium/src rows the same full "Fix commit message" the GitHub-hosted rows get.
async function gitilesCommit(sha) {
  const r = await fetch(`https://chromium.googlesource.com/chromium/src/+/${sha}?format=JSON`, { headers: { 'User-Agent': 'js-engine-hub/diffs' } });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  const txt = await r.text();
  return JSON.parse(txt.replace(/^\)\]\}'\s*/, ''));   // strip Gitiles XSSI guard
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

  // de-dupe rows across files by CVE; keep the confident ones with both commits. GitHub-hosted
  // rows get the full diff; chromium/src (Gitiles) rows get a message-only entry so the modal
  // still shows the full "Fix commit message" (the diff stays link-only via Gitiles ^!).
  const rows = new Map();
  for (const [file, key] of SOURCES) {
    const arr = (await readJSON(file, {}))[key] || [];
    for (const x of arr) {
      const proj = x.patchmap?.project;
      if (!(x.patchmap?.confident && x.patched_commit && x.unpatched_commit) || rows.has(x.cve)) continue;
      if (REPO[proj]) {
        rows.set(x.cve, { cve: x.cve, kind: 'github', project: proj, repo: REPO[proj], unpatched: x.unpatched_commit, patched: x.patched_commit });
      } else if (proj === 'chromium/src') {
        rows.set(x.cve, { cve: x.cve, kind: 'gitiles', project: proj, unpatched: x.unpatched_commit, patched: x.patched_commit, sourceUrl: x.patchmap?.url || null });
      }
    }
  }

  let ok = 0, fail = 0, msgOnly = 0;
  for (const r of rows.values()) {
    try {
      if (r.kind === 'gitiles') {
        // chromium/src: capture the full commit message only (no inline diff source).
        const c = await gitilesCommit(r.patched);
        const out = {
          cve: r.cve, project: r.project,
          url: r.sourceUrl || `https://chromium.googlesource.com/chromium/src/+/${r.patched}^!`,
          message: c.message || null, files: [], diff: null, truncated: false,
        };
        await fs.writeFile(path.join(OUT, `${r.cve}.json`), JSON.stringify(out));
        msgOnly++;
        await sleep(60);
        continue;
      }
      const cmp = await ghJSON(`${GH_API}/repos/${r.repo}/compare/${r.unpatched}...${r.patched}`);
      // Full commit message of the patched commit (head of the range) for the modal.
      const headCommit = (cmp.commits || []).find(c => c.sha === r.patched) || (cmp.commits || []).slice(-1)[0];
      const message = headCommit?.commit?.message || null;
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
        message,
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
  console.log(`[diffs] wrote ${ok} diff(s) + ${msgOnly} chromium/src message-only to public/api/diff/ (${fail} failed).`);
}

main().catch(e => { console.error('[diffs] non-fatal error:', e?.message || e); /* never block deploy */ });
