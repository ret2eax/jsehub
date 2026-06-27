#!/usr/bin/env node
// tools/fetch_jsc_itw_patchmap.js
// Node 18+ required (global fetch). Run: `node tools/fetch_jsc_itw_patchmap.js`
//
// Safari/JSC (WebKit) ITW patch map, modeled on the V8 and SpiderMonkey maps.
// Resolution chain (both ends public and authoritative):
//   CVE -> Apple security advisory pages -> "WebKit Bugzilla: N"
//        -> WebKit commit whose OWN message references show_bug.cgi?id=N
//        -> git parent = the exact vulnerable commit (WebKit history is linear).
//
// Robustness (this is what earns the `high` tier despite WebKit security bugs being
// access-restricted, so we can never read the bug itself):
//   1. Binding direction: an Apple entry is  ...Impact / Description / WebKit Bugzilla: N
//      / CVE-XXXX: credit.  A CVE's bug is the bugzilla line that PRECEDES its CVE line.
//   2. Cross-page corroboration: every WebKit CVE appears in 5-8 product advisories
//      (iOS/macOS/Safari/tvOS/...). We require >=2 to agree on the same bug, which
//      defeats any single-page parse error. A format change degrades to blank, not wrong.
//   3. Exact id=N commit filter + a single mainline fix; cherry-picks collapse to their
//      mainline original (parsed from "Cherry-pick ... (hash)").
// `high`  = >=2 advisories agree + exactly one mainline fix commit + a resolvable parent.
// `low`   = a bug resolved but the fix is ambiguous (multi-part), so commits are withheld.
// `—`     = no WebKit bugzilla published for this CVE (older or non-WebKit), nothing shown.

import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const CVES_JSON = path.join(DATA_DIR, 'jsc_cves.json');
const OUT_JSON  = path.join(DATA_DIR, 'jsc_itw_patchmap.json');

const GH_API = 'https://api.github.com';
const WK_REPO = 'WebKit/WebKit';
const PROJECT = 'webkit/webkit';                    // value consumed by commitUrl() in pages/index.js

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 js-engine-hub';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

const MAX_PAGES = 8;           // cap Apple advisory pages fetched per CVE
const CORROBORATE = 2;         // advisories that must agree on the bug for `high`

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const short = (s) => (typeof s === 'string' && s.length >= 7 ? s.slice(0, 12) : s || '');
const ghCommitUrl = (sha) => sha ? `https://github.com/${WK_REPO}/commit/${sha}` : null;

async function httpJSON(url, { retries = 5, backoff = 500, headers = {} } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/vnd.github+json', ...headers } });
      if (r.ok) return r.json();
      if (r.status === 404) return null;
      lastErr = new Error(`${r.status} ${r.statusText}`);
    } catch (e) { lastErr = e; }
    await sleep(backoff * Math.pow(1.4, i));
  }
  throw lastErr || new Error('fetch failed: ' + url);
}

async function httpText(url, { retries = 3, backoff = 450 } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept-Language': 'en-US' } });
      if (r.ok) return r.text();
      if (r.status === 404) return null;
      lastErr = new Error(`${r.status} ${r.statusText}`);
    } catch (e) { lastErr = e; }
    await sleep(backoff * Math.pow(1.3, i));
  }
  throw lastErr || new Error('fetch failed: ' + url);
}

async function readJSON(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch { return fallback; }
}
async function writeJSON(file, obj) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

/* ----------------------- CVE -> Apple advisory pages ----------------------- */
async function appleAdvisoryUrls(cve) {
  const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cve)}`;
  let meta;
  try { meta = await httpJSON(url, { headers: { Accept: 'application/json' } }); }
  catch { return []; }
  const refs = [
    ...(meta?.containers?.cna?.references || []),
    ...((meta?.containers?.adp || []).flatMap(a => a.references || [])),
  ];
  return [...new Set(
    refs.map(r => r?.url || '')
        .filter(u => /support\.apple\.com\/(en-us\/|kb\/)?(HT)?\d+/i.test(u))
  )];
}

// Bind CVE to the "WebKit Bugzilla: N" line that PRECEDES its "CVE-XXXX: credit" line
// within the same entry. Apple lists the bugzilla just above the CVE id.
function bugForCveInPage(html, cve) {
  let h = html.replace(/<\/(p|div|li|h\d|tr|td|br)>/gi, '\n').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ');
  const lines = h.split('\n').map(s => s.replace(/\s+/g, ' ').trim()).filter(Boolean);
  let curBug = null;
  for (const ln of lines) {
    const bz = ln.match(/WebKit Bugzilla:?\s*(\d{5,7})/i);
    if (bz) { curBug = bz[1]; continue; }
    const cm = ln.match(/^(CVE-20\d{2}-\d+)\s*:/);   // a CVE definition line (id: credit)
    if (cm) {
      if (cm[1] === cve) return curBug;
      curBug = null;                                 // entry consumed, reset for the next
    }
  }
  return null;
}

// Fetch advisory pages until two agree on a bug (early-exit), capped at MAX_PAGES.
async function resolveBug(cve) {
  const urls = (await appleAdvisoryUrls(cve)).slice(0, MAX_PAGES);
  const votes = new Map();
  let pages = 0;
  for (const u of urls) {
    let html;
    try { html = await httpText(u); } catch { html = null; }
    if (html) {
      pages++;
      const bug = bugForCveInPage(html, cve);
      if (bug) {
        votes.set(bug, (votes.get(bug) || 0) + 1);
        if (votes.get(bug) >= CORROBORATE) return { bug, agree: votes.get(bug), pages };
      }
    }
    await sleep(120);
  }
  const top = [...votes.entries()].sort((a, b) => b[1] - a[1])[0];
  return top ? { bug: top[0], agree: top[1], pages } : { bug: null, agree: 0, pages };
}

/* ----------------------- bug -> fix commit -> parent ----------------------- */
function parseCherryPickOriginal(message) {
  // "Cherry-pick 252432.839@safari-7614-branch (71cdc1c09ef1). rdar://..."
  const m = (message || '').match(/cherry-pick[^\n(]*\(([0-9a-f]{7,40})\)/i);
  return m ? m[1] : null;
}

async function commitsForBug(bug) {
  const q = `repo:${WK_REPO}+${bug}`;
  let res;
  try {
    res = await httpJSON(`${GH_API}/search/commits?q=${q}&per_page=30`,
      { headers: { Accept: 'application/vnd.github+json', ...GH_AUTH } });
  } catch (e) {
    console.log(`[jsc-patchmap] commit search failed for bug ${bug}: ${e?.message || e}`);
    return [];
  }
  return (res?.items || [])
    .map(it => ({ sha: it.sha, message: it.commit?.message || '' }))
    .filter(c => new RegExp(`show_bug\\.cgi\\?id=${bug}\\b`).test(c.message))   // exact bug reference only
    .map(c => ({ sha: c.sha, subject: c.message.split('\n')[0], message: c.message }));
}

async function commitMeta(sha) {
  const c = await httpJSON(`${GH_API}/repos/${WK_REPO}/commits/${sha}`, { headers: { ...GH_AUTH } });
  return {
    parent: c?.parents?.[0]?.sha || null,
    message: c?.commit?.message || '',
    files: (c?.files || []).map(f => f.filename),
  };
}

// Resolve the single mainline fix commit (+ exact parent) for a bug.
// mainline = a normal landing; cherry-picks collapse to the original they name.
async function resolveFix(bug) {
  const commits = await commitsForBug(bug);
  if (!commits.length) return null;

  const mainline = commits.filter(c => !/^cherry-pick/i.test(c.subject));
  const cherries = commits.filter(c => /^cherry-pick/i.test(c.subject));

  let fixSha = null, ambiguous = false;
  if (mainline.length === 1) {
    fixSha = mainline[0].sha;
  } else if (mainline.length === 0 && cherries.length >= 1) {
    // No mainline match in results; recover the original from the cherry-pick message.
    const orig = parseCherryPickOriginal(cherries[0].message);
    fixSha = orig || cherries[0].sha;
  } else if (mainline.length > 1) {
    ambiguous = true;                 // multi-part landing; single parent is not well-defined
    fixSha = mainline[0].sha;
  }
  if (!fixSha) return null;

  const meta = await commitMeta(fixSha);
  return {
    bug,
    ambiguous,
    patched_commit: fixSha,
    unpatched_commit: meta.parent,
    subject: meta.message.split('\n')[0],
    files: meta.files.slice(0, 6),
    candidate_count: commits.length,
  };
}

/* ------------------------------- main ------------------------------------ */
async function main() {
  console.log('[jsc-patchmap] start main()');
  if (!GH_TOKEN) console.log('[jsc-patchmap] WARN: no GITHUB_TOKEN/GH_TOKEN; commit search is heavily rate-limited.');

  const cvesData = await readJSON(CVES_JSON, { itw_related: [] });
  const rows = Array.isArray(cvesData.itw_related) ? cvesData.itw_related : [];
  console.log(`[jsc-patchmap] scanning ${rows.length} Safari/JSC ITW CVE(s)…\n`);

  const outMap = {};
  const byCve = new Map();
  for (const r of rows) if (r?.cve) byCve.set(r.cve, r);

  let high = 0, low = 0;

  for (const r of rows) {
    const cve = r?.cve;
    if (!cve) continue;

    const { bug, agree, pages } = await resolveBug(cve);
    if (!bug) {
      console.log(`[jsc-patchmap] ${cve}: no WebKit bugzilla (scanned ${pages} advisor${pages === 1 ? 'y' : 'ies'})`);
      continue;
    }

    const fix = await resolveFix(bug);
    if (!fix) {
      console.log(`[jsc-patchmap] ${cve}: bug ${bug} (agree ${agree}) → no exact-ref commit`);
      continue;
    }

    // `high` requires cross-page corroboration, an unambiguous single fix, and a real parent.
    const confident = agree >= CORROBORATE && !fix.ambiguous && Boolean(fix.unpatched_commit);
    const uiPatched   = confident ? fix.patched_commit : null;
    const uiUnpatched = confident ? fix.unpatched_commit : null;

    const row = byCve.get(cve);
    if (row) {
      row.patched_repo = PROJECT;
      row.patched_url  = ghCommitUrl(fix.patched_commit);
      row.patched_commit = uiPatched || null;
      row.unpatched_commit = uiUnpatched || null;
      row.unpatched_url = uiUnpatched ? ghCommitUrl(uiUnpatched) : null;
      row.patchmap = {
        ...(row.patchmap || {}),
        project: PROJECT,
        bug: Number(bug),
        bug_url: `https://bugs.webkit.org/show_bug.cgi?id=${bug}`,
        advisories_agree: agree,
        confident,
        subject: fix.subject,
        candidate_count: fix.candidate_count,
        patched_commit: uiPatched || null,
        unpatched_commit: uiUnpatched || null,
        urls: {
          patched: fix.patched_commit ? ghCommitUrl(fix.patched_commit) : null,
          unpatched: fix.unpatched_commit ? ghCommitUrl(fix.unpatched_commit) : null,
        },
      };
    }

    outMap[cve] = {
      cve,
      project: PROJECT,
      bug: Number(bug),
      advisories_agree: agree,
      confident,
      subject: fix.subject,
      candidate_count: fix.candidate_count,
      patched_commit: uiPatched || null,
      unpatched_commit: uiUnpatched || null,
      files: fix.files,
      generated: new Date().toISOString(),
    };

    if (confident) {
      high++;
      console.log(`[jsc-patchmap] HIGH: ${cve} → bug ${bug} (agree ${agree}) patched=${short(fix.patched_commit)} · unpatched=${short(fix.unpatched_commit)} "${fix.subject.slice(0,46)}"`);
    } else {
      low++;
      const why = fix.ambiguous ? 'multi-part landing' : agree < CORROBORATE ? `only ${agree} advisory agrees` : 'no parent';
      console.log(`[jsc-patchmap] LOW: ${cve} → bug ${bug} (${why}) → commits withheld`);
    }
    await sleep(150);
  }

  await writeJSON(OUT_JSON, { generated: new Date().toISOString(), items: outMap });
  await writeJSON(CVES_JSON, { ...cvesData, itw_related: rows });

  console.log(`\n[jsc-patchmap] done. high=${high} low=${low} of ${rows.length} CVE(s).`);
}

main().catch(err => {
  console.error('[jsc-patchmap] fatal:', err?.stack || err?.message || String(err));
  process.exit(1);
});
