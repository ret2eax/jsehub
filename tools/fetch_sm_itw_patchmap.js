#!/usr/bin/env node
// tools/fetch_sm_itw_patchmap.js
// Node 18+ required (global fetch). Run: `node tools/fetch_sm_itw_patchmap.js`
//
// Firefox/SpiderMonkey ITW patch map, modeled on tools/fetch_v8_itw_patchmap.js.
// Resolution chain (all machine-readable, no scraping of bloated HTML):
//   CVE -> MFSA advisory YAML (mozilla/foundation-security-advisories) -> Bugzilla bug id
//        -> GitHub commit search on mozilla-firefox/firefox ("Bug <id>") -> fix commit
//        -> git parent = the exact vulnerable commit.
// CVE->bug is authoritative (Mozilla publishes it); bug->fix needs scoring to pick the
// real fix among multi-part landings/tests/backouts, same problem the V8 map solves.
// Honesty rule (mirrors V8): only a single clean fix commit yields a `high` row with an
// exact parent. Multi-part landings or unresolved bugs are left blank (`low`/`—`).

import fs from 'node:fs/promises';
import path from 'node:path';
import { p0BugForCve } from './p0_rca.js';

const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const CVES_JSON = path.join(DATA_DIR, 'sm_cves.json');
const OUT_JSON  = path.join(DATA_DIR, 'sm_itw_patchmap.json');

const GH_API = 'https://api.github.com';
const GIT_REPO = 'mozilla-firefox/firefox';        // git mirror of mozilla-central (default branch = main)
const PROJECT = 'mozilla-firefox/firefox';          // value consumed by commitUrl() in pages/index.js
const ADVISORIES_RAW = 'https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master';

const UA = 'js-engine-hub/sm-patchmap/1.0';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const short = (s) => (typeof s === 'string' && s.length >= 7 ? s.slice(0, 12) : s || '');

async function httpJSON(url, { retries = 5, backoff = 500, headers = {} } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, Accept: 'application/vnd.github+json', ...headers } });
      if (r.ok) return r.json();
      // 403/429 = rate limit; back off harder. 404 = give up immediately.
      if (r.status === 404) return null;
      lastErr = new Error(`${r.status} ${r.statusText}`);
    } catch (e) {
      lastErr = e;
    }
    await sleep(backoff * Math.pow(1.4, i));
  }
  throw lastErr || new Error('fetch failed: ' + url);
}

async function httpText(url, { retries = 4, backoff = 450, headers = {} } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, ...headers } });
      if (r.ok) return r.text();
      if (r.status === 404) return null;
      lastErr = new Error(`${r.status} ${r.statusText}`);
    } catch (e) {
      lastErr = e;
    }
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

/* ----------------------- CVE meta (MITRE) -> refs ----------------------- */
async function fetchCveRefs(cveId) {
  const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`;
  try {
    const meta = await httpJSON(url, { headers: { Accept: 'application/json' } });
    const refs = meta?.containers?.cna?.references ?? [];
    const out = [];
    for (const r of refs) {
      if (r?.url) out.push(String(r.url));
      if (r?.name) out.push(String(r.name));
    }
    return out;
  } catch {
    return [];
  }
}

// Pull Bugzilla bug ids and MFSA advisory ids out of CVE references.
function extractMozillaThings(refs) {
  const bugIds = new Set();
  const mfsaIds = new Set();
  for (const f of refs) {
    let m;
    m = String(f).match(/show_bug\.cgi\?id=(\d+)/i);
    if (m) bugIds.add(m[1]);
    m = String(f).match(/(mfsa\d{4}-\d{2,3})/i);
    if (m) mfsaIds.add(m[1].toLowerCase());
  }
  return { bugIds: [...bugIds], mfsaIds: [...mfsaIds] };
}

/* ------- MFSA advisory YAML (authoritative CVE -> bug mapping) ------- */
// Parse the numeric bug ids listed under a specific CVE in an MFSA YAML file.
// Structure:
//   advisories:
//     CVE-2024-9680:
//       bugs:
//         - url: 1923344
//         - url: https://msrc.microsoft.com/...   (non-numeric, skipped)
function parseBugsForCve(yaml, cve) {
  const lines = yaml.split('\n');
  const cveRe = new RegExp(`^\\s*${cve.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*:\\s*$`, 'i');
  let i = lines.findIndex(l => cveRe.test(l));
  if (i === -1) return [];
  const baseIndent = lines[i].match(/^\s*/)[0].length;
  const bugs = [];
  let inBugs = false;
  for (i = i + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const indent = line.match(/^\s*/)[0].length;
    if (indent <= baseIndent) break;             // next CVE block or dedent
    if (/^\s*bugs\s*:/.test(line)) { inBugs = true; continue; }
    if (inBugs) {
      // a bugs entry is more-indented than `bugs:`; a sibling key at bugs' indent ends it
      const m = line.match(/url\s*:\s*(\d{5,8})\b/);
      if (m) { bugs.push(m[1]); continue; }
      if (/^\s*-/.test(line)) continue;           // non-numeric url entry (e.g. msrc link)
      if (/^\s*\w+\s*:/.test(line)) inBugs = false; // sibling key, bugs list ended
    }
  }
  return bugs;
}

async function bugsFromMfsa(mfsaId, cve) {
  // mfsa2024-51 -> announce/2024/mfsa2024-51.yml
  const m = mfsaId.match(/^mfsa(\d{4})-(\d{2,3})$/);
  if (!m) return [];
  const url = `${ADVISORIES_RAW}/announce/${m[1]}/${mfsaId}.yml`;
  try {
    const yaml = await httpText(url);
    if (!yaml) return [];
    return parseBugsForCve(yaml, cve);
  } catch {
    return [];
  }
}

/* ----------------- bug -> fix commit (scored) ----------------- */
// A landing that is clearly NOT the substantive fix: backout, test-only, sync/import.
function looksLikeNonFix(subject) {
  const s = (subject || '').toLowerCase().trim();
  return (
    /back(ed)?\s?out|backout|\brevert\b/.test(s) ||
    /\b(a|r)=(test|backout)\b/.test(s) ||
    /^bug \d+\s*[-:]\s*(add|update|import|sync|disable|re-?enable|land)\b.*\btest/.test(s) ||
    /\bwpt\b|web-platform-test|crashtest|reftest|mochitest|\btest-only\b/.test(s) ||
    /^no bug\b/.test(s)
  );
}

function scoreCommitSubject(subject, bug) {
  const s = (subject || '').toLowerCase();
  let score = 0;
  if (new RegExp(`^bug ${bug}\\b`).test(s)) score += 60;   // proper landing convention
  else if (s.includes(`bug ${bug}`)) score += 25;
  if (/r=/.test(s)) score += 10;                            // reviewed landing
  if (looksLikeNonFix(s)) score -= 200;
  // multi-part markers are fine individually but signal ambiguity (handled by caller)
  return score;
}

async function searchFixCommits(bug) {
  // GitHub commit search; the bug number appears as "Bug <id>" in the landing subject.
  const q = `repo:${GIT_REPO}+Bug+${bug}`;
  const url = `${GH_API}/search/commits?q=${q}&per_page=30`;
  let res;
  try {
    res = await httpJSON(url, { headers: { Accept: 'application/vnd.github.text-match+json', ...GH_AUTH } });
  } catch (e) {
    console.log(`[sm-patchmap] commit search failed for bug ${bug}: ${e?.message || e}`);
    return [];
  }
  const items = res?.items || [];
  return items
    .map(it => ({ sha: it.sha, subject: (it.commit?.message || '').split('\n')[0] }))
    // keep only landings that actually reference this bug id (avoid substring collisions)
    .filter(c => new RegExp(`\\bBug ${bug}\\b`, 'i').test(c.subject));
}

async function commitParent(sha) {
  const c = await httpJSON(`${GH_API}/repos/${GIT_REPO}/commits/${sha}`, { headers: { ...GH_AUTH } });
  const parent = c?.parents?.[0]?.sha || null;
  const files = (c?.files || []).map(f => f.filename);
  const date = c?.commit?.committer?.date || c?.commit?.author?.date || null;
  return { parent, files, date };
}

const ghCommitUrl = (sha) => sha ? `https://github.com/${GIT_REPO}/commit/${sha}` : null;

// A path that lives only under a test tree (no engine source changed).
function isTestPath(f) {
  return /(^|\/)(jit-test|tests?|testing|reftests?|crashtests?|mochitest|web-platform)\//i.test(f) ||
         /(^|\/)[^/]*test[^/]*\.(js|html|xml|xul|txt|ini|list)$/i.test(f);
}
// Collapse the trailing reviewer/approval trailer ("r=…", "a=…"), "part N", and punctuation
// so multi-part landings / uplifts of ONE fix compare equal.
const normSubject = (s) => (s || '').toLowerCase()
  .replace(/\s+[ar]=.*/, '')      // cut everything from the first " r=" / " a=" trailer onward
  .replace(/part\s*\d+/g, '')
  .replace(/[^a-z0-9]/g, '');

// Given a bug id, return the confident fix commit + vulnerable parent, or a low-confidence note.
// Strategy: drop backouts, then classify each candidate by whether it changed engine source
// (vs test-only). A single source-touching commit -> high. Several commits that are the same
// logical fix split across parts -> high as a range (parent of the earliest .. the latest).
// Genuinely distinct source commits -> low (ambiguous parent withheld).
export async function resolveFix(bug) {
  const candidates = await searchFixCommits(bug);
  if (!candidates.length) return null;

  // Drop obvious non-fixes (backouts/reverts), unless that leaves nothing.
  let cands = candidates.filter(c => !looksLikeNonFix(c.subject));
  if (!cands.length) cands = candidates;

  // Enrich each candidate with files + parent + date so we can classify code vs test-only.
  const enriched = [];
  for (const c of cands) {
    const meta = await commitParent(c.sha);
    const testOnly = meta.files.length > 0 && meta.files.every(isTestPath);
    enriched.push({ ...c, ...meta, testOnly });
    await sleep(60);
  }

  const code = enriched.filter(c => !c.testOnly);

  let chosen = null, unpatched = null, confident = false;
  if (code.length === 1) {
    chosen = code[0];
    unpatched = chosen.parent;
    confident = true;
  } else if (code.length > 1) {
    const subjects = new Set(code.map(c => normSubject(c.subject)));
    if (subjects.size === 1) {
      // Same logical fix landed/uplifted/relanded more than once: anchor on the earliest
      // landing and its own parent for a clean single-commit fix/vulnerable pair.
      const ordered = code.slice().sort((a, b) => new Date(a.date) - new Date(b.date));
      chosen = ordered[0];
      unpatched = ordered[0].parent;
      confident = true;
    } else {
      // Distinct source commits under one bug -> the single vulnerable parent is ambiguous.
      chosen = code.map(c => ({ ...c, score: scoreCommitSubject(c.subject, bug) })).sort((a, b) => b.score - a.score)[0];
      unpatched = chosen.parent;
      confident = false;
    }
  } else {
    // Only test commits resolved (shouldn't normally happen) -> not confident.
    chosen = enriched[0];
    unpatched = chosen?.parent || null;
    confident = false;
  }
  if (!chosen) return null;

  return {
    bug,
    confident: confident && Boolean(unpatched),
    patched_commit: chosen.sha,
    unpatched_commit: unpatched,
    patched_date: chosen.date,
    subject: chosen.subject,
    candidate_count: code.length || enriched.length,
    files: (chosen.files || []).slice(0, 6),
  };
}

/* ------------------------------- main ------------------------------------ */
async function main() {
  console.log('[sm-patchmap] start main()');
  if (!GH_TOKEN) console.log('[sm-patchmap] WARN: no GITHUB_TOKEN/GH_TOKEN; commit search is heavily rate-limited.');

  const cvesData = await readJSON(CVES_JSON, { itw_related: [] });
  const rows = Array.isArray(cvesData.itw_related) ? cvesData.itw_related : [];
  console.log(`[sm-patchmap] scanning ${rows.length} Firefox/SM ITW CVE(s)…\n`);

  const outMap = {};
  const byCve = new Map();
  for (const r of rows) if (r?.cve) byCve.set(r.cve, r);

  let enriched = 0;

  for (const r of rows) {
    const cve = r?.cve;
    if (!cve) continue;
    console.log(`[sm-patchmap] ── ${cve} ─────────────────────────────────────────`);

    // 1) CVE -> Bugzilla bug(s). Prefer authoritative MFSA YAML; fall back to MITRE refs.
    const refs = await fetchCveRefs(cve);
    const { bugIds: refBugs, mfsaIds } = extractMozillaThings(refs);

    let bugIds = [];
    for (const mfsa of mfsaIds) {
      const b = await bugsFromMfsa(mfsa, cve);
      if (b.length) { bugIds = b; console.log(`[sm-patchmap] ${cve} → ${mfsa} → bug(s) ${b.join(', ')}`); break; }
      await sleep(60);
    }
    if (!bugIds.length && refBugs.length) {
      bugIds = refBugs;
      console.log(`[sm-patchmap] ${cve} → bug(s) ${bugIds.join(', ')} (from CVE refs)`);
    }
    // Project Zero's per-CVE RCA can supply the bug when MFSA/MITRE give none.
    let source = 'mozilla';
    if (!bugIds.length) {
      const p0bug = await p0BugForCve(cve, 'sm');
      if (p0bug) { bugIds = [p0bug]; source = 'project-zero'; console.log(`[sm-patchmap] ${cve} → bug ${p0bug} (Project Zero RCA)`); }
    }
    if (!bugIds.length) {
      console.log(`[sm-patchmap] ${cve}: no Bugzilla bug resolved (skipping)`);
      continue;
    }

    // 2) bug -> fix commit -> parent. Try each bug until one yields a confident fix.
    let best = null;
    for (const bug of bugIds) {
      const fix = await resolveFix(bug);
      await sleep(120);
      if (!fix) continue;
      if (!best) best = fix;
      if (fix.confident) { best = fix; break; }
    }

    // Same RCA fallback for the bug -> commit step (bug found but no fix commit). resolveFix still
    // validates the result, so a mis-attributed bug fails safe rather than producing a wrong map.
    if (!best) {
      const p0bug = await p0BugForCve(cve, 'sm');
      if (p0bug && !bugIds.includes(p0bug)) {
        const fix = await resolveFix(p0bug);
        if (fix) { best = fix; source = 'project-zero'; console.log(`[sm-patchmap] ${cve} → bug ${p0bug} (Project Zero RCA)`); }
      }
    }

    if (!best) {
      console.log(`[sm-patchmap] ${cve}: bug(s) ${bugIds.join(', ')} → no fix commit found`);
      continue;
    }

    const confident = best.confident;
    const uiPatched   = confident ? best.patched_commit : null;
    const uiUnpatched = confident ? best.unpatched_commit : null;

    const row = byCve.get(cve);
    if (row) {
      row.patched_repo = PROJECT;
      row.patched_url  = `https://bugzilla.mozilla.org/show_bug.cgi?id=${best.bug}`;
      row.patched_commit = uiPatched || null;
      row.unpatched_commit = uiUnpatched || null;
      row.unpatched_url = uiUnpatched ? ghCommitUrl(uiUnpatched) : null;
      row.patchmap = {
        ...(row.patchmap || {}),
        project: PROJECT,
        bug: Number(best.bug),
        bug_url: `https://bugzilla.mozilla.org/show_bug.cgi?id=${best.bug}`,
        source,
        confident,
        subject: best.subject,
        candidate_count: best.candidate_count,
        patched_date: best.patched_date || null,
        patched_commit: uiPatched || null,
        unpatched_commit: uiUnpatched || null,
        urls: {
          patched: best.patched_commit ? ghCommitUrl(best.patched_commit) : null,
          unpatched: best.unpatched_commit ? ghCommitUrl(best.unpatched_commit) : null,
        },
      };
    }

    outMap[cve] = {
      cve,
      project: PROJECT,
      bug: Number(best.bug),
      confident,
      subject: best.subject,
      candidate_count: best.candidate_count,
      patched_date: best.patched_date || null,
      patched_commit: uiPatched || null,
      unpatched_commit: uiUnpatched || null,
      files: best.files,
      generated: new Date().toISOString(),
    };
    enriched++;

    if (confident) {
      console.log(`[sm-patchmap] OK: ${cve} → bug ${best.bug} patched=${short(best.patched_commit)} · unpatched=${short(best.unpatched_commit)}`);
    } else {
      console.log(`[sm-patchmap] LOW: ${cve} → bug ${best.bug} (${best.candidate_count} landings, ambiguous parent) → commits withheld`);
    }
    await sleep(120);
  }

  await writeJSON(OUT_JSON, { generated: new Date().toISOString(), items: outMap });
  await writeJSON(CVES_JSON, { ...cvesData, itw_related: rows });

  console.log(`\n[sm-patchmap] enriched ${enriched}/${rows.length} CVE(s).`);
}

// Only run when invoked directly (so other tools can import resolveFix without triggering a run).
const __isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (__isMain) main().catch(err => {
  console.error('[sm-patchmap] fatal:', err?.stack || err?.message || String(err));
  process.exit(1);
});
