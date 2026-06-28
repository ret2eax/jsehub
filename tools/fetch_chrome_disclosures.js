#!/usr/bin/env node
// tools/fetch_chrome_disclosures.js
// Recent Chrome security disclosures (last N days, default 90) from the Chrome Releases blog
// ("Stable Channel Update for Desktop" posts), with a patch map per CVE.
//
// Chrome assigns a CVE to nearly every fix (a milestone post can roll up hundreds of internal
// fuzzing finds), so we keep only EXTERNALLY-REPORTED, Critical/High, browser/JS-engine
// exploitation-class bugs - the researcher disclosures, matching the in-the-wild table's kind.
//
// Resolution reuses the V8 ITW resolver helpers (Gerrit by bug id, then a git-mirror fallback).

import fs from 'node:fs/promises';
import path from 'node:path';
import { isExploitClass } from './exploit_class.js';
import { gerritQuery, scoreChange, resolveTracks, githubV8Fix, githubChromiumFix, looksLikeNonFix, changeUrl } from './fetch_v8_itw_patchmap.js';

const OUT = path.join(process.cwd(), 'data', 'chrome_disclosures.json');
const WINDOW_DAYS = Number(process.env.DISCLOSURE_DAYS || 90);
const FEED = 'https://chromereleases.googleblog.com/feeds/posts/default?alt=json';
const UA = 'js-engine-hub/chrome-disclosures';
const CONCURRENCY = Number(process.env.DISC_CONCURRENCY || 2); // Gerrit search is heavy per CVE and rate-sensitive.
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Resolve items with a small bounded concurrency pool, staggering to avoid Gerrit 429s.
async function mapPool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async (_, lane) => {
    await sleep(lane * 250);
    while (i < items.length) { const idx = i++; await fn(items[idx]); await sleep(200); }
  }));
}

async function jget(url) {
  const r = await fetch(url, { headers: { 'User-Agent': UA } });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}

// Parse a Stable Channel Update post's security section into CVE entries.
function parsePost(contentHtml) {
  const html = contentHtml.replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ').replace(/\s+/g, ' ');
  const ver = (html.match(/updated to (\d+\.\d+\.\d+\.\d+)/i) || [])[1] || null;
  const out = [];
  // [reward][bug] Severity CVE-xxxx-nnn: Title. Reported by <name> on <date>
  const re = /\[\s*(\$[\d,]+|N\/A|TBD)\s*\]\s*\[\s*(\d+)\s*\]\s*(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d+)\s*:?\s*(.*?)(?:\s*Reported by\s+(.*?)\s+on\b|\s*(?=\[\s*(?:\$|N\/A|TBD)))/gi;
  let m;
  while ((m = re.exec(html))) {
    const [, reward, bug, severity, cve, title, reporter] = m;
    out.push({
      cve, bug, severity: severity.toLowerCase(),
      title: (title || '').replace(/\.\s*$/, '').trim(),
      reporter: (reporter || '').trim() || null,
      external: /^\$/.test(reward) || Boolean(reporter && !/google|chrome team|internal/i.test(reporter)),
      ver,
    });
  }
  return out;
}

async function resolveChrome(cve, bug) {
  let project = null, change = null, t = null, confident = false, source = 'gerrit';
  let patched = null, unpatched = null, date = null, url = null;
  try {
    // The bug *tracker* may be restricted, but Gerrit indexes the commit footer: V8 commits use
    // "Fixed: <bug>", Chromium uses "Bug: <bug>". Two targeted queries cover both (and avoid the
    // 10-query-per-CVE search that exhausts Gerrit's rate limit across a whole disclosure batch).
    const byNum = new Map();
    for (const needle of [`"Fixed: ${bug}"`, `"Bug: ${bug}"`]) {
      const arr = await gerritQuery(`status:merged ${needle}`, 25);
      for (const c of arr) {
        if ((c.project === 'v8/v8' || c.project === 'chromium/src') && !byNum.has(c._number)) byNum.set(c._number, c);
      }
      await sleep(120);
    }
    const cands = [...byNum.values()];
    if (cands.length) {
      let best = null, bestMeta = null;
      for (const c of cands) {
        const m = scoreChange(c, String(bug));
        if (!best || m.score > bestMeta.score || (m.score === bestMeta.score && m.submitted > bestMeta.submitted)) { best = c; bestMeta = m; }
      }
      project = best.project; change = best._number;
      t = await resolveTracks(project, change);
      confident = !looksLikeNonFix((t.message_preview || '').split('\n')[0]);
      const hasOrig = Boolean(t.patched_original);
      if (confident) {
        patched = hasOrig ? t.patched_original : t.patched_backport;
        unpatched = hasOrig ? t.unpatched_original : t.unpatched_backport;
        date = t.patched_date || null; url = changeUrl(project, change);
      }
    }
  } catch (e) { /* fall through to fallback */ }

  if (!confident) {
    try {
      const fb = await githubV8Fix(cve);
      if (fb) {
        confident = true; source = 'github';
        project = fb.project; patched = fb.patched; unpatched = fb.unpatched;
        date = fb.date || null; url = `https://github.com/${fb.project}/commit/${fb.patched}`;
      }
    } catch (e) { /* none */ }
  }
  // Last resort: a Chromium CL still embargoed on Gerrit may already be public in the
  // chromium/chromium mirror with an exact Bug:/Fixed: footer (dependency rolls are excluded).
  if (!confident) {
    try {
      const fb = await githubChromiumFix(bug);
      if (fb) {
        confident = true; source = 'github-chromium';
        project = fb.project; patched = fb.patched; unpatched = fb.unpatched;
        date = fb.date || null; url = null;
      }
    } catch (e) { /* none */ }
  }
  if (!patched || !unpatched) return null;
  // Reaching here means a confident resolution (patched + its exact vulnerable parent).
  return { project, change, patched, unpatched, date, url, source, confident: true, message_preview: t?.message_preview || null };
}

async function main() {
  const since = Date.now() - WINDOW_DAYS * 86400000;
  const seen = new Set(); const entries = [];
  for (let start = 1; start <= 100; start += 25) {
    let j; try { j = await jget(`${FEED}&max-results=25&start-index=${start}`); } catch { break; }
    const es = j.feed.entry || [];
    for (const e of es) if (!seen.has(e.id.$t)) { seen.add(e.id.$t); entries.push(e); }
    if (es.length < 25) break;
    // stop once we are well past the window
    if (es.length && new Date(es[es.length - 1].published.$t).getTime() < since) break;
  }
  const posts = entries.filter(e =>
    /Stable Channel Update for Desktop/i.test(e.title.$t) &&
    new Date(e.published.$t).getTime() >= since && /CVE-/.test(e.content.$t));

  // Collect externally-reported, critical/high, exploitation-class CVEs (newest post first; dedupe).
  const byCve = new Map();
  for (const e of posts) {
    const disclosed = new Date(e.published.$t).toISOString();
    for (const c of parsePost(e.content.$t)) {
      if (byCve.has(c.cve)) continue;
      if (!['critical', 'high'].includes(c.severity)) continue;
      if (!c.external) continue;
      if (!isExploitClass(c.title)) continue;
      byCve.set(c.cve, {
        cve: c.cve, disclosed, vendor: 'Google', product: 'Chrome',
        severity: c.severity, reporter: c.reporter,
        shortDescription: c.title || null, description: null,
        fixed_in: c.ver ? `Chrome ${c.ver}` : null,
        _bug: c.bug,
      });
    }
  }
  const rows = [...byCve.values()];
  console.log(`[chrome-disc] ${rows.length} externally-reported critical/high exploitation CVE(s) in ${WINDOW_DAYS}d; resolving patch maps...`);

  await mapPool(rows, CONCURRENCY, async (r) => {
    const bug = r._bug; delete r._bug;
    const fix = await resolveChrome(r.cve, bug);
    if (fix) {
      const confident = fix.confident;
      r.patched_commit = confident ? fix.patched : null;
      r.unpatched_commit = confident ? fix.unpatched : null;
      r.patched_repo = fix.project;
      r.patchmap = {
        project: fix.project, confident, source: fix.source,
        gerrit_change: fix.change || null, url: fix.url,
        bug: Number(bug), bug_url: `https://issues.chromium.org/issues/${bug}`,
        patched_date: fix.date, message_preview: fix.message_preview,
        patched_commit: confident ? fix.patched : null,
        unpatched_commit: confident ? fix.unpatched : null,
      };
    } else {
      r.patchmap = { project: 'v8/v8', confident: false, bug: Number(bug), bug_url: `https://issues.chromium.org/issues/${bug}` };
    }
  });
  const high = rows.filter(r => r.patchmap?.confident).length;
  const low = rows.filter(r => r.patchmap && !r.patchmap.confident).length;

  rows.sort((a, b) => (a.cve < b.cve ? 1 : -1));
  await fs.mkdir(path.dirname(OUT), { recursive: true });
  await fs.writeFile(OUT, JSON.stringify({ generated: new Date().toISOString(), window_days: WINDOW_DAYS, items: rows }, null, 2) + '\n');
  console.log(`[chrome-disc] wrote ${OUT}: ${rows.length} CVE(s) | patch maps high=${high} low=${low}`);
}

const __isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (__isMain) main().catch(e => { console.error('[chrome-disc] non-fatal:', e?.message || e); });
