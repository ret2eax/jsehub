#!/usr/bin/env node
// tools/fetch_sm_disclosures.js
// Recent Firefox security disclosures (last N days, default 90) from the Mozilla Foundation
// Security Advisories (MFSA), with a patch map per CVE. Disclosures are the full set of fixed
// CVEs per release - not just the CISA KEV / in-the-wild subset.
//
// Source: mozilla/foundation-security-advisories (the same authoritative repo the ITW patch map
// uses). Each MFSA YAML lists every CVE fixed in a release with severity, reporter, bug, and
// fixed_in. We reuse the SM resolver (resolveFix) for the bug -> commit -> parent step.
//
// Output rows mirror the ITW row shape so the existing table/modal/diff machinery works as-is.

import fs from 'node:fs/promises';
import path from 'node:path';
import yaml from 'js-yaml';
import { resolveFix } from './fetch_sm_itw_patchmap.js';
import { isExploitClass } from './exploit_class.js';

const OUT = path.join(process.cwd(), 'data', 'sm_disclosures.json');
const WINDOW_DAYS = Number(process.env.DISCLOSURE_DAYS || 90);
const REPO_API = 'https://api.github.com/repos/mozilla/foundation-security-advisories/contents/announce';
const RAW = 'https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce';
const PROJECT = 'mozilla-firefox/firefox';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};
const UA = 'js-engine-hub/sm-disclosures';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function jget(url, hdr = {}) {
  const r = await fetch(url, { headers: { 'User-Agent': UA, ...hdr } });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
}
async function tget(url) {
  const r = await fetch(url, { headers: { 'User-Agent': UA } });
  if (!r.ok) return null;
  return r.text();
}

// MFSA bug urls are numeric ids, comma lists, or full URLs; pull the numeric Bugzilla ids.
function bugIds(bugs) {
  const out = [];
  for (const b of (bugs || [])) {
    const s = String(b?.url ?? b ?? '');
    for (const m of s.matchAll(/\b(\d{5,8})\b/g)) out.push(m[1]);
  }
  return out;
}

async function main() {
  const since = Date.now() - WINDOW_DAYS * 86400000;
  const years = [...new Set([new Date().getUTCFullYear(), new Date(since).getUTCFullYear()])];

  // List MFSA files for the relevant year(s), newest first.
  let files = [];
  for (const y of years) {
    try {
      const list = await jget(`${REPO_API}/${y}`, { Accept: 'application/vnd.github+json', ...GH_AUTH });
      for (const f of list) {
        const m = /^mfsa(\d{4})-(\d+)\.yml$/.exec(f.name || '');
        if (m) files.push({ year: +m[1], num: +m[2], name: f.name });
      }
    } catch (e) { console.warn(`[sm-disc] list ${y}: ${e.message}`); }
  }
  files.sort((a, b) => (b.year - a.year) || (b.num - a.num));

  // Pull advisories, keep those announced within the window.
  const rows = [];
  const seen = new Set();
  for (const f of files.slice(0, 40)) {
    const text = await tget(`${RAW}/${f.year}/${f.name}`);
    if (!text) continue;
    let doc; try { doc = yaml.load(text); } catch { continue; }
    const announced = doc?.announced ? new Date(doc.announced) : null;
    if (!announced || isNaN(announced) || announced.getTime() < since) continue;

    const fixedIn = Array.isArray(doc.fixed_in) ? doc.fixed_in.join(', ') : (doc.fixed_in || '');
    if (!/firefox/i.test(fixedIn)) continue; // browser only - drop Thunderbird/SeaMonkey-only advisories
    for (const [cve, adv] of Object.entries(doc.advisories || {})) {
      if (!/^CVE-\d{4}-\d+$/.test(cve) || seen.has(cve)) continue;
      seen.add(cve);
      const bugs = bugIds(adv.bugs);
      rows.push({
        cve,
        disclosed: announced.toISOString(),
        vendor: 'Mozilla', product: 'Firefox',
        severity: (adv.impact || doc.impact || '').toLowerCase() || null,
        reporter: adv.reporter || null,
        shortDescription: (adv.title || '').replace(/\s+/g, ' ').trim() || null,
        description: (adv.description || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || null,
        fixed_in: fixedIn || null,
        mfsa: f.name.replace('.yml', ''),
        _bugs: bugs,
      });
    }
    await sleep(60);
  }

  // Researcher-disclosure scope: critical/high severity, attributed to a named reporter
  // (drop the internal "Memory safety bugs fixed in X" fuzzing roll-ups credited to the team).
  const SEV = new Set(['critical', 'high']);
  const keep = rows.filter(r =>
    SEV.has(r.severity) && r.reporter && !/fuzzing team/i.test(r.reporter) &&
    !/memory safety bugs/i.test(r.shortDescription || '') &&
    isExploitClass(`${r.shortDescription} ${r.description || ''}`));
  console.log(`[sm-disc] ${rows.length} CVE(s) in ${WINDOW_DAYS}d; ${keep.length} critical/high researcher-attributed; resolving patch maps...`);

  // Patch map per CVE (reuse the SM resolver). Bounded, so cost is manageable.
  let high = 0, low = 0;
  for (const r of keep) {
    let best = null;
    for (const bug of r._bugs) {
      const fix = await resolveFix(bug);
      await sleep(80);
      if (!fix) continue;
      if (!best) best = fix;
      if (fix.confident) { best = fix; break; }
    }
    delete r._bugs;
    if (best) {
      const confident = best.confident;
      const ui = (c) => confident ? c : null;
      r.patched_commit = ui(best.patched_commit) || null;
      r.unpatched_commit = ui(best.unpatched_commit) || null;
      r.patched_repo = PROJECT;
      r.patchmap = {
        project: PROJECT,
        bug: Number(best.bug),
        bug_url: `https://bugzilla.mozilla.org/show_bug.cgi?id=${best.bug}`,
        confident,
        subject: best.subject,
        candidate_count: best.candidate_count,
        patched_date: best.patched_date || null,
        patched_commit: ui(best.patched_commit) || null,
        unpatched_commit: ui(best.unpatched_commit) || null,
      };
      confident ? high++ : low++;
    }
    await sleep(40);
  }

  keep.sort((a, b) => (a.cve < b.cve ? 1 : -1));
  await fs.mkdir(path.dirname(OUT), { recursive: true });
  await fs.writeFile(OUT, JSON.stringify({ generated: new Date().toISOString(), window_days: WINDOW_DAYS, items: keep }, null, 2) + '\n');
  console.log(`[sm-disc] wrote ${OUT}: ${keep.length} CVE(s) | patch maps high=${high} low=${low}`);
}

main().catch(e => { console.error('[sm-disc] non-fatal error:', e?.message || e); /* never block deploy */ });
