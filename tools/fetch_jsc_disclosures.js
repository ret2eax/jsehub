#!/usr/bin/env node
// tools/fetch_jsc_disclosures.js
// Recent Safari/WebKit (JSC) security disclosures (last N days, default 90) from Apple's security
// releases index, with a patch map per CVE.
//
// Apple publishes no severity rating and no machine-readable feed, so we:
//   1. parse the security-releases index (support.apple.com/en-us/100100) for advisories in window,
//   2. read each advisory's WebKit / JavaScriptCore component entries (CVE, Impact, reporter, bug),
//   3. keep externally-credited, exploitation-class (memory-corruption / engine) CVEs - matching the
//      in-the-wild table's kind, since there is no severity to filter on,
//   4. resolve the patch map via the JSC ITW resolver (WebKit Bugzilla -> fix commit -> parent).
//
// A WebKit CVE ships across many product advisories in one coordinated wave; we dedupe by CVE.
// Output rows mirror the ITW row shape so the existing table/modal/diff machinery works as-is.

import fs from 'node:fs/promises';
import path from 'node:path';
import { resolveFix } from './fetch_jsc_itw_patchmap.js';
import { isExploitClass } from './exploit_class.js';

const OUT = path.join(process.cwd(), 'data', 'jsc_disclosures.json');
const WINDOW_DAYS = Number(process.env.DISCLOSURE_DAYS || 90);
const INDEX = 'https://support.apple.com/en-us/100100';
const PROJECT = 'webkit/webkit';
const MAX_ADVISORIES = 30;     // cap pages scanned; WebKit CVEs repeat across a wave, so this is plenty
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 js-engine-hub';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function httpText(url) {
  try {
    const r = await fetch(url, { headers: { 'User-Agent': UA, 'Accept-Language': 'en-US' } });
    return r.ok ? r.text() : null;
  } catch { return null; }
}

// Parse the security-releases index into { name, url, date } rows (only WebKit-bearing products).
function parseIndex(html) {
  const out = [];
  for (const m of html.matchAll(/<tr>([\s\S]*?)<\/tr>/g)) {
    const row = m[1];
    const a = row.match(/<a href="(https:\/\/support\.apple\.com\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/);
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map(c => c[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim());
    if (!a || cells.length < 3) continue;
    const name = cells[0];
    if (!/safari|macos|ios|ipados|visionos/i.test(name)) continue;   // only releases that carry WebKit
    const date = new Date(cells[cells.length - 1]);
    if (isNaN(date)) continue;
    out.push({ name, url: a[1], date });
  }
  return out;
}

// Parse one advisory's WebKit/JavaScriptCore component entries.
function parseAdvisory(html) {
  let h = html.replace(/<\/(p|div|li|h\d|tr|td|br)>/gi, '\n').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ');
  const lines = h.split('\n').map(s => s.replace(/\s+/g, ' ').trim()).filter(Boolean);
  const out = [];
  let comp = null, impact = null, bug = null;
  for (let i = 0; i < lines.length; i++) {
    if (/^Available for:/i.test(lines[i]) && i > 0) comp = lines[i - 1];
    const im = lines[i].match(/^Impact:\s*(.+)/i); if (im) impact = im[1].trim();
    const bz = lines[i].match(/WebKit Bugzilla:?\s*(\d{5,7})/i); if (bz) bug = bz[1];
    const cm = lines[i].match(/^(CVE-20\d{2}-\d+)\s*:\s*(.*)$/);
    if (cm) {
      const isWk = comp && /\b(webkit|javascriptcore)\b/i.test(comp) && comp.length < 40;
      if (isWk) out.push({ cve: cm[1], impact, bug, reporter: (cm[2] || '').trim() || null });
      bug = null;   // entry consumed
    }
  }
  return out;
}

async function main() {
  const since = Date.now() - WINDOW_DAYS * 86400000;
  const idxHtml = await httpText(INDEX);
  if (!idxHtml) { await write([]); console.error('[jsc-disc] index unreachable'); return; }

  const advisories = parseIndex(idxHtml)
    .filter(a => a.date.getTime() >= since)
    .sort((a, b) => b.date - a.date)
    .slice(0, MAX_ADVISORIES);

  // Collect WebKit-component CVEs across the wave, dedupe by CVE (first/newest occurrence wins).
  const byCve = new Map();
  for (const a of advisories) {
    const html = await httpText(a.url);
    if (!html) continue;
    for (const e of parseAdvisory(html)) {
      if (byCve.has(e.cve)) continue;
      byCve.set(e.cve, {
        cve: e.cve,
        disclosed: a.date.toISOString(),
        vendor: 'Apple', product: 'Safari',
        severity: null,                                  // Apple publishes no severity rating
        reporter: e.reporter,
        shortDescription: e.impact || null, description: null,
        fixed_in: a.name || null,
        _bug: e.bug,
      });
    }
    await sleep(120);
  }

  // Researcher-disclosure scope: externally credited, exploitation-class (memory corruption / engine).
  const rows = [...byCve.values()].filter(r =>
    r.reporter && !/^apple$/i.test(r.reporter) && isExploitClass(r.shortDescription || ''));
  console.log(`[jsc-disc] ${byCve.size} WebKit CVE(s) in ${WINDOW_DAYS}d; ${rows.length} externally-credited exploitation-class; resolving patch maps...`);

  // Patch map per CVE (reuse the JSC resolver). Sequential + spaced: GitHub commit search is rate-limited.
  let high = 0, low = 0;
  for (const r of rows) {
    const bug = r._bug; delete r._bug;
    let fix = null;
    if (bug) { try { fix = await resolveFix(bug); } catch { fix = null; } }
    if (fix) {
      const confident = !fix.ambiguous && Boolean(fix.unpatched_commit);
      const ui = (c) => confident ? c : null;
      r.patched_commit = ui(fix.patched_commit) || null;
      r.unpatched_commit = ui(fix.unpatched_commit) || null;
      r.patched_repo = PROJECT;
      r.patchmap = {
        project: PROJECT,
        bug: Number(bug),
        bug_url: `https://bugs.webkit.org/show_bug.cgi?id=${bug}`,
        confident,
        subject: fix.subject,
        candidate_count: fix.candidate_count,
        patched_date: fix.patched_date || null,
        patched_commit: ui(fix.patched_commit) || null,
        unpatched_commit: ui(fix.unpatched_commit) || null,
      };
      confident ? high++ : low++;
    } else {
      r.patchmap = bug
        ? { project: PROJECT, confident: false, bug: Number(bug), bug_url: `https://bugs.webkit.org/show_bug.cgi?id=${bug}` }
        : { project: PROJECT, confident: false };
      low++;
    }
    await sleep(1500);
  }

  rows.sort((a, b) => (a.cve < b.cve ? 1 : -1));
  await write(rows);
  console.log(`[jsc-disc] wrote ${OUT}: ${rows.length} CVE(s) | patch maps high=${high} low=${low}`);
}

async function write(items) {
  await fs.mkdir(path.dirname(OUT), { recursive: true });
  await fs.writeFile(OUT, JSON.stringify({ generated: new Date().toISOString(), window_days: WINDOW_DAYS, items }, null, 2) + '\n');
}

const __isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (__isMain) main().catch(e => { console.error('[jsc-disc] non-fatal:', e?.message || e); });
