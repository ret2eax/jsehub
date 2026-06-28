#!/usr/bin/env node
// tools/gen_feeds.js
// Emit machine-readable feeds from the built data so the dashboard is consumable:
//   public/api/itw.json      - every ITW CVE across engines (+ patch-map summary)
//   public/api/patchmap.json - just the resolved patched/vulnerable commit pairs
//   public/feed.xml          - Atom feed of the most recent ITW CVEs
// Run after fetch:data, before `next build` (public/ is copied into the export).

import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = process.cwd();
const DATA = path.join(ROOT, 'data');
const OUT_API = path.join(ROOT, 'public', 'api');
const SITE = 'https://jsehub.dev';

const ENGINES = [
  { key:'chrome', label:'Chrome / V8',            project:'v8/v8',                 file:'cves.json',     cvesKey:'itw_chrome_related' },
  { key:'jsc',    label:'Safari / JSC',           project:'webkit/webkit',         file:'jsc_cves.json', cvesKey:'itw_related' },
  { key:'sm',     label:'Firefox / SpiderMonkey', project:'mozilla-firefox/firefox', file:'sm_cves.json', cvesKey:'itw_related' },
];

async function readJSON(file, fallback) {
  try { return JSON.parse(await fs.readFile(path.join(DATA, file), 'utf8')); }
  catch { return fallback; }
}
const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function classify(s) {
  const t = String(s || '').toLowerCase();
  const rules = [
    [/use[-\s]?after[-\s]?free/, 'Use-after-free'],
    [/type\s+confusion/, 'Type confusion'],
    [/out[-\s]?of[-\s]?bounds.*write|oob\s*write/, 'Out-of-bounds write'],
    [/out[-\s]?of[-\s]?bounds.*read|oob\s*read/, 'Out-of-bounds read'],
    [/out[-\s]?of[-\s]?bounds|oob/, 'Out-of-bounds'],
    [/integer\s+(over|under)flow/, 'Integer overflow'],
    [/race\s+condition|toctou/, 'Race condition'],
    [/memory\s+corruption/, 'Memory corruption'],
    [/sandbox\s+escape/, 'Sandbox escape'],
    [/code\s+execution|rce/, 'Code execution'],
  ];
  for (const [re, cls] of rules) if (re.test(t)) return cls;
  return 'Unspecified';
}

async function main() {
  const all = [];
  const cveYear = (cve) => { const m = String(cve || '').match(/CVE-(\d{4})/); return m ? Number(m[1]) : 0; };
  for (const e of ENGINES) {
    const data = await readJSON(e.file, {});
    // JSC: keep only WebKit-family entries, drop non-engine components and pre-2022 (unresolvable) CVEs.
    const rows = (data[e.cvesKey] || [])
      .filter(x => e.key !== 'jsc' || x.patchmap?.confident || (x.webkit === true && cveYear(x.cve) >= 2022));
    for (const x of rows) {
      const pm = x.patchmap || {};
      all.push({
        cve: x.cve,
        engine: e.key,
        engine_label: e.label,
        vendor: x.vendor || null,
        product: x.product || null,
        date_added: x.dateAdded || null,
        class: classify(x.shortDescription || x.description),
        description: x.shortDescription || x.description || null,
        project: pm.project || e.project,
        confidence: pm.confident ? 'high' : (x.patchmap ? 'low' : null),
        patched_commit: x.patched_commit || pm.patched_commit || null,
        unpatched_commit: x.unpatched_commit || pm.unpatched_commit || null,
        patched_date: pm.patched_date || null,
        url: `${SITE}/#cve=${x.cve}`,
      });
    }
  }
  all.sort((a, b) => new Date(b.date_added || 0) - new Date(a.date_added || 0));

  const generated = new Date().toISOString();
  await fs.mkdir(OUT_API, { recursive: true });

  // 1) full ITW feed
  await fs.writeFile(path.join(OUT_API, 'itw.json'),
    JSON.stringify({ generated, site: SITE, count: all.length, items: all }, null, 2));

  // 2) resolved patch maps only
  const maps = all.filter(x => x.patched_commit && x.unpatched_commit).map(x => ({
    cve: x.cve, engine: x.engine, project: x.project, confidence: x.confidence,
    patched_commit: x.patched_commit, unpatched_commit: x.unpatched_commit, patched_date: x.patched_date,
  }));
  await fs.writeFile(path.join(OUT_API, 'patchmap.json'),
    JSON.stringify({ generated, site: SITE, count: maps.length, items: maps }, null, 2));

  // 2b) recent disclosures feed (researcher-reported, not in-the-wild; same resolution + tiers as ITW)
  const DISC = [
    { key:'chrome', label:'Chrome / V8',            project:'v8/v8',                   file:'chrome_disclosures.json' },
    { key:'jsc',    label:'Safari / JSC',           project:'webkit/webkit',           file:'jsc_disclosures.json' },
    { key:'sm',     label:'Firefox / SpiderMonkey', project:'mozilla-firefox/firefox', file:'sm_disclosures.json' },
  ];
  const disc = [];
  let discWindow = 90;
  for (const e of DISC) {
    const data = await readJSON(e.file, { items: [] });
    if (data.window_days) discWindow = data.window_days;
    for (const x of (data.items || [])) {
      const pm = x.patchmap || {};
      disc.push({
        cve: x.cve,
        engine: e.key,
        engine_label: e.label,
        vendor: x.vendor || null,
        severity: x.severity || null,
        reporter: x.reporter || null,
        disclosed: x.disclosed || null,
        class: classify(x.shortDescription || x.description),
        description: x.shortDescription || x.description || null,
        fix_subject: pm.subject || null,
        project: pm.project || e.project,
        confidence: pm.confident ? 'high' : (x.patchmap ? 'low' : null),
        patched_commit: x.patched_commit || pm.patched_commit || null,
        unpatched_commit: x.unpatched_commit || pm.unpatched_commit || null,
        patched_date: pm.patched_date || null,
        bug: pm.bug || null,
        url: `${SITE}/#cve=${x.cve}`,
      });
    }
  }
  disc.sort((a, b) => new Date(b.disclosed || 0) - new Date(a.disclosed || 0));
  await fs.writeFile(path.join(OUT_API, 'disclosures.json'),
    JSON.stringify({ generated, site: SITE, window_days: discWindow, count: disc.length, items: disc }, null, 2));

  // 3) Atom feed (recent)
  const recent = all.slice(0, 40);
  const entries = recent.map(x => `  <entry>
    <title>${esc(x.cve)} · ${esc(x.engine_label)} · ${esc(x.class)}</title>
    <id>${esc(x.url)}</id>
    <link href="${esc(x.url)}"/>
    <updated>${esc(x.date_added ? new Date(x.date_added).toISOString() : generated)}</updated>
    <summary>${esc(x.description || x.cve)}${x.confidence ? ` [patch map: ${x.confidence}]` : ''}</summary>
  </entry>`).join('\n');
  const atom = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>JS Engine Hub · In-the-wild CVEs</title>
  <id>${SITE}/feed.xml</id>
  <link href="${SITE}/feed.xml" rel="self"/>
  <link href="${SITE}/"/>
  <updated>${generated}</updated>
${entries}
</feed>
`;
  await fs.writeFile(path.join(ROOT, 'public', 'feed.xml'), atom);

  console.log(`[feeds] wrote public/api/itw.json (${all.length}), public/api/patchmap.json (${maps.length}), public/api/disclosures.json (${disc.length}), public/feed.xml (${recent.length} entries)`);
}

main().catch(e => { console.error('[feeds] error:', e?.message || e); process.exit(1); });
