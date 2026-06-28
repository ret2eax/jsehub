#!/usr/bin/env node
// tools/check_data.js
// Post-fetch sanity gate. Run after fetch:data and before `next build`.
// Fails (exit 1) if any core dataset is empty or implausibly small, so a silent upstream
// breakage (API/format change, lost auth, etc.) aborts the deploy instead of shipping empty
// tables. A failed run also surfaces via GitHub's default workflow-failure notification.
//
// Thresholds are conservative lower bounds (well under normal values) so ordinary fluctuation
// never false-alarms, but a collapse toward zero trips the gate.

import fs from 'node:fs/promises';
import path from 'node:path';

const DATA = path.join(process.cwd(), 'data');
const read = async (f, fb) => { try { return JSON.parse(await fs.readFile(path.join(DATA, f), 'utf8')); } catch { return fb; } };
const num = (v) => Array.isArray(v) ? v.length : 0;

async function main() {
  const releases = await read('releases.json', { releases: [] });
  const cves     = await read('cves.json', { itw_chrome_related: [] });
  const jscCves  = await read('jsc_cves.json', { itw_related: [] });
  const smCves   = await read('sm_cves.json', { itw_related: [] });

  const confident = (rows) => rows.filter(x => x?.patchmap?.confident).length;
  const v8High  = confident(cves.itw_chrome_related || []);
  const jscHigh = confident(jscCves.itw_related || []);
  const smHigh  = confident(smCves.itw_related || []);
  const jscWebkit = (jscCves.itw_related || []).filter(x => x.webkit === true).length;

  // [label, actual, min]
  const checks = [
    ['Chrome releases',          num(releases.releases),           100],
    ['Chrome ITW CVEs',          num(cves.itw_chrome_related),      10],
    ['Safari/JSC ITW CVEs',      num(jscCves.itw_related),          10],
    ['Firefox/SM ITW CVEs',      num(smCves.itw_related),            5],
    ['V8 patch maps (high)',     v8High,                            30],
    ['JSC patch maps (high)',    jscHigh,                            8],
    ['SM patch maps (high)',     smHigh,                             5],
    ['JSC WebKit-tagged',        jscWebkit,                         10],
  ];

  let failed = 0;
  console.log('[check] data sanity gate:');
  for (const [label, actual, min] of checks) {
    const ok = actual >= min;
    if (!ok) failed++;
    console.log(`  ${ok ? 'OK ' : 'FAIL'}  ${label}: ${actual} (min ${min})`);
  }

  // Disclosures are a supplementary feed (researcher-reported, last 90d). A source format change
  // should not abort the whole deploy, so these are WARN-only: surfaced in the log, never fatal.
  const chromeDisc = await read('chrome_disclosures.json', { items: [] });
  const jscDisc    = await read('jsc_disclosures.json', { items: [] });
  const smDisc     = await read('sm_disclosures.json', { items: [] });
  const softChecks = [
    ['Chrome disclosures',     num(chromeDisc.items), 1],
    ['Safari/JSC disclosures', num(jscDisc.items),    1],
    ['Firefox/SM disclosures', num(smDisc.items),     1],
  ];
  console.log('[check] disclosures (warn-only):');
  for (const [label, actual, min] of softChecks) {
    console.log(`  ${actual >= min ? 'OK  ' : 'WARN'}  ${label}: ${actual} (expect >= ${min})`);
  }

  if (failed) {
    console.error(`\n[check] ${failed} check(s) failed - aborting before deploy so empty/broken data does not ship.`);
    process.exit(1);
  }
  console.log('\n[check] all good.');
}

main().catch(e => { console.error('[check] fatal:', e?.message || e); process.exit(1); });
