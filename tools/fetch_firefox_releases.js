// tools/fetch_firefox_releases.js
// Use product-details to identify current trains and craft links to release notes.
// Output: data/firefox_releases.json = { entries: [{title, link, updated}] }
import fs from 'node:fs/promises';

const OUT = 'data/firefox_releases.json';
const PD = 'https://product-details.mozilla.org/1.0/firefox_versions.json';

async function main() {
  try {
    const r = await fetch(PD, { headers:{ 'User-Agent':'browser-research-hub' }});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    // keys: LATEST_FIREFOX_VERSION, LATEST_FIREFOX_DEVEL_VERSION, FIREFOX_NIGHTLY, etc.
    const entries = [];
    const pairs = [
      ['Nightly', j.FIREFOX_NIGHTLY, 'https://www.mozilla.org/firefox/nightly/notes/'],
      ['Beta',    j.LATEST_FIREFOX_DEVEL_VERSION, 'https://www.mozilla.org/firefox/beta/notes/'],
      ['Stable',  j.LATEST_FIREFOX_VERSION,        'https://www.mozilla.org/firefox/releases/']
    ];
    for (const [label, ver, link] of pairs) {
      if (!ver) continue;
      entries.push({ title: `${label} ${ver} release notes`, link, updated: new Date().toISOString() });
    }
    await fs.writeFile(OUT, JSON.stringify({ entries }, null, 2));
    console.log(`[firefox releases] wrote ${OUT} with ${entries.length} entries`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ entries: [] }, null, 2));
    console.error(`[firefox releases] error: ${e.message}; wrote empty list`);
  }
}
main();
