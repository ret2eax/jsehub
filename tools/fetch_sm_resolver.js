// tools/fetch_sm_resolver.js
import fs from 'node:fs/promises';

const OUT = 'data/sm_resolver.json';
const PD  = 'https://product-details.mozilla.org/1.0/firefox_versions.json';

async function readJSON(path, fallback) {
  try { return JSON.parse(await fs.readFile(path, 'utf8')); }
  catch { return fallback; }
}

function buildCommitIndex(commits) {
  const idx = {};
  for (const c of (commits || [])) {
    const rev = (c.commit || '').toLowerCase(); // hg node
    if (!/^[0-9a-f]{12,40}$/.test(rev)) continue;
    const meta = { full: rev, subject: c.subject, author: c.author, time: c.time, url: c.url };
    for (let n = 12; n <= 16 && n <= rev.length; n++) {
      const p = rev.slice(0, n);
      if (!idx[p]) idx[p] = meta;
    }
  }
  return idx;
}

async function fetchPD() {
  const r = await fetch(PD, { headers: { 'User-Agent':'browser-research-hub' }});
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

async function main() {
  try {
    let versions = {};
    try {
      const j = await fetchPD();
      versions = {
        nightly: j.FIREFOX_NIGHTLY || '',
        beta:    j.LATEST_FIREFOX_DEVEL_VERSION || '',
        stable:  j.LATEST_FIREFOX_VERSION || ''
      };
    } catch (e) {
      console.warn(`[sm resolver] product-details fetch failed: ${e.message}; leaving versions empty`);
    }

    const smCommits = await readJSON('data/sm_commits.json', { commits: [] });
    const commitIndex = buildCommitIndex(smCommits.commits);

    const out = { versions, commitIndex };
    await fs.writeFile(OUT, JSON.stringify(out, null, 2));
    console.log(`[sm resolver] wrote ${OUT}: versions=${JSON.stringify(versions)}, prefixes=${Object.keys(commitIndex).length}`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ versions: {}, commitIndex: {} }, null, 2));
    console.error(`[sm resolver] error: ${e.message}; wrote empty resolver`);
  }
}

main();
