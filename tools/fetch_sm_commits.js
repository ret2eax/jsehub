// tools/fetch_sm_commits.js
// Get latest commits from mozilla-central (pushlog JSON), flatten to commits.
// Output: data/sm_commits.json = { ref: 'central', commits: [...] }
import fs from 'node:fs/promises';

const OUT = 'data/sm_commits.json';
// full=1 for changesets, tipsonly=1 to keep it compact; count=50 for recent pushes
const PUSHLOG = 'https://hg.mozilla.org/mozilla-central/json-pushes?version=2&full=1&tipsonly=1&count=50';

async function main() {
  try {
    const r = await fetch(PUSHLOG, { headers:{ 'User-Agent':'browser-research-hub' }});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    const commits = [];
    for (const push of Object.values(j.pushes || {})) {
      for (const c of (push.changesets || [])) {
        commits.push({
          commit: c.node,
          subject: (c.desc || '').split('\n')[0],
          author: c.author || '',
          time: new Date((push.date || 0) * 1000).toISOString(),
          url: `https://hg.mozilla.org/mozilla-central/rev/${c.node}`
        });
      }
    }
    // sort newest first
    commits.sort((a,b)=> new Date(b.time) - new Date(a.time));
    await fs.writeFile(OUT, JSON.stringify({ ref:'central', commits: commits.slice(0,80) }, null, 2));
    console.log(`[sm commits] wrote ${OUT} with ${commits.length} commits (truncated)`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ ref:'central', commits: [] }, null, 2));
    console.error(`[sm commits] error: ${e.message}; wrote empty list`);
  }
}
main();
