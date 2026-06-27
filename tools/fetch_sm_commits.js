// tools/fetch_sm_commits.js
// Recent SpiderMonkey commits (scoped to js/src) from mozilla-central, for the resolver's
// commit index. full=1 gives per-changeset file lists so we can scope to the JS engine;
// no tipsonly (push tips are merge commits).
// Output: data/sm_commits.json = { ref: 'central', commits: [{commit, subject, author, time, url}] }
import fs from 'node:fs/promises';

const OUT = 'data/sm_commits.json';
const PUSHLOG = 'https://hg.mozilla.org/mozilla-central/json-pushes?version=2&full=1&count=80';

async function main() {
  try {
    const r = await fetch(PUSHLOG, { headers: { 'User-Agent': 'jsehub-sm-commits/1.0' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();

    const commits = [];
    const seen = new Set();
    for (const push of Object.values(j.pushes || {})) {
      const time = new Date((push.date || 0) * 1000).toISOString();
      for (const c of (push.changesets || [])) {
        if (!(c.files || []).some(f => f.startsWith('js/src/'))) continue;  // SpiderMonkey only
        const subject = (c.desc || '').split('\n')[0];
        if (/^Merge\b/i.test(subject)) continue;
        if (seen.has(c.node)) continue;
        seen.add(c.node);
        commits.push({
          commit: c.node,
          subject,
          author: c.author || '',
          time,
          url: `https://hg.mozilla.org/mozilla-central/rev/${c.node}`,
        });
      }
    }
    commits.sort((a, b) => new Date(b.time) - new Date(a.time));
    await fs.writeFile(OUT, JSON.stringify({ ref: 'central', commits: commits.slice(0, 80) }, null, 2));
    console.log(`[sm commits] wrote ${OUT} with ${commits.length} js/src commits (truncated to 80)`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ ref: 'central', commits: [] }, null, 2));
    console.error(`[sm commits] error: ${e.message}; wrote empty list`);
  }
}
main();
