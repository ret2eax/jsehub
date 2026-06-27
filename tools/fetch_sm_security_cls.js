// tools/fetch_sm_security_cls.js
// Recent SpiderMonkey CLs — the analog of the V8 CLs feed. SpiderMonkey lives inside
// mozilla-central at js/src, so we walk the pushlog (full=1 → per-changeset file lists,
// no tipsonly since push tips are merge commits) and keep every changeset that touches
// js/src. No keyword filter: js/src is entirely the JS engine, so every CL is already
// engine-relevant (unlike V8's broad repo query, which needs keyword curation).
// Output: data/sm_security_cls.json = { items: [{subject, url, owner, submitted}] }
import fs from 'node:fs/promises';

const OUT = 'data/sm_security_cls.json';
const PUSHLOG = 'https://hg.mozilla.org/mozilla-central/json-pushes?version=2&full=1&count=80';

async function main() {
  try {
    const r = await fetch(PUSHLOG, { headers: { 'User-Agent': 'jsehub-sm-cls/1.0' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();

    const items = [];
    const seen = new Set();
    for (const push of Object.values(j.pushes || {})) {
      const submitted = new Date((push.date || 0) * 1000).toISOString();
      for (const c of (push.changesets || [])) {
        const touchesJsSrc = (c.files || []).some(f => f.startsWith('js/src/'));
        if (!touchesJsSrc) continue;
        const subject = (c.desc || '').split('\n')[0];
        if (/^Merge\b/i.test(subject)) continue;   // drop autoland/central merge commits
        if (seen.has(c.node)) continue;
        seen.add(c.node);
        items.push({
          subject,
          url: `https://hg.mozilla.org/mozilla-central/rev/${c.node}`,
          owner: c.author || '',
          submitted,
        });
      }
    }
    // newest first
    items.sort((a, b) => new Date(b.submitted) - new Date(a.submitted));
    await fs.writeFile(OUT, JSON.stringify({ items: items.slice(0, 80) }, null, 2));
    console.log(`[sm cls] wrote ${OUT} with ${items.length} SpiderMonkey (js/src) CLs (truncated to 80)`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ items: [] }, null, 2));
    console.error(`[sm cls] error: ${e.message}; wrote empty list`);
  }
}
main();
