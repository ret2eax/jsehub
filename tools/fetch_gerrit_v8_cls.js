// tools/fetch_gerrit_v8_cls.js
import fs from 'node:fs/promises';

const GERRIT = 'https://chromium-review.googlesource.com';

// compute cutoff = today - 30 days
const ONE_MONTH_AGO = new Date();
ONE_MONTH_AGO.setMonth(ONE_MONTH_AGO.getMonth() - 1);
const cutoff = ONE_MONTH_AGO.toISOString().slice(0, 10); // YYYY-MM-DD

const QUERIES = [
  `project:v8/v8 status:merged -is:wip -is:private after:${cutoff}`,
  `project:chromium/src status:merged file:^v8/.* -is:wip -is:private after:${cutoff}`
];

const KEYWORDS = /\b(asan|ubsan|msan|tsan|sandbox|gc|oob|uaf|bounds|heap|type|wasm|turbofan|ignition|isolate|pointer|spectre|jit)\b/i;

async function get(url) {
  for (let i=0;i<3;i++) {
    const r = await fetch(url, { headers: { 'User-Agent': 'v8-research-hub/1.0' }});
    if (r.ok) return r.text();
    await new Promise(res=>setTimeout(res, 400*(i+1)));
  }
  throw new Error('Failed: '+url);
}

function parseJSONWithXssi(text) {
  return JSON.parse(text.replace(/^\)\]\}'\s*\n?/, ''));
}

const items = [];

for (const q of QUERIES) {
  try {
    const txt = await get(`${GERRIT}/changes/?q=${encodeURIComponent(q)}&n=200&o=DETAILED_LABELS&o=CURRENT_REVISION&o=CURRENT_COMMIT`);
    const arr = parseJSONWithXssi(txt);
    for (const r of arr) {
      if (!r?.subject) continue;
      if (!KEYWORDS.test(r.subject)) continue; // only security-ish
      items.push({
        change_id: r.id,
        subject: r.subject,
        owner: r.owner?.name,
        submitted: r.submitted || r.updated || r.created,
        project: r.project,
        _number: r._number,
        url: `${GERRIT}/c/${r.project}/+/${r._number}`
      });
    }
  } catch (err) {
    console.error('[gerrit] error:', err.message || err);
  }
}

// sort newest first
items.sort((a,b)=> new Date(b.submitted||0) - new Date(a.submitted||0));

await fs.mkdir('data', { recursive: true });
await fs.writeFile('data/v8_security_cls.json', JSON.stringify({ items }, null, 2));
console.log(`[gerrit] wrote data/v8_security_cls.json with ${items.length} items (since ${cutoff})`);
