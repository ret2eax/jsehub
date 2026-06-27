// tools/fetch_safari_releases.js
// Pull WebKit blog RSS and surface Safari Technology Preview posts as "releases".
// Output: data/safari_releases.json = { entries: [{title, link, updated}] }
import fs from 'node:fs/promises';

const OUT = 'data/safari_releases.json';
const WEBKIT_RSS = 'https://webkit.org/feed/';

function parseRss(xml) {
  // very light RSS parse (no external deps)
  const items = [];
  const reItem = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = reItem.exec(xml))) {
    const block = m[1];
    const title = (block.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/) || block.match(/<title>(.*?)<\/title>/))?.[1] || '';
    const link  = (block.match(/<link>(.*?)<\/link>/) || block.match(/<guid.*?>(.*?)<\/guid>/))?.[1] || '';
    const date  = (block.match(/<pubDate>(.*?)<\/pubDate>/))?.[1] || '';
    items.push({ title, link, updated: date });
  }
  return items;
}

async function main() {
  try {
    const r = await fetch(WEBKIT_RSS, { headers: { 'User-Agent':'browser-research-hub' }});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const xml = await r.text();
    const all = parseRss(xml);
    const stp = all.filter(x => /Safari Technology Preview/i.test(x.title || ''));
    await fs.writeFile(OUT, JSON.stringify({ entries: stp.slice(0, 12) }, null, 2));
    console.log(`[safari releases] wrote ${OUT} with ${stp.length} entries`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ entries: [] }, null, 2));
    console.error(`[safari releases] error: ${e.message}; wrote empty list`);
  }
}
main();
