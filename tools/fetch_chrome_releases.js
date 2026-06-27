import fs from 'node:fs/promises';

const FEED = 'https://chromereleases.googleblog.com/atom.xml';

async function getText(url) {
  for (let i=0;i<3;i++) {
    const r = await fetch(url, { headers: { 'User-Agent': 'v8-research-hub/1.0' }});
    if (r.ok) return r.text();
    await new Promise(res=>setTimeout(res, 400*(i+1)));
  }
  throw new Error('Failed: '+url);
}

// very tiny Atom parser: we only need title/link/updated
const xml = await getText(FEED);
const entries = [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].map(m=>{
  const e = m[1];
  const title = (e.match(/<title.*?>([\s\S]*?)<\/title>/) || [,''])[1].trim();
  const updated = (e.match(/<updated>([^<]+)<\/updated>/) || [,''])[1].trim();
  const link = (e.match(/<link[^>]*href="([^"]+)"/) || [,''])[1].trim();
  return { title, updated, link };
});

// mark “in the wild” by phrase match
const itw = entries
  .filter(e => /Stable Channel Update/i.test(e.title))
  .map(e => ({ ...e, itw: /in the wild/i.test(e.title) || /in the wild/i.test(e.summary || '') }));

await fs.mkdir('data', { recursive: true });
await fs.writeFile('data/chrome_releases_atom.json', JSON.stringify({ entries: itw }, null, 2));
console.log('[releases-blog] wrote data/chrome_releases_atom.json with', itw.length, 'entries');
