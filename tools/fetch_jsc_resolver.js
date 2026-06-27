// tools/fetch_jsc_resolver.js
import fs from 'node:fs/promises';

const OUT = 'data/jsc_resolver.json';

async function readJSON(path, fallback) {
  try { return JSON.parse(await fs.readFile(path, 'utf8')); }
  catch { return fallback; }
}

function extractStpEntries(entries) {
  // titles like "Release Notes for Safari Technology Preview 198"
  const out = [];
  const re = /Technology Preview\s+(\d+)/i;
  for (const e of (entries || [])) {
    const m = (e.title || '').match(re);
    if (m) {
      out.push({
        number: Number(m[1]),
        title: e.title,
        link: e.link,
        updated: e.updated
      });
    }
  }
  // newest first by updated date if present
  out.sort((a,b)=> new Date(b.updated||0) - new Date(a.updated||0));
  return out;
}

function buildCommitIndex(commits) {
  const idx = {};
  for (const c of (commits || [])) {
    const sha = (c.commit || '').toLowerCase();
    if (!/^[0-9a-f]{7,40}$/.test(sha)) continue;
    const meta = { full: sha, subject: c.subject, author: c.author, time: c.time, url: c.url };
    // generate prefixes from 7..12 (UI uses 12, but accept shorter)
    for (let n = 7; n <= 12 && n <= sha.length; n++) {
      const p = sha.slice(0, n);
      if (!idx[p]) idx[p] = meta;
    }
  }
  return idx;
}

async function fetchWebKitFeed() {
  const url = 'https://webkit.org/feed/';
  const r = await fetch(url, { headers: { 'User-Agent': 'browser-research-hub' }});
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const xml = await r.text();
  const items = [];
  const reItem = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = reItem.exec(xml))) {
    const block = m[1];
    const title = (block.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/) || block.match(/<title>(.*?)<\/title>/))?.[1] || '';
    const link  = (block.match(/<link>(.*?)<\/link>/) || block.match(/<guid.*?>(.*?)<\/guid>/))?.[1] || '';
    const date  = (block.match(/<pubDate>(.*?)<\/pubDate>/))?.[1] || '';
    if (/Safari Technology Preview/i.test(title)) items.push({ title, link, updated: date });
  }
  return items;
}

async function main() {
  try {
    const localSTP = await readJSON('data/safari_releases.json', { entries: [] });
    let stpEntries = extractStpEntries(localSTP.entries);
    if (stpEntries.length === 0) {
      // fallback: pull fresh
      const web = await fetchWebKitFeed();
      stpEntries = extractStpEntries(web);
    }

    const jscCommits = await readJSON('data/jsc_commits.json', { commits: [] });
    const commitIndex = buildCommitIndex(jscCommits.commits);

    const out = { stp: stpEntries.slice(0, 60), commitIndex };
    await fs.writeFile(OUT, JSON.stringify(out, null, 2));
    console.log(`[jsc resolver] wrote ${OUT}: stp=${out.stp.length}, prefixes=${Object.keys(commitIndex).length}`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ stp: [], commitIndex: {} }, null, 2));
    console.error(`[jsc resolver] error: ${e.message}; wrote empty resolver`);
  }
}

main();
