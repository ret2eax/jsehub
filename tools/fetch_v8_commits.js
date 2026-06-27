// Fetch latest V8 commits from Gitiles into data/v8_commits.json
import fs from 'node:fs/promises';

const REF = process.env.V8_REF || 'refs/heads/main';
const URL = `https://chromium.googlesource.com/v8/v8/+log/${encodeURIComponent(REF)}?format=JSON&n=50`;

const ua = { headers: { 'User-Agent': 'v8-research-hub/1.0 (+https://example.com)' } };

async function getJSON(url) {
  for (let i = 0; i < 3; i++) {
    const r = await fetch(url, ua);
    if (!r.ok) { await new Promise(res=>setTimeout(res, 500*(i+1))); continue; }
    const text = await r.text();
    // Strip Gitiles XSSI guard — it’s exactly ")]}'" followed by optional newline(s)
    const clean = text.replace(/^\)\]\}'\s*\n?/, '');
    return JSON.parse(clean);
  }
  throw new Error(`Failed to fetch ${url}`);
}

const j = await getJSON(URL);
const commits = (j.log || []).map(c => ({
  commit: c.commit,
  author: c.author?.name,
  email: c.author?.email,
  subject: c.subject,
  time: c.author?.time,
}));

await fs.mkdir('data', { recursive: true });
await fs.writeFile('data/v8_commits.json', JSON.stringify({ ref: REF, commits }, null, 2));
console.log('[v8] wrote data/v8_commits.json with', commits.length, 'commits');
