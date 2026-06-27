// tools/fetch_jsc_security_cls.js
// Recent JavaScriptCore CLs — the analog of the V8 CLs feed. JavaScriptCore lives inside
// the WebKit repo at Source/JavaScriptCore, so we scope the commit listing to that path.
// No keyword filter: Source/JavaScriptCore is entirely the JS engine, so every CL is
// already engine-relevant (unlike a whole-WebKit query, which needs keyword curation).
// Output: data/jsc_security_cls.json = { items: [{subject, url, owner, submitted}] }
import fs from 'node:fs/promises';

const OUT = 'data/jsc_security_cls.json';
const GH_COMMITS = 'https://api.github.com/repos/WebKit/WebKit/commits?sha=main&path=Source/JavaScriptCore&per_page=80';
// Authenticate GitHub API calls when a token is present (60/hr unauth -> 1000+/hr).
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

async function main() {
  try {
    const r = await fetch(GH_COMMITS, { headers: { 'User-Agent': 'jsehub-jsc-cls/1.0', ...GH_AUTH } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const rows = await r.json();
    const items = rows
      .filter(x => (x.parents?.length || 1) === 1)   // skip any merge commits
      .map(x => ({
        subject: (x.commit?.message || '').split('\n')[0],
        url: x.html_url,
        owner: x.commit?.author?.name || x.author?.login || '',
        submitted: x.commit?.author?.date || '',
      }));
    await fs.writeFile(OUT, JSON.stringify({ items }, null, 2));
    console.log(`[jsc cls] wrote ${OUT} with ${items.length} JavaScriptCore CLs`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ items: [] }, null, 2));
    console.error(`[jsc cls] error: ${e.message}; wrote empty list`);
  }
}
main();
