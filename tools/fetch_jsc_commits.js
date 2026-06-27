// tools/fetch_jsc_commits.js
// Fetch recent WebKit (JSC) commits from GitHub mirror (unauthenticated; low rate).
// Output: data/jsc_commits.json = { ref: 'main', commits: [{commit, subject, author, time, url}] }
import fs from 'node:fs/promises';

const OUT = 'data/jsc_commits.json';
const GH_COMMITS = 'https://api.github.com/repos/WebKit/WebKit/commits?sha=main&per_page=50';
// Authenticate GitHub API calls when a token is present (60/hr unauth -> 1000+/hr).
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

async function main() {
  try {
    const r = await fetch(GH_COMMITS, { headers: { 'User-Agent': 'browser-research-hub', ...GH_AUTH }});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const rows = await r.json();
    const commits = rows.map(x => ({
      commit: x.sha,
      subject: (x.commit && x.commit.message ? x.commit.message.split('\n')[0] : ''),
      author: (x.commit && x.commit.author ? x.commit.author.name : (x.author?.login || '')),
      time:   (x.commit && x.commit.author ? x.commit.author.date : ''),
      url: x.html_url
    }));
    await fs.writeFile(OUT, JSON.stringify({ ref:'main', commits }, null, 2));
    console.log(`[jsc commits] wrote ${OUT} with ${commits.length} commits`);
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ ref:'main', commits: [] }, null, 2));
    console.error(`[jsc commits] error: ${e.message}; wrote empty list`);
  }
}
main();
