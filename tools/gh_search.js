// tools/gh_search.js
// Shared, rate-limited client for GitHub's commit-search endpoint. The Search API has a much
// stricter limit than the core API (~30 requests/minute, even authenticated), and a single
// `fetch:data` run fires many commit searches across the resolvers. Without pacing, a run hits
// 403 secondary-rate-limit errors that silently drop CVEs from the patch map and can starve the
// `validate:data` gate below its floor (a flaky red build).
//
// This paces calls to stay under the limit and, on a 403/429, retries while honoring the server's
// Retry-After / X-RateLimit-Reset hint, so commit-search resolution is deterministic (just slower).
// Pacing state is per-process; the pipeline runs each resolver as its own process, sequentially.

const GH_API = 'https://api.github.com';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};
const UA = 'js-engine-hub/gh-search';

const MIN_SPACING_MS = Number(process.env.GH_SEARCH_SPACING_MS || 2200);  // ~27/min, safely under 30
const MAX_RETRIES = 4;
const RETRY_CAP_MS = 65000;
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// Serialize search requests and keep their start times >= MIN_SPACING_MS apart, even under the
// concurrency the disclosure fetchers use.
let lastStart = 0;
let chain = Promise.resolve();
function paced(fn) {
  const run = chain.then(async () => {
    const wait = lastStart + MIN_SPACING_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastStart = Date.now();
    return fn();
  });
  chain = run.then(() => {}, () => {});   // a failure must not break the queue
  return run;
}

// Run a GitHub commit search. `query` is the raw `q` value (e.g. `repo:WebKit/WebKit+235551`).
// Returns the parsed response ({ items, total_count, ... }); throws only after exhausting retries.
export async function ghSearchCommits(query, perPage = 30, accept = 'application/vnd.github+json') {
  const url = `${GH_API}/search/commits?q=${query}&per_page=${perPage}`;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const r = await paced(() => fetch(url, { headers: { 'User-Agent': UA, Accept: accept, ...GH_AUTH } }));
    if (r.ok) return r.json();
    if (r.status === 404) return { items: [] };
    if ((r.status === 403 || r.status === 429) && attempt < MAX_RETRIES) {
      const retryAfter = Number(r.headers.get('retry-after'));
      const reset = Number(r.headers.get('x-ratelimit-reset'));
      const waitMs = retryAfter ? retryAfter * 1000
        : reset ? Math.max(0, reset * 1000 - Date.now())
        : 2000 * Math.pow(2, attempt);
      await sleep(Math.min(waitMs + 500, RETRY_CAP_MS));
      continue;
    }
    throw new Error(`${r.status} ${r.statusText}`);
  }
  throw new Error('gh search: retries exhausted');
}
