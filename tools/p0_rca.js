// tools/p0_rca.js
// Project Zero "0days-in-the-wild" lookup. For an in-the-wild CVE, Google Project Zero publishes a
// structured, per-CVE root-cause analysis at a predictable path that names the upstream bug id and
// the exact fix commit. This supplies the CVE -> bug link that Apple's pre-2023 advisories, NVD,
// OSV and the WebKit Bugzilla all omit (verified empirically). It is authoritative and ITW-scoped,
// so it is used only as a last-resort fallback for otherwise-unresolved in-the-wild CVEs; the
// resulting bug is still run through the engine's normal, verifiable bug -> commit -> parent
// resolution, so a mis-read fails safe (the CVE simply stays unresolved).

const RAW = 'https://raw.githubusercontent.com/googleprojectzero/0days-in-the-wild/main/0day-RCAs';
const UA = 'js-engine-hub/p0-rca';

// Engine-specific bug-tracker URL patterns as they appear inside a P0 RCA.
const BUG_PATTERNS = {
  jsc:    /(?:show_bug\.cgi\?id=|webkit\.org\/b\/)(\d+)/g,
  chrome: /(?:crbug\.com\/|issues\.chromium\.org\/issues\/|bugs\.chromium\.org\/p\/chromium\/issues\/detail\?id=)(\d+)/g,
  sm:     /bugzilla\.mozilla\.org\/show_bug\.cgi\?id=(\d+)/g,
};

async function fetchRca(cve) {
  const m = String(cve || '').match(/CVE-(\d{4})-\d+/);
  if (!m) return null;
  const year = m[1];
  for (const ext of ['.md', '.html']) {
    try {
      const r = await fetch(`${RAW}/${year}/${cve}${ext}`, { headers: { 'User-Agent': UA } });
      if (r.ok) return r.text();
    } catch { /* try next */ }
  }
  return null;
}

// Return the upstream bug id P0 attributes to this CVE for the given engine, or null. Requires an
// unambiguous single bug so an RCA that cites several bugs (variants) fails safe rather than guesses.
export async function p0BugForCve(cve, engine) {
  const re = BUG_PATTERNS[engine];
  if (!re) return null;
  const text = await fetchRca(cve);
  if (!text) return null;
  const bugs = [...new Set([...text.matchAll(re)].map(x => x[1]))];
  return bugs.length === 1 ? bugs[0] : null;
}
