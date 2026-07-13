// Build a CVE -> changed-file-paths index from the resolved per-CVE diffs
// (public/api/diff/<cve>.json). Node-only (uses fs); consumed at build time by
// the feed generator and the dashboard's getStaticProps to feed authoritative
// file paths into engine-relevance classification. Missing dir -> empty index.
import fs from 'node:fs';
import path from 'node:path';

export function readDiffIndex(diffDir) {
  const idx = new Map();
  let entries = [];
  try { entries = fs.readdirSync(diffDir); } catch { return idx; }
  for (const f of entries) {
    if (!f.endsWith('.json')) continue;
    try {
      const d = JSON.parse(fs.readFileSync(path.join(diffDir, f), 'utf8'));
      if (d.cve) idx.set(d.cve, (d.files || []).map(x => x.file).filter(Boolean));
    } catch { /* skip unreadable diff */ }
  }
  return idx;
}
