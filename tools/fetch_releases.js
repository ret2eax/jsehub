// tools/fetch_releases.js
// Chromium Dash only. Collect recent releases per platform and write data/releases.json.

import fs from 'node:fs/promises';

const BASE = 'https://chromiumdash.appspot.com/fetch_releases';
const PLATFORMS = ['linux', 'mac', 'windows', 'android'];
const NUM = 200;

async function fetchJSON(url) {
  const opts = { headers: { 'User-Agent': 'v8-research-hub/1.0' } };
  for (let i = 0; i < 3; i++) {
    const r = await fetch(url, opts);
    if (r.ok) {
      const txt = await r.text();
      try { return JSON.parse(txt); } catch {}
    }
    await new Promise(res => setTimeout(res, 400 * (i + 1)));
  }
  return null;
}

const seen = new Set();
const out = [];

for (const pf of PLATFORMS) {
  const url = `${BASE}?platform=${encodeURIComponent(pf)}&num=${NUM}`;
  const arr = await fetchJSON(url);
  if (!Array.isArray(arr)) {
    console.log(`[releases] ${pf}: no array`);
    continue;
  }
  for (const r of arr) {
    const hashes = r.hashes || {};
    const key = [
      r.channel || '',
      pf,
      r.version || '',
      r.milestone ?? '',
      hashes.chromium || '',
      hashes.v8 || ''
    ].join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      channel: r.channel || '',
      platform: pf,
      version: r.version || '',
      milestone: r.milestone ?? null,
      chromium_main_branch_position: r.chromium_main_branch_position ?? null,
      chromium_commit: hashes.chromium ?? null,
      v8_commit: hashes.v8 ?? null,
      skia_commit: hashes.skia ?? null,
      angle_commit: hashes.angle ?? null,
      updated: r.time ?? null
    });
  }
}

out.sort((a, b) => new Date(b.updated || 0) - new Date(a.updated || 0));

await fs.mkdir('data', { recursive: true });
await fs.writeFile('data/releases.json', JSON.stringify({ releases: out }, null, 2));
console.log('[releases] wrote data/releases.json with', out.length, 'rows');
