// tools/fetch_sm_builds.js
// Node ESM. Requires Node 18+ (global fetch).
import fs from 'node:fs/promises';

const UA = 'fetch-sm-builds/1.0 (+https://jsehub.local)';
const INDEX_API = 'https://firefox-ci-tc.services.mozilla.com/api/index/v1/task/';
const QUEUE_API = 'https://firefox-ci-tc.services.mozilla.com/api/queue/v1/task/';

// Try fuzzing-asan-opt first (preferred for security testing), then fall back to asan-opt.
const CANDIDATES = [
  // linux
  {
    platKey: 'linux',
    arch: 'x64',
    indexes: [
      'gecko.v2.mozilla-central.latest.firefox.linux64-fuzzing-asan-opt',
      'gecko.v2.mozilla-central.latest.firefox.linux64-asan-opt',
    ],
  },
  // windows
  {
    platKey: 'win64',
    arch: 'x64',
    indexes: [
      'gecko.v2.mozilla-central.latest.firefox.win64-fuzzing-asan-opt',
      'gecko.v2.mozilla-central.latest.firefox.win64-asan-opt',
    ],
  },
  // mac x64
  {
    platKey: 'mac',
    arch: 'x64',
    indexes: [
      'gecko.v2.mozilla-central.latest.firefox.macosx64-fuzzing-asan-opt',
      'gecko.v2.mozilla-central.latest.firefox.macosx64-asan-opt',
    ],
  },
  // mac arm64
  {
    platKey: 'mac',
    arch: 'arm64',
    indexes: [
      'gecko.v2.mozilla-central.latest.firefox.macosx64-aarch64-fuzzing-asan-opt',
      'gecko.v2.mozilla-central.latest.firefox.macosx64-aarch64-asan-opt',
    ],
  },
];

async function getJson(url) {
  const r = await fetch(url, { headers: { 'User-Agent': UA } });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    const err = new Error(`${r.status} ${r.statusText} for ${url}${text ? ` — ${text.slice(0,200)}` : ''}`);
    err.status = r.status;
    throw err;
  }
  return r.json();
}

async function resolveTaskId(indexKey) {
  // index → { taskId, namespace, rank }
  const url = INDEX_API + encodeURIComponent(indexKey);
  const data = await getJson(url);
  return data.taskId;
}

async function getArtifacts(taskId) {
  // queue/v1/task/<taskId>/artifacts → list of { name, contentType, ... }
  const url = `${QUEUE_API}${encodeURIComponent(taskId)}/artifacts`;
  const data = await getJson(url);
  return data.artifacts || [];
}

async function getTask(taskId) {
  // queue/v1/task/<taskId> returns the task definition directly (no `.task` wrapper).
  const url = `${QUEUE_API}${encodeURIComponent(taskId)}`;
  return getJson(url);
}

function pickArtifact(artifacts) {
  // Prefer the JS shell (the `js` binary — SpiderMonkey's analog of V8's d8, what the
  // table advertises and what fuzzers/PoCs actually use). Fall back to the full browser
  // archive only if the shell isn't published for a platform.
  const wanted = [
    'public/build/target.jsshell.zip',
    'public/build/target.tar.xz',
    'public/build/target.zip',
    'public/build/target.dmg',
    'public/build/target.tar.bz2',
  ];
  for (const w of wanted) {
    const hit = artifacts.find(a => a.name === w);
    if (hit) return hit;
  }
  // Fallback: any public/build/* archive-looking
  return artifacts.find(a => a.name.startsWith('public/build/')) || null;
}

function artifactUrl(taskId, artifactName) {
  return `${QUEUE_API}${encodeURIComponent(taskId)}/artifacts/${encodeURIComponent(artifactName)}`;
}

async function fetchMd5(taskId, filename) {
  // Taskcluster's artifact listing carries no content hash, but gecko builds publish a
  // `target.checksums` artifact: lines of "<hash> <type> <size> <filename>". md5 is listed
  // for the build archive (matches the md5 column used on the Chrome/V8 side).
  try {
    const r = await fetch(artifactUrl(taskId, 'public/build/target.checksums'), { headers: { 'User-Agent': UA } });
    if (!r.ok) return null;
    const txt = await r.text();
    for (const line of txt.trim().split('\n')) {
      const [hash, type, , name] = line.trim().split(/\s+/);
      if (type === 'md5' && name === filename) return hash;
    }
  } catch { /* checksums are best-effort */ }
  return null;
}

async function tryOne({ platKey, arch, indexes }) {
  for (const indexKey of indexes) {
    try {
      const taskId = await resolveTaskId(indexKey);
      const [artifacts, task] = await Promise.all([getArtifacts(taskId), getTask(taskId)]);
      const art = pickArtifact(artifacts);
      if (!art) {
        console.warn(`[sm] ${indexKey} found task ${taskId} but no suitable artifact`);
        continue;
      }
      const url = artifactUrl(taskId, art.name);
      const filename = art.name.split('/').pop();
      const md5 = await fetchMd5(taskId, filename);
      const created = task.created || task.createdTime || null;
      // mozilla-central revision the build was produced from (matches gecko-dev git commit).
      const env = task.payload?.env || {};
      const commit = env.GECKO_HEAD_REV || env.MOZ_SOURCE_CHANGESET || null;

      console.log(`[sm] ${indexKey} → ${filename}`);
      return {
        platform: platKey,
        arch,
        indexKey,
        taskId,
        filename,
        download: url,
        md5,
        created,
        commit,
      };
    } catch (e) {
      if (e.status === 404) {
        console.log(`[sm] ${indexKey} not found (404)`);
      } else {
        console.log(`[sm] ${indexKey} failed: ${e.message}`);
      }
      // try next candidate
    }
  }
  console.log(`[sm] No namespace found for ${platKey} ${arch} + asan, skipping`);
  return null;
}

async function main() {
  const out = { latest: {} };
  const rows = await Promise.all(CANDIDATES.map(tryOne));
  for (const row of rows) {
    if (!row) continue;
    if (row.platform === 'mac') {
      out.latest.mac ||= {};
      out.latest.mac[row.arch] = row;
    } else {
      out.latest[row.platform] = row;
    }
  }

  await fs.mkdir('data', { recursive: true });
  await fs.writeFile('data/sm_builds.json', JSON.stringify(out, null, 2));
  console.log('[sm] wrote data/sm_builds.json');
}

main().catch(err => {
  console.error(err.stack || String(err));
  process.exit(1);
});
