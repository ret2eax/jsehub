#!/usr/bin/env node
// tools/fetch_v8_itw_patchmap.js
// Node 18+ required (global fetch). Run: `node tools/fetch_v8_itw_patchmap.js`

import fs from 'node:fs/promises';
import path from 'node:path';

const ROOT = process.cwd();
const DATA_DIR = path.join(ROOT, 'data');
const CVES_JSON = path.join(DATA_DIR, 'cves.json');
const OUT_JSON  = path.join(DATA_DIR, 'v8_itw_patchmap.json');

const GERRIT = 'https://chromium-review.googlesource.com';
const GITILES_ROOT = 'https://chromium.googlesource.com';
const V8_PROJECT = 'v8/v8';
const CHROMIUM_PROJECT = 'chromium/src';

const UA = 'v8-research-hub/patchmap/6.0';

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const short = (s) => (typeof s === 'string' && s.length >= 7 ? s.slice(0, 12) : s || '');
const stripXssi = (t) => t.replace(/^\)\]\}'\s*\n?/, '');

async function httpText(url, { retries = 6, backoff = 450, headers = {} } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(url, { headers: { 'User-Agent': UA, ...headers } });
      if (r.ok) return r.text();
      lastErr = new Error(`${r.status} ${r.statusText}`);
    } catch (e) {
      lastErr = e;
    }
    await sleep(backoff * Math.pow(1.3, i));
  }
  throw lastErr || new Error('fetch failed: ' + url);
}

async function gerritJSON(url) {
  const txt = await httpText(url, { headers: { Accept: 'application/json' } });
  return JSON.parse(stripXssi(txt));
}

async function gitilesJSON(project, sha) {
  const url = `${GITILES_ROOT}/${project}/+/${sha}?format=JSON`;
  const txt = await httpText(url, { headers: { Accept: 'application/json' } });
  return JSON.parse(stripXssi(txt));
}

async function readJSON(file, fallback) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); }
  catch { return fallback; }
}

async function writeJSON(file, obj) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

function changeUrl(project, change) {
  return `${GERRIT}/c/${project}/+/${change}`;
}

function parseCherryPickedFrom(message) {
  if (!message) return null;
  const m = message.match(/\(cherry picked from commit ([0-9a-f]{7,40})\)/i);
  return m ? m[1] : null;
}

function parseProjectAndChangeFromUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    if (u.hostname !== 'chromium-review.googlesource.com') return null;
    const parts = u.pathname.split('/').filter(Boolean);
    const cIdx = parts.indexOf('c');
    if (cIdx === -1 || parts.length < cIdx + 3) return null;
    const project = decodeURIComponent(parts[cIdx + 1]);
    const changeNumber = parseInt(parts[cIdx + 2], 10);
    if (!project || !Number.isFinite(changeNumber)) return null;
    return { project, changeNumber };
  } catch {
    return null;
  }
}

/* ----------------------- CVE meta → IDs/CLs ----------------------- */
async function fetchCveMeta(cveId) {
  const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`;
  try {
    const txt = await httpText(url, { headers: { Accept: 'application/json' } });
    return JSON.parse(txt);
  } catch {
    return null;
  }
}

function extractRefs(meta) {
  const out = [];
  const refs =
    meta?.containers?.cna?.references ??
    meta?.cnaContainer?.references ??
    [];
  for (const r of refs) {
    if (!r) continue;
    const url = r.url || r.name || '';
    if (url) out.push(String(url));
    if (Array.isArray(r.tags)) for (const t of r.tags) out.push(String(t));
  }
  return out;
}

function extractChromiumThings(refs) {
  const issueIds = new Set();
  const changeLinks = [];
  for (const f of refs) {
    let m;
    // Bug/Issue IDs (we never fetch the bug; we just use the id in Gerrit queries)
    m = String(f).match(/issues\.chromium\.org\/issues\/(\d+)/i);
    if (m) issueIds.add(m[1]);
    m = String(f).match(/crbug\.com\/(?:[\w-]+\/)?(\d+)/i);
    if (m) issueIds.add(m[1]);
    m = String(f).match(/bugs\.chromium\.org\/p\/chromium\/issues\/detail\?id=(\d+)/i);
    if (m) issueIds.add(m[1]);
    m = String(f).match(/\bchromium:(\d+)\b/i);
    if (m) issueIds.add(m[1]);

    // Direct Gerrit CL link (rare but sometimes present)
    m = String(f).match(/chromium-review\.googlesource\.com\/c\/([^/]+)\/\+\/(\d+)/i);
    if (m) changeLinks.push({ project: m[1], change: +m[2] });
  }
  return { issueIds: [...issueIds], changeLinks };
}

/* ----------------------- Gerrit discovery ------------------------- */
// A merged CL that is clearly NOT a security fix (test/fuzzer/roll/version bump/squash).
// Used both to penalize during selection and to blank a low-confidence result at write time.
function looksLikeNonFix(subject) {
  const s = (subject || '').toLowerCase().trim();
  return (
    /^(revert|reland)\b/.test(s) ||
    /^roll\b/.test(s) ||                         // dependency roll (Skia/ANGLE/FreeType/Perfetto/...)
    /^version\s+\d/.test(s) ||                    // version-bump commit
    /\bfuzz(er|ing)?\b|libfuzzer/.test(s) ||      // fuzzer changes
    /regression test|add (a |some )?(d?check|test)|^\[?test\b|\btest(s)? for\b/.test(s) ||
    /--stress-|--no-lazy/.test(s) ||              // test/stress config changes
    /squashed multiple commits/.test(s)           // vague squash, not a precise fix
  );
}

function scoreChange(change, needle) {
  const subj = (change?.subject || '').toLowerCase();
  const msg  = (change?.revisions?.[change.current_revision]?.commit?.message || change?.subject || '').toLowerCase();

  let score = 0;
  // Prefer V8 over Chromium for V8 CVEs, but keep Chromium viable
  score += (change?.project === V8_PROJECT) ? 100 : 60;

  const n = String(needle).toLowerCase();
  if (subj.includes(n)) score += 20;
  if (msg.includes(n))  score += 35;

  // STRONG positive: real Chrome security fixes are backported to release/LTS branches
  // ([M###-LTS], [LTS-M###], [CfM-...]) and/or are cherry-picks ("Merged:", "cherry picked from").
  if (/\[m\d+(-lts)?\]|\[lts-m\d+\]|\[cfm/i.test(subj)) score += 90;
  if (/cherry picked from/i.test(msg))                 score += 45;
  if (/^merged:/i.test(subj))                          score += 25;

  // STRONG negative: non-fix CLs that merely reference the bug (the root cause of mismaps).
  if (looksLikeNonFix(subj)) score -= 150;

  const submitted = new Date(change?.submitted || change?.updated || change?.created || 0).getTime();
  return { score, submitted };
}

async function gerritQuery(q, n = 200, start = 0) {
  const url = `${GERRIT}/changes/?q=${encodeURIComponent(q)}&n=${n}&S=${start}&o=CURRENT_REVISION`;
  try {
    const txt = await httpText(url, { headers: { Accept: 'application/json' } });
    const arr = JSON.parse(stripXssi(txt));
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    console.log('[v8-patchmap] gerrit query failed:', e?.message || e, 'q=', q);
    return [];
  }
}

async function findMergedChangeForIssueOrCVE({ issueId, cveId }) {
  // Build robust query set (both projects, both styles)
  const needles = [];
  if (issueId) {
    needles.push(`"Bug: ${issueId}"`, `"Fixed: ${issueId}"`,
                 `"Bug: chromium:${issueId}"`, `"Fixed: chromium:${issueId}"`,
                 `${issueId}`);
  }
  if (cveId) {
    // Sometimes commits mention CVE explicitly
    needles.push(`"${cveId}"`, cveId);
  }

  const scopes = [
    `project:${V8_PROJECT} status:merged`,
    `project:${CHROMIUM_PROJECT} status:merged`,
  ];

  const seen = new Set();
  const candidates = [];

  for (const n of needles) {
    for (const s of scopes) {
      const q = `${s} ${n}`;
      let start = 0;
      for (;;) {
        const batch = await gerritQuery(q, 200, start);
        if (!batch.length) break;
        for (const ch of batch) {
          if (!ch?._number) continue;
          const key = `${ch.project}:${ch._number}`;
          if (seen.has(key)) continue;
          seen.add(key);
          candidates.push(ch);
        }
        if (batch.length < 200) break;
        start += batch.length;
        await sleep(100);
      }
    }
  }

  if (!candidates.length) return null;

  // Pick best by score; tie-breaker = most recent
  let best = null, meta = null, needle = issueId || cveId;
  for (const ch of candidates) {
    const m = scoreChange(ch, needle);
    if (!best || m.score > meta.score || (m.score === meta.score && m.submitted > meta.submitted)) {
      best = ch; meta = m;
    }
  }
  return best ? { project: best.project, change: best._number, status: (best.status || '').toUpperCase() } : null;
}

/* ------------------- Resolve tracks for a change ------------------- */
async function resolveTracks(project, changeNumber) {
  const detail = await gerritJSON(
    `${GERRIT}/changes/${encodeURIComponent(changeNumber)}/detail?o=CURRENT_REVISION`
  );
  const revId = detail?.current_revision;
  if (!revId) throw new Error('no current_revision in detail');

  const commit = await gerritJSON(
    `${GERRIT}/changes/${encodeURIComponent(changeNumber)}/revisions/${encodeURIComponent(revId)}/commit`
  );

  const landed = commit?.commit || null;
  const landedParent = commit?.parents?.[0]?.commit || null;
  const message = commit?.message || '';
  if (!landed) throw new Error('no commit sha in /revisions/<rev>/commit');

  const original = parseCherryPickedFrom(message) || null;

  let originalParent = null;
  if (original) {
    try {
      const gl = await gitilesJSON(project, original);
      originalParent = gl?.parents?.[0] || null;
    } catch (e) {
      console.log(`[v8-patchmap] warn: gitiles parent fetch failed for ${project} ${short(original)} → ${e?.message || e}`);
    }
  }

  // Gerrit submit timestamp ("YYYY-MM-DD HH:MM:SS.sss" UTC) -> ISO for the cross-engine timeline.
  let submitted = null;
  if (detail?.submitted) {
    const iso = String(detail.submitted).replace(' ', 'T').replace(/\.\d+$/, '') + 'Z';
    const d = new Date(iso);
    submitted = isNaN(d) ? null : d.toISOString();
  }

  return {
    project,
    change: changeNumber,
    status: (detail?.status || '').toUpperCase(),
    message_preview: message.slice(0, 300),
    patched_date: submitted,
    patched_backport: landed,
    unpatched_backport: landedParent,
    patched_original: original,
    unpatched_original: originalParent,
  };
}

/* -------- GitHub commit-search fallback (recovers old V8 fixes Gerrit text-search misses) -------- */
const GH_API = 'https://api.github.com';
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

async function ghJSON(url) {
  const txt = await httpText(url, { headers: { Accept: 'application/vnd.github+json', ...GH_AUTH } });
  return JSON.parse(txt);
}

// When Gerrit only yields a non-fix (e.g. a dependency roll), search the v8/v8 git mirror
// (then chromium/src) for the bug id and take the real fixing commit + its exact parent.
// Reverts and rolls are dropped; relands are kept and the latest substantive landing wins.
async function githubV8Fix(cve) {
  const meta = await fetchCveMeta(cve);
  const { issueIds } = extractChromiumThings(extractRefs(meta));
  for (const repo of ['v8/v8', 'chromium/src']) {
    for (const id of issueIds) {
      let res;
      try { res = await ghJSON(`${GH_API}/search/commits?q=repo:${repo}+${id}&per_page=30`); }
      catch { continue; }
      const items = (res?.items || [])
        .map(it => ({
          sha: it.sha,
          msg: it.commit?.message || '',
          subject: (it.commit?.message || '').split('\n')[0],
          date: it.commit?.committer?.date || it.commit?.author?.date || null,
        }))
        .filter(c => new RegExp(`\\b${id}\\b`).test(c.msg))                 // really references the bug
        .filter(c => !/^revert\b/i.test(c.subject) && !/^roll\b/i.test(c.subject));
      if (!items.length) continue;
      items.sort((a, b) => new Date(a.date || 0) - new Date(b.date || 0));
      const chosen = items[items.length - 1];                              // latest landed (reland wins)
      let commit;
      try { commit = await ghJSON(`${GH_API}/repos/${repo}/commits/${chosen.sha}`); }
      catch { continue; }
      const parent = commit?.parents?.[0]?.sha || null;
      if (!parent) continue;
      return { project: repo, patched: chosen.sha, unpatched: parent, date: chosen.date, subject: chosen.subject, bug: id };
    }
    await sleep(120);
  }
  return null;
}

/* ------------------------------- main ------------------------------------ */
async function main() {
  console.log('[v8-patchmap] start main()');
  const cvesData = await readJSON(CVES_JSON, { itw_chrome_related: [] });
  const rows = Array.isArray(cvesData.itw_chrome_related) ? cvesData.itw_chrome_related : [];

  console.log(`[v8-patchmap] scanning ${rows.length} Chrome/V8 ITW CVE(s)…\n`);

  const outMap = {};
  const byCve = new Map();
  for (const r of rows) if (r?.cve) byCve.set(r.cve, r);

  const misses = [];

  for (const r of rows) {
    const cve = r?.cve;
    if (!cve) continue;

    console.log(`[v8-patchmap] ── ${cve} ─────────────────────────────────────────────`);

    let project = r?.patchmap?.project || r?.patched_repo || null;
    let changeNumber = r?.patchmap?.gerrit_change ? +r.patchmap.gerrit_change : null;

    // Chromium issue-tracker id (for the modal "Chromium bug" link); also feeds discovery below.
    const { issueIds: issueIds0, changeLinks: changeLinks0 } = extractChromiumThings(extractRefs(await fetchCveMeta(cve)));
    let chromiumBug = issueIds0[0] || null;

    // 0) If patched_url exists, trust it first
    if (!changeNumber && r?.patched_url) {
      const parsed = parseProjectAndChangeFromUrl(r.patched_url);
      if (parsed) {
        project = parsed.project;
        changeNumber = parsed.changeNumber;
        console.log(`[v8-patchmap] seed: parsed from patched_url → ${project}/+/${changeNumber}`);
      }
    }

    // 1) If still unknown, auto-discover via CVE refs → (issue id | CVE string) → Gerrit
    if (!changeNumber) {
      const issueIds = issueIds0, changeLinks = changeLinks0;

      // Direct CL link beats everything
      if (changeLinks.length) {
        const best = changeLinks[0];
        project = best.project;
        changeNumber = best.change;
        console.log(`[v8-patchmap] discover: ${cve} → ${project}/+/${changeNumber} (from CVE refs: direct CL)`);
      } else {
        // Try by issue id variants, then fall back to CVE string
        let hit = null;

        for (const id of issueIds) {
          hit = await findMergedChangeForIssueOrCVE({ issueId: id, cveId: null });
          if (hit) {
            project = hit.project;
            changeNumber = hit.change;
            console.log(`[v8-patchmap] discover: ${cve} → ${project}/+/${changeNumber} (status=${hit.status})`);
            break;
          }
          await sleep(80);
        }

        if (!hit) {
          hit = await findMergedChangeForIssueOrCVE({ issueId: null, cveId: cve });
          if (hit) {
            project = hit.project;
            changeNumber = hit.change;
            console.log(`[v8-patchmap] discover (CVE text): ${cve} → ${project}/+/${changeNumber} (status=${hit.status})`);
          }
        }
      }
    }

    if (!changeNumber) {
      console.log(`[v8-patchmap] ${cve}: no Gerrit change resolved (skipping)`);
      misses.push(cve);
      continue;
    }

    try {
      const t = await resolveTracks(project, changeNumber);

      // Confidence guard: a CL that references the bug but is a test/fuzzer/roll/version/squash
      // is not the fix. For those, try the GitHub commit-search fallback to recover the real fix.
      const subjFirst = (t.message_preview || '').split('\n')[0];
      const hasOriginal = Boolean(t.patched_original);

      let confident = !looksLikeNonFix(subjFirst);
      let source = 'gerrit';
      let uiProject = t.project;
      let uiPatched   = confident ? (hasOriginal ? t.patched_original : t.patched_backport) : null;
      let uiUnpatched = confident ? (hasOriginal ? t.unpatched_original : t.unpatched_backport) : null;
      let uiDate = t.patched_date || null;
      let uiUrl = changeUrl(t.project, t.change);

      if (!confident) {
        const fb = await githubV8Fix(cve);
        if (fb) {
          confident = true; source = 'github';
          chromiumBug = chromiumBug || fb.bug;
          uiProject = fb.project; uiPatched = fb.patched; uiUnpatched = fb.unpatched;
          uiDate = fb.date || null; uiUrl = `https://github.com/${fb.project}/commit/${fb.patched}`;
          console.log(`[v8-patchmap] RECOVERED via github: ${cve} → ${fb.project} patched=${short(fb.patched)} · unpatched=${short(fb.unpatched)} (bug ${fb.bug}) "${(fb.subject||'').slice(0,44)}"`);
        }
      }

      const commitLink = (sha) => source === 'github'
        ? `https://github.com/${uiProject}/commit/${sha}`
        : `${GITILES_ROOT}/${uiProject}/+/${sha}`;

      const row = byCve.get(cve);
      if (row) {
        row.patched_repo = uiProject;
        row.patched_url  = uiUrl;
        row.patched_commit = uiPatched || null;
        row.unpatched_commit = uiUnpatched || null;
        row.unpatched_url = uiUnpatched ? commitLink(uiUnpatched) : null;

        row.patchmap = {
          ...(row.patchmap || {}),
          project: uiProject,
          gerrit_change: t.change,
          url: uiUrl,
          bug: chromiumBug ? Number(chromiumBug) : null,
          bug_url: chromiumBug ? `https://issues.chromium.org/issues/${chromiumBug}` : null,
          status: t.status,
          confident,
          source,
          patched_date: uiDate,
          message_preview: t.message_preview,
          patched_backport: t.patched_backport,
          unpatched_backport: t.unpatched_backport,
          patched_original: t.patched_original || null,
          unpatched_original: t.unpatched_original || null,
          urls: {
            patched_backport: t.patched_backport ? `${GITILES_ROOT}/${t.project}/+/${t.patched_backport}` : null,
            unpatched_backport: t.unpatched_backport ? `${GITILES_ROOT}/${t.project}/+/${t.unpatched_backport}` : null,
            patched_original: t.patched_original ? `${GITILES_ROOT}/${t.project}/+/${t.patched_original}` : null,
            unpatched_original: t.unpatched_original ? `${GITILES_ROOT}/${t.project}/+/${t.unpatched_original}` : null,
          },
          // Legacy mirrors for older consumers
          patched_commit: uiPatched || null,
          unpatched_commit: uiUnpatched || null,
        };
      }

      if (confident) {
        console.log(
          `[v8-patchmap] OK(${source}${source==='gerrit' ? (hasOriginal ? '/mainline' : '/backport') : ''}): ${cve} → ` +
          `patched=${short(uiPatched)} · unpatched=${short(uiUnpatched)} [${uiProject}]`
        );
      } else {
        console.log(`[v8-patchmap] BLANKED (non-fix CL, no github fix): ${cve} → ${t.project}/+/${t.change} "${subjFirst.slice(0,60)}"`);
      }

      outMap[cve] = {
        cve,
        project: uiProject,
        change: t.change,
        bug: chromiumBug ? Number(chromiumBug) : null,
        bug_url: chromiumBug ? `https://issues.chromium.org/issues/${chromiumBug}` : null,
        status: t.status,
        confident,
        source,
        patched_date: uiDate,
        message_preview: t.message_preview,
        patched_backport: t.patched_backport,
        unpatched_backport: t.unpatched_backport,
        patched_original: t.patched_original || null,
        unpatched_original: t.unpatched_original || null,
        patched_commit: uiPatched || null,
        unpatched_commit: uiUnpatched || null,
        url: uiUrl,
        generated: new Date().toISOString(),
      };
    } catch (e) {
      console.log(`[v8-patchmap] ${cve}: ${project}/+/${changeNumber} → error: ${e?.message || e}`);
      misses.push(cve);
    }

    await sleep(80);
  }

  await writeJSON(OUT_JSON, { generated: new Date().toISOString(), items: outMap });
  await writeJSON(CVES_JSON, { itw_chrome_related: rows });

  const enriched = Object.keys(outMap).length;
  const missCount = rows.length - enriched;
  console.log(`\n[v8-patchmap] enriched ${enriched} CVE(s). Misses: ${missCount}`);
  if (missCount) {
    console.log('[v8-patchmap] Misses → ' + rows.filter(r => !outMap[r.cve]).map(r => r.cve).join(', '));
  }
}

main().catch(err => {
  console.error('[v8-patchmap] fatal:', err?.stack || err?.message || String(err));
  process.exit(1);
});
