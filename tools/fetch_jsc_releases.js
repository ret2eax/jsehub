// tools/fetch_jsc_releases.js
// Fetch Safari STP, Stable, and Beta release info.
// STP webkit_commit comes from the jsc_commits tip (STP tracks main).
// Stable/Beta webkit_commit: derived from Apple build number via GitHub tag lookup.
//   Apple build e.g. "20624.1.16" → tag prefix "WebKit-7624.1.16" (strip leading "206", prepend "7")
//   Beta: parsed from Apple developer docs for the next version.
// Output: data/jsc_releases.json = { releases: [{ channel, version, stp_number?, webkit_commit, link, updated, platform }] }

import fs from 'node:fs/promises';

const WEBKIT_FEED = 'https://webkit.org/feed/';
const APPLE_DOCS_BASE = 'https://developer.apple.com/tutorials/data/documentation/safari-release-notes';
const GITHUB_REFS_BASE = 'https://api.github.com/repos/WebKit/WebKit/git/matching-refs/tags';
const OUT = 'data/jsc_releases.json';
// Authenticate GitHub API calls when a token is present (60/hr unauth -> 1000+/hr).
const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
const GH_AUTH = GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {};

async function fetchText(url, opts = {}) {
  const r = await fetch(url, { headers: { 'User-Agent': 'js-engine-hub', ...GH_AUTH, ...opts.headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.text();
}

async function fetchJSON(url, opts = {}) {
  const r = await fetch(url, { headers: { 'User-Agent': 'js-engine-hub', 'Accept': 'application/json', ...GH_AUTH, ...opts.headers } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.json();
}

async function readJSON(path, fallback) {
  try { return JSON.parse(await fs.readFile(path, 'utf8')); }
  catch { return fallback; }
}

function parseRss(xml) {
  return [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => {
    const b = m[1];
    const title = (b.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/) || b.match(/<title>(.*?)<\/title>/))?.[1]?.trim() || '';
    const link  = (b.match(/<link>(.*?)<\/link>/) || b.match(/<guid[^>]*>(.*?)<\/guid>/))?.[1]?.trim() || '';
    const date  = b.match(/<pubDate>(.*?)<\/pubDate>/)?.[1]?.trim() || '';
    return { title, link, updated: date };
  });
}

const APPLE_SECURITY_INDEX = 'https://support.apple.com/en-us/100100';
const APPLE_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 js-engine-hub';

// Latest shipping Safari version from Apple's security-releases index (newest first). Reliable and
// always current, unlike the WebKit blog's "WebKit Features in Safari X.Y" post, which is infrequent
// and scrolls off the feed - which previously left Stable (and, gated on it, Beta) blank.
async function fetchLatestSafariStable() {
  try {
    const html = await fetchText(APPLE_SECURITY_INDEX, { headers: { 'User-Agent': APPLE_UA } });
    for (const rm of html.matchAll(/<tr>([\s\S]*?)<\/tr>/g)) {
      const row = rm[1];
      const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map(c => c[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim());
      if (cells.length < 3) continue;
      const sm = cells[0].match(/^Safari\s+([\d.]+)$/i);
      if (sm) {
        const d = new Date(cells[cells.length - 1]);
        const a = row.match(/<a href="(https:\/\/support\.apple\.com\/[^"]+)"/);
        return { version: sm[1], link: a?.[1] || null, updated: isNaN(d) ? null : d.toISOString() };
      }
    }
  } catch (e) { console.warn(`[jsc releases] apple index fetch failed: ${e.message}`); }
  return null;
}

// Convert Apple build number to GitHub WebKit tag prefix.
// e.g. "20624.1.16" → "7624.1.16"
// The major component starts with "20" (206xx) — strip "20" prefix, prepend "7".
// More precisely: major "20624" → strip first 2 chars "20" → "624", prepend "7" → "7624"
function buildToTagPrefix(build) {
  const parts = build.split('.');
  if (!parts.length) return null;
  const major = parts[0]; // e.g. "20624"
  // Strip leading "20" (2 chars) and prepend "7"
  const tagMajor = '7' + major.slice(2); // "7" + "624" = "7624"
  return [tagMajor, ...parts.slice(1)].join('.');
}

// Fetch build number from Apple release notes docs for a given version slug.
// slug: e.g. "safari-26_4-release-notes" derived from version "26.4"
async function fetchAppleBuild(version) {
  try {
    const slug = 'safari-' + version.replace(/\./g, '_') + '-release-notes';
    const url = `${APPLE_DOCS_BASE}/${slug}.json`;
    const j = await fetchJSON(url);
    // Look for abstract containing build number, e.g. "26.4 (20624.1.16)"
    const abstract = j?.abstract?.[0]?.text || j?.primaryContentSections?.[0]?.content?.[0]?.text || '';
    const m = abstract.match(/\((\d{5}\.\d+\.\d+[^)]*)\)/);
    if (m) return m[1].trim();
    // Try other locations
    const intro = JSON.stringify(j).match(/"text":"[^"]*\((\d{5}\.\d+\.\d+[^")]*)\)/);
    if (intro) return intro[1].trim();
    return null;
  } catch (e) {
    console.warn(`[jsc releases] apple docs fetch failed for ${version}: ${e.message}`);
    return null;
  }
}

// Fetch the latest GitHub tag matching a prefix and return its SHA.
async function fetchLatestTagSha(prefix) {
  try {
    const url = `${GITHUB_REFS_BASE}/WebKit-${prefix}`;
    const tags = await fetchJSON(url, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
    if (!Array.isArray(tags) || !tags.length) return null;
    const last = tags[tags.length - 1];
    const obj = last?.object;
    if (!obj) return null;
    if (obj.type === 'commit') return obj.sha;
    // annotated tag → fetch the tag object to get the commit sha
    try {
      const tagObj = await fetchJSON(obj.url, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
      return tagObj?.object?.sha || null;
    } catch {
      return obj.sha; // best-effort fallback
    }
  } catch (e) {
    console.warn(`[jsc releases] github tag fetch failed for prefix ${prefix}: ${e.message}`);
    return null;
  }
}

// Fetch the tip SHA of a GitHub branch by exact name.
async function fetchBranchSha(branchName) {
  try {
    const url = `https://api.github.com/repos/WebKit/WebKit/branches/${encodeURIComponent(branchName)}`;
    const j = await fetchJSON(url, { headers: { 'Accept': 'application/vnd.github.v3+json' } });
    return j?.commit?.sha || null;
  } catch {
    return null;
  }
}

// Derive webkit_commit for a release version via Apple docs + GitHub tags/branches.
// Falls back to the major safari-{major}-branch tip if no point-release tag exists.
async function resolveWebkitCommit(version) {
  const build = await fetchAppleBuild(version);
  if (!build) return null;
  console.log(`  [jsc releases] ${version} build: ${build}`);
  const prefix = buildToTagPrefix(build);
  if (!prefix) return null;
  console.log(`  [jsc releases] ${version} tag prefix: WebKit-${prefix}`);

  // Try GitHub tags first (point releases)
  const tagSha = await fetchLatestTagSha(prefix);
  if (tagSha) return tagSha;

  // Try exact branch (e.g. safari-7624.2.1-branch)
  const branchSha = await fetchBranchSha(`safari-${prefix}-branch`);
  if (branchSha) return branchSha;

  // Fall back to major version branch (e.g. safari-7624-branch) for pre-release/beta
  const major = prefix.split('.')[0]; // "7624"
  const majorBranchSha = await fetchBranchSha(`safari-${major}-branch`);
  if (majorBranchSha) {
    console.log(`  [jsc releases] ${version} using major branch safari-${major}-branch (no point-release tag yet)`);
    return majorBranchSha;
  }

  return null;
}

// Detect the current Safari Beta version from the WebKit blog or Apple docs.
// Heuristic: look for "WebKit Features in Safari X.Y Beta" or similar in the RSS feed.
function detectBetaVersion(items, stableVersion) {
  // Check RSS feed for beta announcement
  const betaRe = /Safari\s+([\d.]+)\s+[Bb]eta/i;
  const betaItem = items.find(i => betaRe.test(i.title));
  if (betaItem) {
    const m = betaRe.exec(betaItem.title);
    return { version: m[1], link: betaItem.link, updated: betaItem.updated };
  }
  // Fallback: try stable major + minor+1 (e.g. 26.4 → 26.5)
  if (!stableVersion) return null;
  const parts = stableVersion.split('.');
  if (parts.length < 2) return null;
  const nextMinor = (parseInt(parts[1], 10) || 0) + 1;
  const guessVersion = `${parts[0]}.${nextMinor}`;
  return { version: guessVersion, link: null, updated: null, guessed: true };
}

async function main() {
  try {
    const [xml, jscCommits, appleStable] = await Promise.all([
      fetchText(WEBKIT_FEED),
      readJSON('data/jsc_commits.json', { commits: [] }),
      fetchLatestSafariStable(),
    ]);

    const items = parseRss(xml);
    // STP tracks WebKit main; resolve the live main tip directly so it never depends on
    // jsc_commits.json being populated first (that ordering left STP commits null on deploys).
    const tipCommit = (await fetchBranchSha('main')) || jscCommits.commits?.[0]?.commit || null;

    // STP: "Release Notes for Safari Technology Preview N"
    const stpRe = /Technology Preview\s+(\d+)/i;
    const latestStp = items.find(i => stpRe.test(i.title));
    const stpNumber = latestStp ? parseInt(stpRe.exec(latestStp.title)[1], 10) : null;

    // Stable: prefer Apple's security-releases index (always current); fall back to the WebKit blog's
    // "WebKit Features for Safari X.Y" post when the index is unreachable.
    const stableRe = /WebKit [Ff]eatures? (?:in )?(?:for )?Safari\s+([\d.]+)(?:\s|$)/i;
    const feedStable = items.find(i => stableRe.test(i.title));
    const stableVersion = appleStable?.version || (feedStable ? stableRe.exec(feedStable.title)[1] : null);
    const stableLink = appleStable?.link || feedStable?.link || null;
    const stableUpdated = appleStable?.updated || feedStable?.updated || null;

    // Beta is detected independently of Stable so a missing stable never blanks it too.
    const betaInfo = detectBetaVersion(items, stableVersion);
    const betaVersion = betaInfo?.version || null;

    // Point releases (e.g. 26.5.2) often have no dedicated release-notes doc, so fall back to the
    // major.minor (26.5) to still resolve a webkit_commit.
    const resolveStableCommit = async (v) => {
      if (!v) return null;
      const c = await resolveWebkitCommit(v);
      if (c || v.split('.').length <= 2) return c;
      return resolveWebkitCommit(v.split('.').slice(0, 2).join('.'));
    };
    const [stableCommit, betaCommit] = await Promise.all([
      resolveStableCommit(stableVersion),
      betaVersion   ? resolveWebkitCommit(betaVersion)   : Promise.resolve(null),
    ]);

    const releases = [
      stableVersion && {
        channel:       'Stable',
        version:       stableVersion,
        stp_number:    null,
        webkit_commit: stableCommit,
        link:          stableLink,
        updated:       stableUpdated ? new Date(stableUpdated).toISOString() : new Date().toISOString(),
        platform:      'macos',
      },
      betaVersion && {
        channel:       'Beta',
        version:       betaVersion,
        stp_number:    null,
        webkit_commit: betaCommit, // null if no GitHub tag yet
        link:          betaInfo?.link || null,
        updated:       betaInfo?.updated ? new Date(betaInfo.updated).toISOString() : new Date().toISOString(),
        platform:      'macos',
      },
      stpNumber && {
        channel:       'STP',
        version:       `STP ${stpNumber}`,
        stp_number:    stpNumber,
        webkit_commit: tipCommit,
        link:          latestStp.link,
        updated:       latestStp.updated ? new Date(latestStp.updated).toISOString() : new Date().toISOString(),
        platform:      'macos',
      },
    ].filter(Boolean);

    await fs.writeFile(OUT, JSON.stringify({ releases }, null, 2));
    console.log(`[jsc releases] wrote ${OUT}`);
    for (const r of releases) {
      console.log(`  ${r.channel}: ${r.version} | webkit=${(r.webkit_commit||'null').slice(0,12)} | ${r.updated?.slice(0,10)}`);
    }
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ releases: [] }, null, 2));
    console.error(`[jsc releases] error: ${e.message}; wrote empty list`);
  }
}

main();
