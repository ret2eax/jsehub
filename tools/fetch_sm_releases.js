// tools/fetch_sm_releases.js
// Fetch current Firefox Nightly/Beta/Stable versions from Mozilla product-details,
// and tip metadata (hg node, git mirror SHA, push ID, subject, branch) from hg.mozilla.org.
// Output: data/sm_releases.json = { releases: [...] }

import fs from 'node:fs/promises';

const PD_VERSIONS = 'https://product-details.mozilla.org/1.0/firefox_versions.json';
const PD_RELEASES = 'https://product-details.mozilla.org/1.0/firefox.json';
const HG_TIP = {
  Nightly: 'https://hg.mozilla.org/mozilla-central/json-rev/tip',
  Beta:    'https://hg.mozilla.org/releases/mozilla-beta/json-rev/tip',
  Stable:  'https://hg.mozilla.org/releases/mozilla-release/json-rev/tip',
};
const OUT = 'data/sm_releases.json';

async function fetchJSON(url) {
  const r = await fetch(url, { headers: { 'User-Agent': 'js-engine-hub' } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${url}`);
  return r.json();
}

const GH_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';

// The mozilla-firefox/firefox git mirror lags mozilla-central slightly, so the freshest
// (Nightly) git_commit may not be mirrored yet. Only keep a git SHA we can confirm exists,
// so the resolver never renders a 404 git link (the hg link always resolves).
async function gitMirrored(sha) {
  if (!sha) return false;
  try {
    const r = await fetch(`https://api.github.com/repos/mozilla-firefox/firefox/commits/${sha}`, {
      headers: {
        'User-Agent': 'js-engine-hub',
        'Accept': 'application/vnd.github+json',
        ...(GH_TOKEN ? { Authorization: `Bearer ${GH_TOKEN}` } : {}),
      },
    });
    return r.status === 200;
  } catch { return false; }
}

async function fetchTip(channel) {
  try {
    const j = await fetchJSON(HG_TIP[channel]);
    return {
      node:       j.node       || null,
      git_commit: j.git_commit || null,
      push_id:    j.pushid     ?? null,
      branch:     j.branch     || null,
      subject:    (j.desc || '').split('\n')[0].trim() || null,
    };
  } catch (e) {
    console.warn(`[sm releases] tip fetch failed for ${channel}: ${e.message}`);
    return { node: null, git_commit: null, push_id: null, branch: null, subject: null };
  }
}

function parseMilestone(version) {
  const m = String(version || '').match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function releaseDate(releasesMap, version) {
  // product-details keys are like "firefox-149.0.2"
  const key = `firefox-${version}`;
  return releasesMap[key]?.date || null; // "YYYY-MM-DD"
}

async function main() {
  try {
    const [pd, pdReleases] = await Promise.all([
      fetchJSON(PD_VERSIONS),
      fetchJSON(PD_RELEASES).then(j => j.releases || {}).catch(() => ({})),
    ]);

    const nightly = pd.FIREFOX_NIGHTLY || '';
    const beta    = pd.LATEST_FIREFOX_DEVEL_VERSION || '';
    const stable  = pd.LATEST_FIREFOX_VERSION || '';
    const now     = new Date().toISOString();

    const [nightlyTip, betaTip, stableTip] = await Promise.all([
      fetchTip('Nightly'),
      fetchTip('Beta'),
      fetchTip('Stable'),
    ]);

    // Drop any git SHA not yet present in the mirror (keeps git links from 404ing).
    await Promise.all([nightlyTip, betaTip, stableTip].map(async tip => {
      if (tip.git_commit && !(await gitMirrored(tip.git_commit))) tip.git_commit = null;
    }));

    const betaDate   = releaseDate(pdReleases, beta);
    const stableDate = releaseDate(pdReleases, stable);

    const releases = [
      nightly && {
        channel:    'Nightly',
        version:    nightly,
        milestone:  parseMilestone(nightly),
        sm_commit:  nightlyTip.node,
        git_commit: nightlyTip.git_commit,
        push_id:    nightlyTip.push_id,
        branch:     nightlyTip.branch,
        subject:    nightlyTip.subject,
        updated:    now,
        platform:   'linux',
      },
      beta && {
        channel:    'Beta',
        version:    beta,
        milestone:  parseMilestone(beta),
        sm_commit:  betaTip.node,
        git_commit: betaTip.git_commit,
        push_id:    betaTip.push_id,
        branch:     betaTip.branch,
        subject:    betaTip.subject,
        updated:    betaDate ? new Date(betaDate).toISOString() : now,
        platform:   'linux',
      },
      stable && {
        channel:    'Stable',
        version:    stable,
        milestone:  parseMilestone(stable),
        sm_commit:  stableTip.node,
        git_commit: stableTip.git_commit,
        push_id:    stableTip.push_id,
        branch:     stableTip.branch,
        subject:    stableTip.subject,
        updated:    stableDate ? new Date(stableDate).toISOString() : now,
        platform:   'linux',
      },
    ].filter(Boolean);

    await fs.writeFile(OUT, JSON.stringify({ releases }, null, 2));
    console.log(`[sm releases] wrote ${OUT}`);
    for (const r of releases) {
      console.log(`  ${r.channel}: ${r.version} | hg=${(r.sm_commit||'').slice(0,12)} | git=${(r.git_commit||'').slice(0,12)} | push=${r.push_id}`);
    }
  } catch (e) {
    await fs.writeFile(OUT, JSON.stringify({ releases: [] }, null, 2));
    console.error(`[sm releases] error: ${e.message}; wrote empty list`);
  }
}

main();
