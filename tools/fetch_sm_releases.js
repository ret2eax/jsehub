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
