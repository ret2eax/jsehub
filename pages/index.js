import path from 'node:path';
import fs from 'node:fs';
import { useMemo, useState } from 'react';
import Head from 'next/head';

/* ------------------ utils ------------------ */
function formatDate(v) {
  if (!v) return '—';
  const d = new Date(v);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function readJSON(rel, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(process.cwd(), rel), 'utf8')); }
  catch { return fallback; }
}
const truncate = (s, n) => (s ? (s.length > n ? s.slice(0, n-1) + '…' : s) : '');

/* --------- CISA KEV: derive vulnerability class from shortDescription ---------- */
function kevClassFromShort(s) {
  if (!s) return 'Unspecified';
  const text = String(s).toLowerCase();
  const m = text.match(/contains?\s+(?:an?\s+)?(.+?)\s+vulnerabilit(?:y|ies)/i);
  const raw = (m ? m[1] : text).replace(/\s+/g, ' ').trim();

  const rules = [
    { re: /\buse[-\s]?after[-\s]?free\b/,                              cls: 'Use-after-free' },
    { re: /\btype\s+confusion\b/,                                      cls: 'Type confusion' },
    { re: /\bout[-\s]?of[-\s]?bounds.*\bwrite\b|\boob\s*write\b/,      cls: 'Out-of-bounds write' },
    { re: /\bout[-\s]?of[-\s]?bounds.*\bread\b|\boob\s*read\b/,        cls: 'Out-of-bounds read' },
    { re: /\bout[-\s]?of[-\s]?bounds\b|\boob\b/,                       cls: 'Out-of-bounds' },
    { re: /\binteger\s+(?:over|under)flow\b/,                          cls: 'Integer overflow/underflow' },
    { re: /\brace\s+condition\b|\btoctou\b/,                           cls: 'Race condition' },
    { re: /\bsandbox\s+escape\b/,                                      cls: 'Sandbox escape' },
    { re: /\bimproper\s+input\s+validation\b/,                         cls: 'Input validation' },
    { re: /\binappropriate\s+implementation\b/,                        cls: 'Implementation issue' },
    { re: /\blogic\s+error\b/,                                         cls: 'Logic error' },
    { re: /\bheap\s+buffer\s+overflow\b/,                              cls: 'Heap overflow' },
    { re: /\bstack\s+buffer\s+overflow\b/,                             cls: 'Stack overflow' },
    { re: /\bbuffer\s+overflow\b/,                                     cls: 'Buffer overflow' },
    { re: /\bmemory\s+corruption\b/,                                   cls: 'Memory corruption' },
    { re: /\b(remote|arbitrary)\s+code\s+execution\b|\brce\b/,         cls: 'Code execution' },
    { re: /\bdenial[-\s]?of[-\s]?service\b|\bdos\b/,                   cls: 'Denial of service' },
  ];
  for (const { re, cls } of rules) if (re.test(raw) || re.test(text)) return cls;

  const pretty = raw
    .replace(/\bunspecified\b/g, '')
    .replace(/\bmemory\b.*\b(write|read)\b/, 'Out-of-bounds $1')
    .trim()
    .replace(/\b\w/g, c => c.toUpperCase());
  return pretty || 'Unspecified';
}

/* ------------------ data load ------------------ */
export async function getStaticProps() {
  // Chrome / V8
  const releases = readJSON('data/releases.json', { releases: [] });
  const v8       = readJSON('data/v8_commits.json', { ref: 'refs/heads/main', commits: [] });
  const builds   = readJSON('data/builds.json', { asan_latest: {}, linux_release_asan_latest: null });
  const cves     = readJSON('data/cves.json', { itw_chrome_related: [] });
  const blog     = readJSON('data/chrome_releases_atom.json', { entries: [] });
  const gcls     = readJSON('data/v8_security_cls.json', { items: [] });

  // JSC
  const jsc_releases = readJSON('data/jsc_releases.json', { releases: [] });
  const jsc_commits  = readJSON('data/jsc_commits.json', { ref: 'main', commits: [] });
  const jsc_cves     = readJSON('data/jsc_cves.json', { itw_related: [] });
  const jsc_blog     = readJSON('data/safari_releases.json', { entries: [] });
  const jsc_gcls     = readJSON('data/jsc_security_cls.json', { items: [] });
  const jsc_resolve  = readJSON('data/jsc_resolver.json', { stp: [], commitIndex: {} });

  // SpiderMonkey
  const sm_releases = readJSON('data/sm_releases.json', { releases: [] });
  const sm_commits  = readJSON('data/sm_commits.json', { ref: 'central', commits: [] });
  const sm_builds   = readJSON('data/sm_builds.json', { latest: {} });
  const sm_cves     = readJSON('data/sm_cves.json', { itw_related: [] });
  const sm_blog     = readJSON('data/firefox_releases.json', { entries: [] });
  const sm_gcls     = readJSON('data/sm_security_cls.json', { items: [] });
  const sm_resolve  = readJSON('data/sm_resolver.json', { versions: {}, commitIndex: {} });

  return {
    props: {
      chrome: { releases, v8, builds, cves, blog, gcls },
      jsc:    { releases: jsc_releases, commits: jsc_commits, cves: jsc_cves, blog: jsc_blog, gcls: jsc_gcls, resolve: jsc_resolve },
      sm:     { releases: sm_releases,  commits: sm_commits,  builds: sm_builds,  cves: sm_cves,  blog: sm_blog,  gcls: sm_gcls,  resolve: sm_resolve }
    }
  };
}

/* ------------------ transforms ------------------ */
function latestByChannel(releases, ch) {
  const rows = (releases.releases || []).filter(r => (r.channel || '').toLowerCase() === ch.toLowerCase());
  if (!rows.length) return null;
  const linuxFirst = rows.slice().sort((a, b) => {
    const pa = (a.platform || '').toLowerCase() === 'linux' ? 1 : 0;
    const pb = (b.platform || '').toLowerCase() === 'linux' ? 1 : 0;
    if (pb !== pa) return pb - pa;
    return new Date(b.updated || 0) - new Date(a.updated || 0);
  });
  return linuxFirst[0];
}
function normalizeAsan(builds) {
  const out = {};
  const src = builds?.asan_latest || {};
  const put = (plat, arch, row) => { (out[plat] ||= {}); out[plat][arch || 'x64'] = row; };
  for (const [plat, obj] of Object.entries(src)) {
    if (obj && typeof obj === 'object' && !('platform' in obj)) {
      for (const [arch, row] of Object.entries(obj)) put(plat, arch, row);
    }
  }
  for (const [plat, row] of Object.entries(src)) {
    if (row && typeof row === 'object' && ('platform' in row)) put(plat, row.arch || 'x64', row);
  }
  return out;
}

/* ------------------ commit link helpers ------------------ */
function commitUrl(commit, project) {
  if (!commit) return null;
  const p = (project || '').toLowerCase();
  if (p === 'v8/v8')           return `https://github.com/v8/v8/commit/${commit}`;
  if (p === 'chromium/src')    return `https://chromium.googlesource.com/chromium/src/+/${commit}`;
  if (p === 'webkit/webkit')   return `https://github.com/WebKit/WebKit/commit/${commit}`;
  if (p === 'mozilla-central') return `https://hg.mozilla.org/mozilla-central/rev/${commit}`;
  return null;
}

function MonoCommitLink({ commit, project }) {
  if (!commit) return <span className="muted">—</span>;
  const short = String(commit).slice(0, 12);
  const url = commitUrl(commit, project);
  return url
    ? <a className="mono" href={url} target="_blank" rel="noreferrer">{short}</a>
    : <span className="mono">{short}</span>;
}

/* ------------------ modal ------------------ */
function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="modal-root" role="dialog" aria-modal="true">
      <div className="modal">
        <div className="modal-h">
          <div className="modal-t">{title}</div>
          <button className="x" aria-label="Close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-b">{children}</div>
      </div>
      <style jsx>{`
        .modal-root{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:1000;padding:20px}
        .modal{width:min(860px,96vw);border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2));box-shadow:0 28px 80px rgba(0,0,0,.55);overflow:hidden}
        .modal-h{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}
        .modal-t{font-weight:900;letter-spacing:.3px}
        .modal-b{padding:18px;max-height:70vh;overflow:auto}
        .x{border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--text);padding:7px 11px;cursor:pointer}
        .x:hover{background:#131a29}
      `}</style>
    </div>
  );
}

/* ------------------ shared cells ------------------ */
/* Commit-only display: no links, just 12-char hashes */
function MonoCommit({ commit }) {
  if (!commit) return <span className="muted">—</span>;
  return <span className="mono">{String(commit).slice(0, 12)}</span>;
}

/* Coalesce helpers so we always prefer commit hashes (top-level or patchmap) */
function coalescePatched(x) {
  const commit =
    x.patched_commit ||
    x.patchmap?.patched_commit ||
    null;
  const version = x.patched_version || null;
  return { commit, version };
}

function coalesceUnpatched(x) {
  const single =
    x.unpatched_commit ||
    x.patchmap?.unpatched_commit ||
    null;

  const commits = Array.isArray(x.unpatched_commits)
    ? x.unpatched_commits
    : (single ? [single] : []);

  const version = x.unpatched_version || null;
  return { commits: commits.length ? commits : null, version };
}

function PatchedCell({ patched_commit, patched_version, project }) {
  if (patched_commit) return <MonoCommitLink commit={patched_commit} project={project} />;
  if (patched_version) return <span className="mono">{patched_version}</span>;
  return <span className="muted">—</span>;
}

function UnpatchedCell({ unpatched_commits, unpatched_version, project }) {
  if (Array.isArray(unpatched_commits) && unpatched_commits.length) {
    const firstThree = unpatched_commits.slice(0, 3);
    return (
      <span className="mono">
        {firstThree.map((c, i) => {
          const url = commitUrl(c, project);
          const short = String(c).slice(0, 12);
          return (
            <span key={i}>
              {url
                ? <a className="mono" href={url} target="_blank" rel="noreferrer">{short}</a>
                : short}
              {i < firstThree.length - 1 ? ', ' : ''}
            </span>
          );
        })}
        {unpatched_commits.length > 3 ? ' …' : ''}
      </span>
    );
  }
  if (unpatched_commits) return <MonoCommitLink commit={unpatched_commits} project={project} />;
  if (unpatched_version) return <span className="mono">{unpatched_version}</span>;
  return <span className="muted">—</span>;
}

/* ------------------ resolvers ------------------ */
function ChromeResolver({ releases, openModal }) {
  const [q, setQ] = useState('');
  const hint = 'Version (127.0.x.x), Milestone (M127), Chromium/V8 commit hash, refs/heads/main@{#123456}';

  const byVersion = useMemo(() => {
       const m = new Map();
       const rows = (releases.releases || []).slice().sort((a, b) => new Date(b.updated || 0) - new Date(a.updated || 0));
       for (const r of rows) {
         if (!r.version) continue;
         const prev = m.get(r.version);
         const isLinux = (r.platform || '').toLowerCase() === 'linux' ? 1 : 0;
         if (!prev || ((prev.platform || '').toLowerCase() !== 'linux' && isLinux)) m.set(r.version, r);
       }
       return m;
     }, [releases]);

  const byMilestone = useMemo(() => {
    const g = new Map();
    for (const r of (releases.releases || [])) {
      if (r.milestone == null) continue;
      const key = String(r.milestone);
      (g.get(key) || g.set(key, []).get(key)).push(r);
    }
    const best = new Map();
    for (const [m, arr] of g) {
      arr.sort((a, b) => {
        const pa = (a.platform || '').toLowerCase() === 'linux' ? 1 : 0;
        const pb = (b.platform || '').toLowerCase() === 'linux' ? 1 : 0;
        if (pb !== pa) return pb - pa;
        return new Date(b.updated || 0) - new Date(a.updated || 0);
      });
      best.set(m, arr[0]);
    }
    return best;
  }, [releases]);

  const byPosition = useMemo(() => {
    const m = new Map();
    for (const r of (releases.releases || [])) {
      if (r.chromium_main_branch_position == null) continue;
      const key = String(r.chromium_main_branch_position);
      const prev = m.get(key);
      const isLinux = (r.platform || '').toLowerCase() === 'linux' ? 1 : 0;
      if (!prev || ((prev.platform || '').toLowerCase() !== 'linux' && isLinux)) m.set(key, r);
    }
    return m;
  }, [releases]);

  const byCommit = useMemo(() => {
    const m = new Map();
    for (const r of (releases.releases || [])) {
      if (r.chromium_commit) m.set(r.chromium_commit.toLowerCase(), { row: r, type: 'chromium' });
      if (r.v8_commit) m.set(r.v8_commit.toLowerCase(), { row: r, type: 'v8' });
    }
    return m;
  }, [releases]);

  function findByHash(prefix) {
    const p = prefix.toLowerCase();
    for (const [key, val] of byCommit) {
      if (key.startsWith(p)) return val;
    }
    return null;
  }

  function show(title, obj) {
    openModal(title,
      <div>
        <div className="kv">
          {'version' in obj ? (<><label>Version</label><div>{obj.version}</div></>) : null}
          {'milestone' in obj ? (<><label>Milestone</label><div>{obj.milestone}</div></>) : null}
          {'channel' in obj ? (<><label>Channel</label><div>{obj.channel}</div></>) : null}
          {'platform' in obj ? (<><label>Platform</label><div>{obj.platform}</div></>) : null}
          {'chromium_main_branch_position' in obj ? (<><label>Commit Pos</label><div className="mono">{obj.chromium_main_branch_position}</div></>) : null}
          {'hashes' in obj && obj.hashes?.chromium ? (<><label>Chromium</label><div className="mono">{obj.hashes.chromium}</div></>) : null}
          {'hashes' in obj && obj.hashes?.v8 ? (<><label>V8</label><div className="mono">{obj.hashes.v8}</div></>) : null}
          {'updated' in obj ? (<><label>Updated</label><div>{formatDate(obj.updated)}</div></>) : null}
        </div>
        <details style={{marginTop:14}}><summary className="muted">Raw JSON</summary><pre className="pre" style={{marginTop:8}}>{JSON.stringify(obj, null, 2)}</pre></details>
      </div>
    );
  }

  function resolve() {
    const s = q.trim();
    if (!s) return;

    if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) {
      const row = byVersion.get(s);
      if (!row) return openModal('Not found', <div className="muted">No matching Chrome/V8 release found for that version.</div>);
      return show('Version → details', {
        kind: 'version', version: row.version,
        channel: row.channel, platform: row.platform, milestone: row.milestone,
        chromium_main_branch_position: row.chromium_main_branch_position,
        hashes: { chromium: row.chromium_commit, v8: row.v8_commit, skia: row.skia_commit, angle: row.angle_commit },
        updated: row.updated
      });
    }

    const m = s.match(/^m?(\d{2,3})$/i);
    if (m) {
      const row = byMilestone.get(m[1]);
      if (!row) return openModal('Milestone not found', <div className="muted">Milestone {m[1]} not present.</div>);
      return show('Milestone → best version', {
        kind: 'milestone',
        milestone: row.milestone, best_version: row.version,
        channel: row.channel, platform: row.platform,
        chromium_main_branch_position: row.chromium_main_branch_position,
        hashes: { chromium: row.chromium_commit, v8: row.v8_commit, skia: row.skia_commit, angle: row.angle_commit },
        updated: row.updated
      });
    }

    if (/^refs\/heads\/main@\{#\d+\}$/.test(s) || /^refs\/branch-heads\/\d+x@\{#\d+\}$/.test(s)) {
      const posMatch = s.match(/@\{#(\d+)\}/);
      const row = posMatch ? byPosition.get(posMatch[1]) : null;
      if (row) {
        return show('Commit position → release', {
          kind: 'position',
          version: row.version,
          channel: row.channel,
          platform: row.platform,
          milestone: row.milestone,
          chromium_main_branch_position: row.chromium_main_branch_position,
          hashes: { chromium: row.chromium_commit, v8: row.v8_commit, skia: row.skia_commit, angle: row.angle_commit },
          updated: row.updated,
        });
      }
      const url = `https://crrev.org/${posMatch[1]}`;
      return openModal('Commit position', <div><span className="muted">Not found locally. </span><a href={url} target="_blank" rel="noreferrer">Open in crrev</a></div>);
    }

    if (/^[0-9a-f]{7,40}$/i.test(s)) {
      const hit = findByHash(s);
      if (!hit) {
        // Not the tip of any cached release. The commit may still be a valid
        // intermediate Chromium/V8 commit (e.g. a CVE patch), so route to the
        // authoritative sources instead of a dead end. Gitiles resolves
        // abbreviated SHAs; crrev redirects to the matching commit.
        const v8Url       = `https://chromium.googlesource.com/v8/v8/+/${s}`;
        const chromiumUrl = `https://chromium.googlesource.com/chromium/src/+/${s}`;
        const crrevUrl    = `https://crrev.com/${s}`;
        return openModal('Commit not a release tip', (
          <div>
            <div className="muted">No cached release ships this exact commit as its tip. Inspect it directly on the source:</div>
            <div className="kv" style={{marginTop:10}}>
              <label>Chromium</label><div><a href={chromiumUrl} target="_blank" rel="noreferrer">{chromiumUrl}</a></div>
              <label>V8</label><div><a href={v8Url} target="_blank" rel="noreferrer">{v8Url}</a></div>
              <label>crrev</label><div><a href={crrevUrl} target="_blank" rel="noreferrer">{crrevUrl}</a></div>
            </div>
          </div>
        ));
      }
      const { row, type } = hit;
      return show(`${type === 'v8' ? 'V8' : 'Chromium'} hash → release`, {
        kind: type,
        version: row.version,
        channel: row.channel,
        platform: row.platform,
        milestone: row.milestone,
        chromium_main_branch_position: row.chromium_main_branch_position,
        hashes: { chromium: row.chromium_commit, v8: row.v8_commit, skia: row.skia_commit, angle: row.angle_commit },
        updated: row.updated,
      });
    }

    openModal('How to use', <div className="muted">
      Version: <span className="mono">127.0.0.1</span> · Milestone: <span className="mono">M127</span> · Hash: <span className="mono">abc123</span> · Commit pos: <span className="mono">refs/heads/main@{`{#123456}`}</span>
    </div>);
  }

  return (
    <>
      <p className="resolver-hint">
        &gt;&gt; resolves version, milestone, Chromium/V8 commit hash, or refs/heads/main position to release metadata and full commit set.
      </p>
      <div className="resolver-input">
        <input className="input" placeholder={hint} value={q} onChange={(e)=>setQ(e.target.value)} />
        <button className="btn" onClick={resolve}>Resolve</button>
      </div>
    </>
  );
}

function JscResolver({ data, openModal }) {
  const [q, setQ] = useState('');
  const hint = 'Version (26.5), stable/beta, STP 246, JSC commit hash, r298000';

  const stp     = data.resolve?.stp || [];
  const idx     = data.resolve?.commitIndex || {};
  const commits = data.commits?.commits || [];
  const releases = data.releases?.releases || [];

  const releaseByChannel = useMemo(() => {
    const m = {};
    for (const r of releases) if (r.channel) m[r.channel.toLowerCase()] = r;
    return m;
  }, [releases]);

  const releaseByStp = useMemo(() => {
    const m = {};
    for (const r of releases) if (r.stp_number != null) m[String(r.stp_number)] = r;
    return m;
  }, [releases]);

  const releaseCommitIndex = useMemo(() => {
    const m = new Map();
    for (const r of releases) {
      if (r.webkit_commit) m.set(r.webkit_commit.toLowerCase(), r);
    }
    return m;
  }, [releases]);

  function findCommit(prefix) {
    const p = prefix.toLowerCase();
    if (idx[p]) return idx[p];
    const hit = commits.find(c => (c.commit || '').toLowerCase().startsWith(p));
    return hit ? { full: hit.commit.toLowerCase(), subject: hit.subject, author: hit.author, time: hit.time, url: hit.url } : null;
  }

  function findReleaseByHash(prefix) {
    const p = prefix.toLowerCase();
    for (const [key, row] of releaseCommitIndex) {
      if (key.startsWith(p)) return row;
    }
    return null;
  }

  function show(title, obj) {
    const gitUrl = obj.webkit_commit
      ? `https://github.com/WebKit/WebKit/commit/${obj.webkit_commit}`
      : null;
    openModal(title,
      <div>
        <div className="kv">
          {'version'       in obj && obj.version       != null && <><label>Version</label><div>{obj.version}</div></>}
          {'channel'       in obj && obj.channel       != null && <><label>Channel</label><div>{obj.channel}</div></>}
          {'stp_number'    in obj && obj.stp_number    != null && <><label>STP</label><div className="mono">{obj.stp_number}</div></>}
          {'webkit_commit' in obj && obj.webkit_commit != null && <><label>WebKit</label><div className="mono">{gitUrl ? <a href={gitUrl} target="_blank" rel="noreferrer">{obj.webkit_commit}</a> : obj.webkit_commit}</div></>}
          {'subject'       in obj && obj.subject       != null && <><label>Subject</label><div>{obj.subject}</div></>}
          {'link'          in obj && obj.link          != null && <><label>Release notes</label><div><a href={obj.link} target="_blank" rel="noreferrer">{obj.link}</a></div></>}
          {'updated'       in obj && obj.updated       != null && <><label>Updated</label><div>{formatDate(obj.updated)}</div></>}
        </div>
        <details style={{marginTop:14}}><summary className="muted">Raw JSON</summary><pre className="pre" style={{marginTop:8}}>{JSON.stringify(obj, null, 2)}</pre></details>
      </div>
    );
  }

  function resolve() {
    const s = q.trim();
    if (!s) return;

    // Safari version number e.g. "18.4" or "26.4" - match any cached release (Stable/Beta/STP)
    if (/^\d+\.\d+(?:\.\d+)?$/.test(s)) {
      const row = releases.find(r => r.version === s);
      if (!row) return openModal('Version not found', <div className="muted">No matching Safari release. Try the current Stable/Beta version, <span className="mono">beta</span>, or <span className="mono">STP N</span>.</div>);
      return show(`Safari ${s}`, {
        version:       row.version,
        channel:       row.channel,
        stp_number:    row.stp_number ?? null,
        webkit_commit: row.webkit_commit ?? null,
        link:          row.link ?? null,
        updated:       row.updated ?? null,
      });
    }

    // Channel: "stable", "beta", or "stp"
    if (/^(stable|beta|stp)$/i.test(s)) {
      const key = s.toLowerCase();
      const row = releaseByChannel[key];
      if (!row) return openModal('Not found', <div className="muted">No matching Safari/JSC release found.</div>);
      return show(`Safari ${row.version}`, {
        version:       row.version,
        channel:       row.channel,
        stp_number:    row.stp_number ?? null,
        webkit_commit: row.webkit_commit ?? null,
        link:          row.link ?? null,
        updated:       row.updated ?? null,
      });
    }

    // STP number: "STP 198" or "198"
    const mStp = /^(?:stp\s*)?(\d{2,3})$/i.exec(s);
    if (mStp) {
      const n = parseInt(mStp[1], 10);
      // first check release cache
      const relRow = releaseByStp[String(n)];
      if (relRow) {
        return show(`STP ${n}`, {
          version:       relRow.version,
          channel:       relRow.channel,
          stp_number:    relRow.stp_number,
          webkit_commit: relRow.webkit_commit ?? null,
          link:          relRow.link ?? null,
          updated:       relRow.updated ?? null,
        });
      }
      // fall back to stp list from resolver
      const stpRow = stp.find(x => x.number === n);
      if (!stpRow) return openModal('STP not found', <div className="muted">No Safari Technology Preview {n} found.</div>);
      return show(`STP ${n}`, {
        version:    `STP ${n}`,
        channel:    'STP',
        stp_number: n,
        link:       stpRow.link ?? null,
        updated:    stpRow.updated ?? null,
      });
    }

    // Legacy SVN revision: r298000
    const mRev = /^r(\d{3,})$/i.exec(s);
    if (mRev) {
      const url = `https://trac.webkit.org/changeset/${mRev[1]}`;
      return openModal(`WebKit r${mRev[1]}`, <div>Open: <a href={url} target="_blank" rel="noreferrer">{url}</a></div>);
    }

    // Commit hash
    if (/^[0-9a-f]{7,40}$/i.test(s)) {
      const rel = findReleaseByHash(s.slice(0, 12));
      if (rel) {
        return show(`${rel.channel} release commit`, {
          version:       rel.version,
          channel:       rel.channel,
          stp_number:    rel.stp_number ?? null,
          webkit_commit: rel.webkit_commit ?? null,
          link:          rel.link ?? null,
          updated:       rel.updated ?? null,
        });
      }
      const c = findCommit(s.slice(0, 12));
      if (!c) {
        // Not a recent Source/JavaScriptCore commit; it may still be a valid WebKit commit
        // (JSC lives in the WebKit repo), so link out instead of dead-ending.
        const wkUrl = `https://github.com/WebKit/WebKit/commit/${s}`;
        return openModal('Not a recent JSC commit', (
          <div><span className="muted">No recent Source/JavaScriptCore commit matches that prefix. Look it up in the WebKit repo: </span><a href={wkUrl} target="_blank" rel="noreferrer">{wkUrl}</a></div>
        ));
      }
      return openModal(`JSC ${c.full.slice(0,12)}`, (
        <div>
          <div className="kv">
            <label>Commit</label><div className="mono">{c.full}</div>
            <label>Subject</label><div>{c.subject}</div>
            <label>Author</label><div>{c.author}</div>
            <label>Time</label><div>{formatDate(c.time)}</div>
            <label>Link</label><div><a href={c.url} target="_blank" rel="noreferrer">{c.url}</a></div>
          </div>
          <details style={{marginTop:14}}><summary className="muted">Raw JSON</summary><pre className="pre" style={{marginTop:8}}>{JSON.stringify(c, null, 2)}</pre></details>
        </div>
      ));
    }

    openModal('How to use', <div className="muted">Try: <span className="mono">26.5</span>, <span className="mono">stable</span>, <span className="mono">beta</span>, <span className="mono">STP 246</span>, <span className="mono">r298000</span>, or a JSC commit SHA/prefix.</div>);
  }

  return (
    <>
      <p className="resolver-hint">
        &gt;&gt; resolves Safari version, channel (stable/beta/stp), STP number, JSC commit hash/prefix, or SVN revision to release metadata or commit details.
      </p>
      <div className="resolver-input">
        <input className="input" placeholder={hint} value={q} onChange={(e)=>setQ(e.target.value)} />
        <button className="btn" onClick={resolve}>Resolve</button>
      </div>
    </>
  );
}

function SmResolver({ data, openModal }) {
  const [q, setQ] = useState('');
  const hint = 'Version (149.0.2), Milestone (M149), nightly/beta/stable, SpiderMonkey commit (hg/git)';

  const versions = data.resolve?.versions || {};
  const idx = data.resolve?.commitIndex || {};
  const commits = data.commits?.commits || [];
  const releases = data.releases?.releases || [];

  const releaseByChannel = useMemo(() => {
    const m = {};
    for (const r of releases) if (r.channel) m[r.channel.toLowerCase()] = r;
    return m;
  }, [releases]);

  const releaseByMilestone = useMemo(() => {
    const m = {};
    for (const r of releases) if (r.milestone != null) m[String(r.milestone)] = r;
    return m;
  }, [releases]);

  // index release-branch commits (Beta/Stable tips) so hash lookup finds them
  const releaseCommitIndex = useMemo(() => {
    const m = new Map();
    for (const r of releases) {
      if (r.sm_commit)  m.set(r.sm_commit.toLowerCase(),  { kind: 'hg',  row: r });
      if (r.git_commit) m.set(r.git_commit.toLowerCase(), { kind: 'git', row: r });
    }
    return m;
  }, [releases]);

  function findReleaseByHash(prefix) {
    const p = prefix.toLowerCase();
    for (const [key, val] of releaseCommitIndex) {
      if (key.startsWith(p)) return val;
    }
    return null;
  }

  function findCommit(prefix) {
    const p = prefix.toLowerCase();
    if (idx[p]) return idx[p];
    const hit = commits.find(c => (c.commit || '').toLowerCase().startsWith(p));
    return hit ? { full: hit.commit.toLowerCase(), subject: hit.subject, author: hit.author, time: hit.time, url: hit.url } : null;
  }

  function notesLink(channel) {
    const ch = (channel || '').toLowerCase();
    if (ch === 'stable') return 'https://www.mozilla.org/firefox/releases/';
    if (ch === 'beta')   return 'https://www.mozilla.org/firefox/beta/notes/';
    return 'https://www.mozilla.org/firefox/nightly/notes/';
  }

  function show(title, obj) {
    const hgBase = obj.branch === 'default'
      ? 'https://hg.mozilla.org/mozilla-central'
      : obj.channel === 'Beta'   ? 'https://hg.mozilla.org/releases/mozilla-beta'
      : obj.channel === 'Stable' ? 'https://hg.mozilla.org/releases/mozilla-release'
      : 'https://hg.mozilla.org/mozilla-central';
    const hgUrl  = obj.sm_commit  ? `${hgBase}/rev/${obj.sm_commit}`  : null;
    const gitUrl = obj.git_commit ? `https://github.com/mozilla-firefox/firefox/commit/${obj.git_commit}` : null;
    openModal(title,
      <div>
        <div className="kv">
          {'version'    in obj && obj.version    != null && <><label>Version</label><div>{obj.version}</div></>}
          {'channel'    in obj && obj.channel    != null && <><label>Train</label><div>{obj.channel}</div></>}
          {'milestone'  in obj && obj.milestone  != null && <><label>Milestone</label><div>{obj.milestone}</div></>}
          {'push_id'    in obj && obj.push_id    != null && <><label>Push ID</label><div className="mono">{obj.push_id}</div></>}
          {'sm_commit'  in obj && obj.sm_commit  != null && <><label>mozilla-central</label><div className="mono">{hgUrl ? <a href={hgUrl} target="_blank" rel="noreferrer">{obj.sm_commit}</a> : obj.sm_commit}</div></>}
          {'git_commit' in obj && obj.git_commit != null && <><label>firefox (git)</label><div className="mono">{gitUrl ? <a href={gitUrl} target="_blank" rel="noreferrer">{obj.git_commit}</a> : obj.git_commit}</div></>}
          {'subject'    in obj && obj.subject    != null && <><label>Subject</label><div>{obj.subject}</div></>}
          {'notes'      in obj && obj.notes      != null && <><label>Release notes</label><div><a href={obj.notes} target="_blank" rel="noreferrer">{obj.notes}</a></div></>}
          {'updated'    in obj && obj.updated    != null && <><label>Updated</label><div>{formatDate(obj.updated)}</div></>}
        </div>
        <details style={{marginTop:14}}><summary className="muted">Raw JSON</summary><pre className="pre" style={{marginTop:8}}>{JSON.stringify(obj, null, 2)}</pre></details>
      </div>
    );
  }

  function resolve() {
    const s = q.trim();
    if (!s) return;

    if (/^\d+\.\d+(?:\.\d+|[ab]\d+)?$/.test(s)) {
      const v = s;
      const channel = (v === versions.stable) ? 'Stable' : (v === versions.beta) ? 'Beta' : (v === versions.nightly) ? 'Nightly' : null;
      if (!channel) return openModal('Version not found', <div className="muted">No matching Firefox release found. Try the current <span className="mono">nightly</span>, <span className="mono">beta</span>, or <span className="mono">stable</span> version.</div>);
      const row = releaseByChannel[channel.toLowerCase()];
      return show(`Firefox ${v}`, {
        version:    v,
        channel:    channel,
        milestone:  row?.milestone  ?? null,
        push_id:    row?.push_id    ?? null,
        sm_commit:  row?.sm_commit  ?? null,
        git_commit: row?.git_commit ?? null,
        subject:    row?.subject    ?? null,
        notes:      notesLink(channel),
        updated:    row?.updated    ?? null,
      });
    }

    const mMs = s.match(/^m?(\d{2,3})$/i);
    if (mMs) {
      const row = releaseByMilestone[mMs[1]];
      if (!row) return openModal('Milestone not found', <div className="muted">Milestone {mMs[1]} not found.</div>);
      return show(`Milestone M${mMs[1]} → ${row.channel}`, {
        version:    row.version,
        channel:    row.channel,
        milestone:  row.milestone,
        push_id:    row.push_id    ?? null,
        sm_commit:  row.sm_commit  ?? null,
        git_commit: row.git_commit ?? null,
        subject:    row.subject    ?? null,
        notes:      notesLink(row.channel),
        updated:    row.updated    ?? null,
      });
    }

    if (/^(nightly|beta|stable)$/i.test(s)) {
      const key = s.toLowerCase();
      const row = releaseByChannel[key];
      const v = versions[key] || row?.version || null;
      return show(`Firefox ${s}`, {
        version:    v,
        channel:    s.charAt(0).toUpperCase() + s.slice(1).toLowerCase(),
        milestone:  row?.milestone  ?? null,
        push_id:    row?.push_id    ?? null,
        sm_commit:  row?.sm_commit  ?? null,
        git_commit: row?.git_commit ?? null,
        subject:    row?.subject    ?? null,
        notes:      notesLink(key),
        updated:    row?.updated    ?? null,
      });
    }

    if (/^[0-9a-f]{7,40}$/i.test(s)) {
      // first check if it's a known release-branch tip (Beta/Stable hg or git hash)
      const rel = findReleaseByHash(s.slice(0, 12));
      if (rel) {
        const { row } = rel;
        return show(`${row.channel} release commit`, {
          version:    row.version,
          channel:    row.channel,
          milestone:  row.milestone  ?? null,
          push_id:    row.push_id    ?? null,
          sm_commit:  row.sm_commit  ?? null,
          git_commit: row.git_commit ?? null,
          subject:    row.subject    ?? null,
          notes:      notesLink(row.channel),
          updated:    row.updated    ?? null,
        });
      }
      // fall back to mozilla-central commit index
      const c = findCommit(s.slice(0,12));
      if (!c) return openModal('Changeset not found', <div className="muted">No changeset matches that prefix. Try a longer prefix.</div>);
      return openModal(`mozilla-central ${c.full.slice(0,12)}`, (
        <div>
          <div className="kv">
            <label>Rev</label><div className="mono">{c.full}</div>
            <label>Subject</label><div>{c.subject}</div>
            <label>Author</label><div>{c.author}</div>
            <label>Time</label><div>{formatDate(c.time)}</div>
            <label>Link</label><div><a href={c.url} target="_blank" rel="noreferrer">{c.url}</a></div>
          </div>
          <details style={{marginTop:14}}><summary className="muted">Raw JSON</summary><pre className="pre" style={{marginTop:8}}>{JSON.stringify(c, null, 2)}</pre></details>
        </div>
      ));
    }

    openModal('How to use', <div className="muted">Try a Firefox version (<span className="mono">128.0.2</span>), a train (<span className="mono">nightly</span>/<span className="mono">beta</span>/<span className="mono">stable</span>), or an hg rev prefix.</div>);
  }

  return (
    <>
      <p className="resolver-hint">
        &gt;&gt; resolves Firefox version, release train (nightly/beta/stable), or SpiderMonkey (js/src) changeset hash/prefix to release metadata or commit details.
      </p>
      <div className="resolver-input">
        <input className="input" placeholder={hint} value={q} onChange={(e)=>setQ(e.target.value)} />
        <button className="btn" onClick={resolve}>Resolve</button>
      </div>
    </>
  );
}

/* ------------------ engine sections ------------------ */
function ChromeSection({ data, openModal }) {
  const channels = ['Canary','Dev','Beta','Stable'];
  const latest = Object.fromEntries(channels.map(ch => [ch, latestByChannel(data.releases, ch)]));
  const asan = normalizeAsan(data.builds);
  const platOrder = ['linux','mac','windows','win64','chromeos'];
  const platLabel = { linux:'Linux', mac:'MacOS', windows:'Windows', win64:'Windows64', chromeos:'ChromeOS'};
  const archLabel = { x64:'x64', arm64:'arm64', arm:'arm', sandbox:'sandbox' };

  const showMoreV8CLs = () => {
    const items = (data.gcls.items || []).slice(0, 50);
    openModal('Recent V8 CLs', (
      <ul className="list">
        {items.map(x=>(
          <li key={x.url}>
            <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
            <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
          </li>
        ))}
      </ul>
    ));
  };

  return (
    <>
      <section className="block">
        <header className="bhead">
          <h2>Chrome / V8</h2><span className="tag">Chromium</span>
        </header>
        <div className="ruler" />
        <div className="statrow">
          {channels.map(ch=>{
            const r = latest[ch] || {};
            return (
              <div className="stat" key={ch}>
                <div className="label">{ch}</div>
                <div className="value">{r.version || '—'}</div>
                <div className="meta">M{r.milestone ?? '—'} · <span className="mono">{r.v8_commit ? r.v8_commit.slice(0,12) : '—'}</span> · {r.updated ? formatDate(r.updated) : '—'}</div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="block">
        <div className="refs">
          <span className="l">Docs</span><a href="https://v8.dev" target="_blank" rel="noreferrer">https://v8.dev</a>
          <span className="l">V8 Source</span><a href="https://chromium.googlesource.com/v8/v8.git" target="_blank" rel="noreferrer">https://chromium.googlesource.com/v8/v8.git</a>
          <span className="l">V8 Source mirror</span><a href="https://github.com/v8/v8" target="_blank" rel="noreferrer">https://github.com/v8/v8</a>
          <span className="l">Issue tracker</span><a href="https://issues.chromium.org/issues" target="_blank" rel="noreferrer">https://issues.chromium.org/issues</a>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Latest ASan d8 Release Builds</h3></header>
        <p className="resolver-hint">
          &gt;&gt; pulled from [<a href="https://storage.googleapis.com/v8-asan/index.html" target="_blank">Google's official ASan bucket</a>].<br/></p>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr><th>Platform</th><th>Arch</th><th>Filename</th><th>Build</th><th>Commit</th><th>Updated</th><th>md5</th><th></th></tr>
            </thead>
            <tbody>
              {platOrder.flatMap(plat=>{
                const arches = asan[plat];
                if (!arches) return [];
                return Object.entries(arches).map(([arch,row])=>(
                  <tr key={`${plat}-${arch}`}>
                    <td>{platLabel[plat] || plat}</td>
                    <td>{archLabel[arch] || arch}</td>
                    <td className="mono">{row.filename || '—'}</td>
                    <td className="mono">{row.id || '—'}</td>
                    <td className="mono">{row.commit ? row.commit.slice(0,12) : '—'}</td>
                    <td>{formatDate(row.updated)}</td>
                    <td className="mono">{row.md5_hex || '—'}</td>
                    <td>{row.download ? <a className="btn small" href={row.download} target="_blank" rel="noreferrer">Download</a> : <span className="muted">—</span>}</td>
                  </tr>
                ));
              })}
              {Object.values(asan).every(v => !v || Object.keys(v).length===0) && (
                <tr><td colSpan={8} className="muted">ASan builds not fetched yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RESOLVER [Chrome/V8]</h3></header>
        <ChromeResolver releases={data.releases} openModal={openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Chrome/V8]</h3></header>
        <p className="resolver-hint">
        &gt;&gt; vulnerable commits derived from patched canonical parent (via cherry pick), verify before use to avoid misleading deltas.
      </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Component</th>
                <th>Patched</th><th>Vulnerable</th>
              </tr>
            </thead>
            <tbody>
              {data.cves.itw_chrome_related.slice(0,12).map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve}>
                    <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '—'}</td>
                    <td>{formatDate(x.dateAdded)}</td>
                    <td>{x.product}</td>
                    <td>
                      <PatchedCell
                        patched_commit={p.commit}
                        patched_version={p.version}
                        project={x.patchmap?.project}
                      />
                    </td>
                    <td>
                      <UnpatchedCell
                        unpatched_commits={u.commits}
                        unpatched_version={u.version}
                        project={x.patchmap?.project}
                      />
                    </td>
                  </tr>
                );
              })}
              {data.cves.itw_chrome_related.length===0 && <tr><td colSpan={7} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent V8 CLs</h3></header>
        <ul className="list">
          {(data.gcls.items||[]).slice(0,14).map(x=>(
            <li key={x.url}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {(data.gcls.items||[]).length>14 && (
            <li>
              <span className="more-link" onClick={showMoreV8CLs} role="button" tabIndex={0}
                onKeyDown={(e)=> (e.key==='Enter'||e.key===' ') && showMoreV8CLs()}>≫ show more</span>
            </li>
          )}
          {(data.gcls.items||[]).length===0 && <li className="muted">No items.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// V8 Commits <span className="muted mono" style={{fontWeight:400}}>[{data.v8.ref}]</span></h3></header>
        <ul className="timeline">
          {(data.v8.commits||[]).slice(0,14).map(c=>(
            <li key={c.commit}>
              <div className="mono hash">{c.commit.slice(0,12)}</div>
              <div className="tline-main">{truncate(c.subject, 140)}</div>
              <div className="subline">{c.author} · {formatDate(c.time)}</div>
            </li>
          ))}
          {(!data.v8.commits || data.v8.commits.length===0) && <li className="muted">No commits.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Chrome Releases</h3></header>
        <ul className="list">
          {data.blog.entries.slice(0,10).map((e,i)=>(
            <li key={i}>
              <a href={e.link} target="_blank" rel="noreferrer">{e.title}</a>
              {e.itw ? <span className="pill itw">ITW</span> : null}
              <div className="subline">{formatDate(e.updated)}</div>
            </li>
          ))}
          {data.blog.entries.length===0 && <li className="muted">No posts.</li>}
        </ul>
      </section>
    </>
  );
}

function JscSection({ data, openModal }) {
  const showMoreJscCLs = () => {
    const items = (data.gcls.items || []).slice(0, 50);
    openModal('Recent JavaScriptCore CLs', (
      <ul className="list">
        {items.map((x,i)=>(
          <li key={i}>
            <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
            <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
          </li>
        ))}
      </ul>
    ));
  };

  return (
    <>
      <section className="block">
        <header className="bhead">
          <h2>Safari / JavaScriptCore</h2><span className="tag">WebKit</span>
        </header>
        <div className="ruler" />
        {(data.releases.releases||[]).length ? (
          <div className="statrow">
            {['Stable','Beta','STP'].map(ch => {
              const r = latestByChannel(data.releases, ch) || {};
              return (
                <div className="stat" key={ch}>
                  <div className="label">{ch}</div>
                  <div className="value">{r.version || '—'}</div>
                  <div className="meta"><span className="mono">{r.webkit_commit ? r.webkit_commit.slice(0,12) : '—'}</span> · {r.updated ? formatDate(r.updated) : '—'}</div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="muted">No releases available right now.</div>
        )}
      </section>

      <section className="block">
        <div className="refs">
          <span className="l">Docs</span><a href="https://webkit.org" target="_blank" rel="noreferrer">https://webkit.org</a>
          <span className="l">Build docs</span><a href="https://docs.webkit.org" target="_blank" rel="noreferrer">https://docs.webkit.org</a>
          <span className="l">JSC Source</span><a href="https://github.com/WebKit/WebKit/tree/main/Source/JavaScriptCore" target="_blank" rel="noreferrer">https://github.com/WebKit/WebKit/tree/main/Source/JavaScriptCore</a>
          <span className="l">Bug tracker</span><a href="https://bugs.webkit.org" target="_blank" rel="noreferrer">https://bugs.webkit.org</a>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// ASan jsc Shell <span className="muted mono" style={{fontWeight:400}}>(build from source)</span></h3></header>
        <p className="resolver-hint">
          &gt;&gt; unlike V8&apos;s <code className="code">d8</code> and the SpiderMonkey <code className="code">jsshell</code>, WebKit/JSC publishes no prebuilt ASan distribution, build the engine-only <code className="code">jsc</code> shell from source via the JSCOnly port.
        </p>
        <pre className="pre sh" style={{marginTop:10}}>
<span className="c-com"># 1) get the WebKit source</span>{'\n'}
<span className="c-cmd">git</span> clone <span className="c-str">https://github.com/WebKit/WebKit.git</span>{'\n'}
<span className="c-cmd">cd</span> WebKit{'\n'}
{'\n'}
<span className="c-com"># 2) enable AddressSanitizer (persists across builds)</span>{'\n'}
<span className="c-cmd">Tools/Scripts/set-webkit-configuration</span> <span className="c-flag">--asan</span>{'\n'}
{'\n'}
<span className="c-com"># 3) build the engine-only jsc shell (JSCOnly port), debug</span>{'\n'}
<span className="c-cmd">Tools/Scripts/build-jsc</span> <span className="c-flag">--jsc-only</span> <span className="c-flag">--debug</span>{'\n'}
{'\n'}
<span className="c-com"># 4) resulting shell</span>{'\n'}
<span className="c-path">WebKitBuild/JSCOnly/Debug/bin/jsc</span>
</pre>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RESOLVER [Safari/JSC]</h3></header>
        <JscResolver data={data} openModal={openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Safari/JSC]</h3></header>
        <p className="resolver-hint">
          &gt;&gt; recent ITW patch map is a work in progress for this engine.
        </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Product</th>
                <th>Patched</th><th>Unpatched</th>
              </tr>
            </thead>
            <tbody>
              {(data.cves.itw_related||[]).slice(0,12).map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve}>
                    <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '—'}</td>
                    <td>{formatDate(x.dateAdded)}</td>
                    <td>{x.product}</td>
                    <td><PatchedCell patched_commit={p.commit} patched_version={p.version} project={x.patchmap?.project} /></td>
                    <td><UnpatchedCell unpatched_commits={u.commits} unpatched_version={u.version} project={x.patchmap?.project} /></td>
                  </tr>
                );
              })}
              {(data.cves.itw_related||[]).length===0 && <tr><td colSpan={7} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent JavaScriptCore CLs</h3></header>
        <ul className="list">
          {(data.gcls.items||[]).slice(0,14).map((x,i)=>(
            <li key={i}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {(data.gcls.items||[]).length>14 && (
            <li>
              <span className="more-link" onClick={showMoreJscCLs} role="button" tabIndex={0}
                onKeyDown={(e)=> (e.key==='Enter'||e.key===' ') && showMoreJscCLs()}>≫ show more</span>
            </li>
          )}
          {(data.gcls.items||[]).length===0 && <li className="muted">No items.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// JSC Commits <span className="muted mono" style={{fontWeight:400}}>({data.commits.ref})</span></h3></header>
        <ul className="timeline">
          {(data.commits.commits||[]).slice(0,14).map(c=>(
            <li key={c.commit}>
              <div className="mono hash">{c.commit.slice(0,12)}</div>
              <div className="tline-main">{truncate(c.subject, 140)}</div>
              <div className="subline">{c.author} · {formatDate(c.time)}</div>
            </li>
          ))}
          {(!data.commits.commits || data.commits.commits.length===0) && <li className="muted">No commits.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Safari Releases</h3></header>
        <ul className="list">
          {data.blog.entries.slice(0,10).map((e,i)=>(
            <li key={i}>
              <a href={e.link} target="_blank" rel="noreferrer">{e.title}</a>
              <div className="subline">{formatDate(e.updated)}</div>
            </li>
          ))}
          {data.blog.entries.length===0 && <li className="muted">No posts.</li>}
        </ul>
      </section>
    </>
  );
}

function SmSection({ data, openModal }) {
  const showMoreSmCLs = () => {
    const items = (data.gcls.items || []).slice(0, 50);
    openModal('Recent SpiderMonkey CLs', (
      <ul className="list">
        {items.map((x,i)=>(
          <li key={i}>
            <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
            <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
          </li>
        ))}
      </ul>
    ));
  };

  return (
    <>
      <section className="block">
        <header className="bhead">
          <h2>Firefox / SpiderMonkey</h2><span className="tag">Gecko</span>
        </header>
        <div className="ruler" />
        {(data.releases.releases||[]).length ? (
          <div className="statrow">
            {['Nightly','Beta','Stable'].map(ch => {
              const r = latestByChannel(data.releases, ch) || {};
              return (
                <div className="stat" key={ch}>
                  <div className="label">{ch}</div>
                  <div className="value">{r.version || '—'}</div>
                  <div className="meta">M{r.milestone ?? '—'} · <span className="mono">{r.sm_commit ? r.sm_commit.slice(0,12) : '—'}</span> · {r.updated ? formatDate(r.updated) : '—'}</div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="muted">No releases available right now.</div>
        )}
      </section>

      <section className="block">
        <div className="refs">
          <span className="l">Docs</span><a href="https://spidermonkey.dev" target="_blank" rel="noreferrer">https://spidermonkey.dev</a>
          <span className="l">SM Source (js/src)</span><a href="https://searchfox.org/firefox-main/source/js/src" target="_blank" rel="noreferrer">https://searchfox.org/firefox-main/source/js/src</a>
          <span className="l">SM Source mirror</span><a href="https://github.com/mozilla-firefox/firefox" target="_blank" rel="noreferrer">https://github.com/mozilla-firefox/firefox</a>
          <span className="l">Bug tracker</span><a href="https://bugzilla.mozilla.org" target="_blank" rel="noreferrer">https://bugzilla.mozilla.org</a>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Latest Spidermonkey ASan JS Shell Builds</h3></header>
        <p className="resolver-hint">
          &gt;&gt; pulled from [<a href="https://firefox-ci-tc.services.mozilla.com" target="_blank">Mozilla's Official Taskcluster</a>].<br/></p>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr>
                <th>Platform</th><th>Arch</th><th>Filename</th><th>Build</th><th>Commit</th><th>Created</th><th>md5</th><th></th>
              </tr>
            </thead>
            <tbody>
              {/* linux */}
              {data.builds?.latest?.linux && (
                <tr>
                  <td>linux64</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.linux.filename}</td>
                  <td className="mono">{data.builds.latest.linux.taskId || '—'}</td>
                  <td className="mono">{data.builds.latest.linux.commit ? data.builds.latest.linux.commit.slice(0,12) : '—'}</td>
                  <td>{formatDate(data.builds.latest.linux.created)}</td>
                  <td className="mono">{data.builds.latest.linux.md5 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.linux.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* windows */}
              {data.builds?.latest?.win64 && (
                <tr>
                  <td>win64</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.win64.filename}</td>
                  <td className="mono">{data.builds.latest.win64.taskId || '—'}</td>
                  <td className="mono">{data.builds.latest.win64.commit ? data.builds.latest.win64.commit.slice(0,12) : '—'}</td>
                  <td>{formatDate(data.builds.latest.win64.created)}</td>
                  <td className="mono">{data.builds.latest.win64.md5 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.win64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* mac x64 / arm64 */}
              {data.builds?.latest?.mac?.x64 && (
                <tr>
                  <td>macOS</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.mac.x64.filename}</td>
                  <td className="mono">{data.builds.latest.mac.x64.taskId || '—'}</td>
                  <td className="mono">{data.builds.latest.mac.x64.commit ? data.builds.latest.mac.x64.commit.slice(0,12) : '—'}</td>
                  <td>{formatDate(data.builds.latest.mac.x64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.x64.md5 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.mac.x64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}
              {data.builds?.latest?.mac?.arm64 && (
                <tr>
                  <td>macOS</td>
                  <td>arm64</td>
                  <td className="mono">{data.builds.latest.mac.arm64.filename}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.taskId || '—'}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.commit ? data.builds.latest.mac.arm64.commit.slice(0,12) : '—'}</td>
                  <td>{formatDate(data.builds.latest.mac.arm64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.md5 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.mac.arm64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* empty state */}
              {!data.builds || Object.keys(data.builds.latest || {}).length === 0 ? (
                <tr><td colSpan={8} className="muted">No SpiderMonkey ASan builds available right now.</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="muted" style={{marginTop:8}}>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RESOLVER [Firefox/SpiderMonkey]</h3></header>
        <SmResolver data={data} openModal={openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Firefox/SpiderMonkey]</h3></header>
        <p className="resolver-hint">
          &gt;&gt; recent ITW patch map is a work in progress for this engine.
        </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Product</th>
                <th>Patched</th><th>Unpatched</th>
              </tr>
            </thead>
            <tbody>
              {(data.cves.itw_related||[]).slice(0,12).map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve}>
                    <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '—'}</td>
                    <td>{formatDate(x.dateAdded)}</td>
                    <td>{x.product}</td>
                    <td><PatchedCell patched_commit={p.commit} patched_version={p.version} project={x.patchmap?.project} /></td>
                    <td><UnpatchedCell unpatched_commits={u.commits} unpatched_version={u.version} project={x.patchmap?.project} /></td>
                  </tr>
                );
              })}
              {(data.cves.itw_related||[]).length===0 && <tr><td colSpan={7} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent SpiderMonkey CLs</h3></header>
        <ul className="list">
          {(data.gcls.items||[]).slice(0,14).map((x,i)=>(
            <li key={i}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {(data.gcls.items||[]).length>14 && (
            <li>
              <span className="more-link" onClick={showMoreSmCLs} role="button" tabIndex={0}
                onKeyDown={(e)=> (e.key==='Enter'||e.key===' ') && showMoreSmCLs()}>≫ show more</span>
            </li>
          )}
          {(data.gcls.items||[]).length===0 && <li className="muted">No items.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// SpiderMonkey Commits <span className="muted mono" style={{fontWeight:400}}>({data.commits.ref})</span></h3></header>
        <ul className="timeline">
          {(data.commits.commits||[]).slice(0,14).map(c=>(
            <li key={c.commit}>
              <div className="mono hash">{c.commit.slice(0,12)}</div>
              <div className="tline-main">{truncate(c.subject, 140)}</div>
              <div className="subline">{c.author} · {formatDate(c.time)}</div>
            </li>
          ))}
          {(!data.commits.commits || data.commits.commits.length===0) && <li className="muted">No commits.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Firefox Releases</h3></header>
        <ul className="list">
          {data.blog.entries.slice(0,10).map((e,i)=>(
            <li key={i}>
              <a href={e.link} target="_blank" rel="noreferrer">{e.title}</a>
              {/in.the.wild/i.test(e.title) ? <span className="pill itw">ITW</span> : null}
              <div className="subline">{formatDate(e.updated)}</div>
            </li>
          ))}
          {data.blog.entries.length===0 && <li className="muted">No posts.</li>}
        </ul>
      </section>
    </>
  );
}

/* ------------------ page ------------------ */

function KeepMeAliveSnippet({ addr = "3BXV3v7KvWXPNYDwJdLQVtH8zxCXdhkwc9" }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try { await navigator.clipboard.writeText(addr); } catch {}
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  }

  return (
    <div
      className="donate"
      role="button"
      tabIndex={0}
      onClick={copy}
      onKeyDown={(e)=> (e.key==='Enter' || e.key===' ') && copy()}
      title="Click to copy address"
    >
      <span className="kw">function</span>{" "}
      <span className="fn">keepMeAlive</span>() {"{"}{" "}
      <span className="kw">const</span> <span className="id">donate</span> ={" "}
      <span className="str">"{addr}"</span>; {"}"} <span className="id">gc</span>();{" "}
      <span className="cmt">// --expose-gc --allow-natives-syntax</span>

      <span className={`toast ${copied ? "on" : ""}`}>copied ✓</span>
    </div>
  );
}

export default function BrowserResearchHub({ chrome, jsc, sm }) {
  const [tab, setTab] = useState('chrome');
  const [modal, setModal] = useState({ open:false, title:'', content:null });
  const openModal = (title, content) => setModal({ open:true, title, content });
  const closeModal = () => setModal(s => ({ ...s, open:false }));
  const chromeData = { ...chrome, openModal };

  return (
    <div className="page">
      <Head>
        <title>JS Engine Hub</title>
        <meta name="description" content="A curated surgical dashboard for fuzzing and vulnerability research across modern JavaScript engines, updates daily." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="robots" content="index, follow" />
        <meta name="theme-color" content="#070b12" />
        <link rel="canonical" href="https://jsehub.dev/" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon-32.png" sizes="32x32" type="image/png" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="JS Engine Hub" />
        <meta property="og:title" content="JS Engine Hub" />
        <meta property="og:description" content="Fuzzing and vulnerability research across V8, SpiderMonkey, and JavaScriptCore: releases, ASan builds, resolver, and in-the-wild CVEs." />
        <meta property="og:url" content="https://jsehub.dev/" />
        <meta property="og:image" content="https://jsehub.dev/og.png" />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="JS Engine Hub" />
        <meta name="twitter:description" content="Fuzzing and vulnerability research across V8, SpiderMonkey, and JavaScriptCore." />
        <meta name="twitter:image" content="https://jsehub.dev/og.png" />
      </Head>
      <GlobalStyles/>

      <header className="hero">
        <div className="brand">
          <em />
          <span>JS Engine Hub</span>
        </div>
        <p className="lede">A curated surgical dashboard for fuzzing and vulnerability research across modern JS engines.</p>
        <p className="update-note">
          <span className="cmt">// UPDATES DAILY AT 0700 &amp; 2100 ZULU [UTC]</span>
        </p>
        <nav className="tabs" role="tablist" aria-label="Engines">
          <div className="tab-group">
            <button className={`tab ${tab==='chrome'?'on':''}`} onClick={()=>setTab('chrome')} role="tab" aria-selected={tab==='chrome'}>Chrome / V8</button>
            <button className={`tab ${tab==='sm'?'on':''}`} onClick={()=>setTab('sm')} role="tab" aria-selected={tab==='sm'}>Firefox / SpiderMonkey</button>
            <button className={`tab ${tab==='jsc'?'on':''}`} onClick={()=>setTab('jsc')} role="tab" aria-selected={tab==='jsc'}>Safari / JSC</button>
          </div>
          <a
            className="gh-link"
            href="https://github.com/ret2eax/jsehub/issues/new?labels=enhancement"
            target="_blank"
            rel="noreferrer"
          >
            Request a feature →
          </a>
        </nav>
      </header>

      <main className="flow">
        {tab==='chrome' && <ChromeSection data={chromeData} openModal={openModal}/>}
        {tab==='jsc'    && <JscSection    data={jsc}       openModal={openModal}/>}
        {tab==='sm'     && <SmSection     data={sm}        openModal={openModal}/>}
      </main>

      <footer className="ft muted">
        <KeepMeAliveSnippet addr="3BXV3v7KvWXPNYDwJdLQVtH8zxCXdhkwc9" />
        <div className="ft-copy">
            {new Date().getFullYear()} JS Engine Hub : minimal surface, maximum signal.
        </div>
      </footer>

      <Modal open={modal.open} onClose={closeModal} title={modal.title}>
        {modal.content}
      </Modal>
    </div>
  );
}

/* ------------------ global styles ------------------ */
function GlobalStyles() {
  return (
    <style jsx global>{`
      :root{
        --bg:#070b12;
        --surface:#0c111a;
        --surface2:#0a0f17;
        --line:#162033;
        --text:#e9eff7;
        --muted:#9fb0c5;
        --mono:#d6e6ff;
        --accent:#7ff0be;
        --accent-ghost:rgba(127,240,190,.10);
        --warn:#f3d077;
        --good:#64e6bd;
        --shadow:0 24px 80px rgba(0,0,0,.55);

        /* VSCode-like syntax colors */
        --syntax-keyword:#c792ea;  /* purple */
        --syntax-func:#82aaff;     /* blue */
        --syntax-string:#ecc48d;   /* sand */
        --syntax-number:#f78c6c;   /* orange */
        --syntax-comment:#5c6370;  /* gray */
      }
      html,body{background:var(--bg);color:var(--text);font-family:Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial}
      *{box-sizing:border-box}
      a{color:var(--accent);text-decoration:none}
      a:hover{text-decoration:underline dotted}
      .page{max-width:1360px;margin:0 auto;padding:34px 22px}

      /* Hero */
      .hero{margin-bottom:22px;border-bottom:1px solid var(--line);padding-bottom:18px}
      .brand{display:flex;align-items:center;gap:12px;font-weight:1000;font-size:26px;letter-spacing:.2px}
      .brand em{display:inline-block;width:12px;height:12px;border-radius:999px;background:var(--accent);box-shadow:0 0 22px var(--accent-ghost)}
      .lede{margin:8px 0 6px;color:#bbcadc}
      .update-note{margin:0 0 14px 0;font-size:12px}
      .update-note .cmt{color:var(--syntax-comment)}
      .update-note .kw{color:var(--syntax-keyword)}
      .update-note .id{color:var(--mono)}
      .update-note .num{color:var(--syntax-number)}

      /* Tabs (syntax-colored active state) */
      .tabs{
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:8px;
      }
      .tab-group{display:flex;gap:8px;}
      .tab{border:1px solid var(--line);background:linear-gradient(180deg,#0e1521,#0b1018);color:var(--text);padding:10px 14px;border-radius:12px;cursor:pointer}
      .tab.on{color:var(--syntax-keyword);box-shadow:0 0 0 4px var(--accent-ghost) inset;border-color:#253148}
      .gh-link{
        border:1px solid var(--line);
        border-radius:12px;
        padding:10px 14px;
        text-decoration:none;
        background:linear-gradient(180deg,#0e1521,#0b1018);
        color:var(--text);
        font-weight:800;
        white-space:nowrap;
      }
      .gh-link:hover{box-shadow:0 0 0 4px var(--accent-ghost)}

      /* Flow sections */
      .flow{display:block}
      .block{padding:18px 0;border-top:1px solid var(--line)}
      .bhead{display:flex;align-items:center;gap:10px}
      .bhead h2{margin:0;font-weight:950;letter-spacing:.3px;color:var(--syntax-func)}
      .tag{border:1px solid var(--line);border-radius:999px;padding:4px 10px;font-size:12px;background:#0e1626;color:var(--syntax-string)}
      .ruler{height:1px;background:linear-gradient(90deg,transparent, var(--line) 20%, var(--line) 80%, transparent);margin:8px 0 2px}
      .bsub h3{margin:0;font-size:13px;text-transform:uppercase;letter-spacing:.16em;color:var(--syntax-keyword)}

      /* Stats row */
      .statrow{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:10px}
      @media(max-width:920px){ .statrow{grid-template-columns:1fr 1fr} }
      @media(max-width:540px){ .statrow{grid-template-columns:1fr} }
      .stat{padding:14px 12px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--surface2),#080d14);box-shadow:var(--shadow)}
      .stat .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.14em}
      .stat .value{font-weight:900;margin-top:4px;color:var(--syntax-number)}
      .stat .meta{margin-top:4px;color:var(--muted);font-size:12px}

      /* Tables & lists */
      .tableWrap{overflow-x:auto}
      .table{width:100%;border-collapse:collapse;font-size:12px}
      .table th,.table td{border-bottom:1px solid var(--line);padding:10px 10px;text-align:left;vertical-align:top}
      .table th{color:#cfe0f2;font-weight:700;text-transform:uppercase;letter-spacing:.08em}

      /* KEV table: shrink description column ~20% */
      .table th:nth-child(3), .table td:nth-child(3){
        width:40%;
        max-width:40%;
      }

      /* ITW tables: CVE / date / patched / vulnerable stay on one line; Description wraps */
      .table.itw th:nth-child(1), .table.itw td:nth-child(1),
      .table.itw th:nth-child(4), .table.itw td:nth-child(4),
      .table.itw th:nth-child(6), .table.itw td:nth-child(6),
      .table.itw th:nth-child(7), .table.itw td:nth-child(7){
        white-space:nowrap;
      }
      .table.itw th:nth-child(3), .table.itw td:nth-child(3){
        width:32%;
        max-width:32%;
      }

      .list{list-style:none;margin:0;padding:0}
      .list li{padding:12px 0;border-bottom:1px dashed var(--line)}
      .list li:last-child{border-bottom:0}
      .subline{color:var(--muted);font-size:12px;margin-top:3px}
      .timeline{list-style:none;margin:0;padding:0;border-left:1px solid var(--line)}
      .timeline li{padding:12px 0 12px 14px;position:relative}
      .timeline li::before{content:'';position:absolute;left:-6px;top:19px;width:10px;height:10px;border-radius:999px;background:#162133;border:1px solid var(--line)}
      .timeline .hash{font-size:12px;color:var(--syntax-number)}
      .timeline .tline-main{margin-top:2px}

      /* UI atoms */
      .kv{display:grid;grid-template-columns:140px 1fr;gap:8px 14px}
      .kv.slim label{color:var(--muted)}
      .notice{display:inline-block;padding:5px 12px;border-radius:999px;border:1px solid var(--line);background:#0f1727}
      .notice[data-state="good"]{color:var(--good)}
      .notice[data-state="warn"]{color:var(--warn)}
      .btn{background:linear-gradient(180deg,#0f1828,#0b1220);border:1px solid var(--line);border-radius:12px;padding:9px 12px;color:var(--text);font-weight:800;cursor:pointer}
      .btn.small{padding:7px 10px;font-size:12px}
      .btn:hover{box-shadow:0 0 0 4px var(--accent-ghost)}
      .input{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:#0b1220;color:var(--text);outline:none}
      .input:focus{box-shadow:0 0 0 4px var(--accent-ghost)}
      .pre{background:#0a0e16;border:1px solid var(--line);border-radius:10px;padding:10px;font-size:12px;white-space:pre-wrap;word-break:break-word}
      .pill{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);font-size:11px}
      .pill.itw{color:#ffb27e;background:#2a160b;border-color:#3a2216}
      .mono{font-family:ui-monospace, SFMono-Regular, Menlo, monospace;color:var(--mono)}
      /* Obsidian-style inline code chip */
      .code{font-family:ui-monospace, SFMono-Regular, Menlo, monospace;font-size:.9em;background:var(--accent-ghost);color:var(--accent);border:1px solid var(--line);border-radius:5px;padding:1px 6px}
      /* bash/sh code block highlighting */
      .pre.sh .c-com{color:var(--syntax-comment);font-style:italic}
      .pre.sh .c-cmd{color:var(--syntax-func)}
      .pre.sh .c-flag{color:var(--syntax-number)}
      .pre.sh .c-str{color:var(--syntax-string)}
      .pre.sh .c-path{color:var(--syntax-string)}
      /* per-engine references */
      .refs{display:grid;grid-template-columns:auto 1fr;gap:7px 16px;align-items:baseline;font-size:13px;margin-top:4px}
      .refs .l{color:var(--muted);white-space:nowrap}
      .refs a{word-break:break-all;font-family:ui-monospace, SFMono-Regular, Menlo, monospace;font-size:.95em}
      .muted{color:var(--muted)}

      .more-link{cursor:pointer;user-select:none}
      .more-link:hover{text-decoration:underline}

      /* Resolver hint + inline input/button */
      .resolver-hint{
        margin: 6px 0 8px;
        color: var(--muted);
        font-size: 13px;
      }
      .resolver-input{
        display:flex;
        gap:8px;
        align-items:center;
      }
      .resolver-input .input{flex:1;}

      .ft{border-top:1px solid var(--line);padding-top:14px;margin-top:28px;font-size:12px;color:#98abc2}

      /* Footer actions row */
      .ft-row{display:flex;justify-content:flex-end;margin-bottom:10px;}
      .gh-link{
        display:inline-block;border:1px solid var(--line);border-radius:10px;padding:6px 10px;font-size:12px;
        background:linear-gradient(180deg,#0f1828,#0b1220);color:var(--text);text-decoration:none;
      }
      .gh-link:hover{box-shadow:0 0 0 4px var(--accent-ghost);text-decoration:none;}

      /* Donation snippet: mono, syntax colored, click-to-copy */
      .donate{
        font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
        border:1px solid var(--line);
        border-radius:12px;
        background:linear-gradient(180deg,#0f1828,#0b1220);
        padding:10px 12px;
        white-space:nowrap;
        overflow:auto;
        cursor:copy;
        position:relative;
        box-shadow:var(--shadow);
        text-align:center; /* center the inline code line */
      }
      .donate:hover{ box-shadow:0 0 0 4px var(--accent-ghost); }
      .donate .kw{ color:var(--syntax-keyword); }
      .donate .fn{ color:var(--syntax-func); font-weight:700; }
      .donate .str{ color:var(--syntax-string); }
      .donate .cmt{ color:var(--syntax-comment); }
      .donate .id{ color:var(--mono); }

      /* Tiny toast */
      .toast{
        position:fixed;
        right:16px;
        bottom:16px;
        background:#0f1727;
        border:1px solid var(--line);
        padding:6px 9px;
        border-radius:10px;
        font-size:12px;
        color:var(--text);
        opacity:0;
        transform:translateY(8px);
        transition:opacity .18s ease, transform .18s ease;
        pointer-events:none;
        z-index:1200;
      }
      .toast.on{opacity:1;transform:translateY(0);}

      /* Footer copy line separated slightly */
      .ft-copy{ margin-top:10px; }

      .donate-snippet {
        background:#0a0e16;
        border:1px solid var(--line);
        border-radius:10px;
        padding:10px;
        font-size:12px;
        font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
        color:var(--mono);
        margin-bottom:12px;
        white-space:pre;
      }
    `}</style>
  );
}
