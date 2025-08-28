import path from 'node:path';
import fs from 'node:fs';
import { useMemo, useState } from 'react';

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
  const tree     = readJSON('data/tree_status.json', { general_state: '', message: '', date: '' });
  const gcls     = readJSON('data/v8_security_cls.json', { items: [] });

  // JSC
  const jsc_releases = readJSON('data/jsc_releases.json', { releases: [] });
  const jsc_commits  = readJSON('data/jsc_commits.json', { ref: 'main', commits: [] });
  const jsc_builds   = readJSON('data/jsc_builds.json', { latest: {} });
  const jsc_cves     = readJSON('data/jsc_cves.json', { itw_related: [] });
  const jsc_blog     = readJSON('data/safari_releases.json', { entries: [] });
  const jsc_tree     = readJSON('data/jsc_tree.json', { general_state: '', message: '', date: '' });
  const jsc_gcls     = readJSON('data/jsc_security_cls.json', { items: [] });
  const jsc_resolve  = readJSON('data/jsc_resolver.json', { stp: [], commitIndex: {} });

  // SpiderMonkey
  const sm_releases = readJSON('data/sm_releases.json', { releases: [] });
  const sm_commits  = readJSON('data/sm_commits.json', { ref: 'central', commits: [] });
  const sm_builds   = readJSON('data/sm_builds.json', { latest: {} });
  const sm_cves     = readJSON('data/sm_cves.json', { itw_related: [] });
  const sm_blog     = readJSON('data/firefox_releases.json', { entries: [] });
  const sm_tree     = readJSON('data/sm_tree.json', { general_state: '', message: '', date: '' });
  const sm_gcls     = readJSON('data/sm_security_cls.json', { items: [] });
  const sm_resolve  = readJSON('data/sm_resolver.json', { versions: {}, commitIndex: {} });

  return {
    props: {
      chrome: { releases, v8, builds, cves, blog, tree, gcls },
      jsc:    { releases: jsc_releases, commits: jsc_commits, builds: jsc_builds, cves: jsc_cves, blog: jsc_blog, tree: jsc_tree, gcls: jsc_gcls, resolve: jsc_resolve },
      sm:     { releases: sm_releases,  commits: sm_commits,  builds: sm_builds,  cves: sm_cves,  blog: sm_blog,  tree: sm_tree,  gcls: sm_gcls,  resolve: sm_resolve }
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
        .modal{
          width:800px;
          max-width:96vw;
          height:500px;
          max-height:90vh;
          display:flex;
          flex-direction:column;
          border:1px solid var(--line);
          border-radius:14px;
          background:linear-gradient(180deg,var(--surface),var(--surface2));
          box-shadow:0 28px 80px rgba(0,0,0,.55);
        }
        .modal-h{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}
        .modal-t{font-weight:900;letter-spacing:.3px}
        .modal-b{
          flex:1;
          padding:18px;
          overflow-y:auto;
        }
        .x{border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--text);padding:7px 11px;cursor:pointer}
        .x:hover{background:#131a29}
      `}</style>
    </div>
  );
}

/* ------------------ resolvers ------------------ */
function ChromeResolver({ releases, openModal }) {
  const [q, setQ] = useState('');
  const hint = 'Version (127.0.x.x), Milestone (M127), Commit Position (refs/heads/main@{#123456})';

  const byVersion = useMemo(() => {
       const m = new Map();
       const rows = (releases.releases || []).slice().sort((a, b) => new Date(b.updated || 0) - new Date(a.updated || 0));
       for (const r of rows) {
         if (!r.version) continue;
         const prev = m.get(r.version);
         const isLinux = (r.platform || '').toLowerCase() === 'linux';
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
      if (!row) return openModal('Not found', <div className="muted">No match in cache. Run <span className="mono">pnpm fetch:data</span>.</div>);
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
      const url = `https://crrev.org/${encodeURIComponent(s)}`;
      return openModal('Commit position', <div>Open in crrev: <a href={url} target="_blank" rel="noreferrer">{url}</a></div>);
    }

    openModal('How to use', <div className="muted">
      Version: <span className="mono">127.0.0.1</span> · Milestone: <span className="mono">M127</span> · Commit pos: <span className="mono">refs/heads/main@{`{#123456}`}</span>
    </div>);
  }

  return (
    <>
      <p className="resolver-hint">
        Enter a Chrome version, milestone, or commit position to resolve it to the corresponding release details and hashes.
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
  const hint = 'STP 198 · r298000 · WebKit SHA (prefix ok)';
  const stp = data.resolve?.stp || [];
  const idx = data.resolve?.commitIndex || {};
  const commits = data.commits?.commits || [];

  function findCommit(prefix) {
    const p = prefix.toLowerCase();
    if (idx[p]) return idx[p];
    const hit = commits.find(c => (c.commit || '').toLowerCase().startsWith(p));
    return hit ? { full: hit.commit.toLowerCase(), subject: hit.subject, author: hit.author, time: hit.time, url: hit.url } : null;
  }

  function resolve() {
    const s = q.trim();
    if (!s) return;

    const mStp = /^stp\s*(\d{2,3})$/i.exec(s);
    if (mStp) {
      const n = parseInt(mStp[1], 10);
      const row = stp.find(x => x.number === n) || stp.find(x => (x.title || '').match(new RegExp(`\\b${n}\\b`)));
      if (!row) return openModal('STP not found', <div className="muted">No Safari Technology Preview {n} in cache.</div>);
      return openModal(`STP ${n}`, (
        <div className="kv">
          <label>Title</label><div>{row.title}</div>
          <label>Link</label><div><a href={row.link} target="_blank" rel="noreferrer">{row.link}</a></div>
          <label>Updated</label><div>{formatDate(row.updated)}</div>
        </div>
      ));
    }

    const mRev = /^r(\d{3,})$/i.exec(s);
    if (mRev) {
      const url = `https://trac.webkit.org/changeset/${mRev[1]}`;
      return openModal(`WebKit r${mRev[1]}`, <div>Open: <a href={url} target="_blank" rel="noreferrer">{url}</a></div>);
    }

    if (/^[0-9a-f]{7,40}$/i.test(s)) {
      const c = findCommit(s.slice(0,12));
      if (!c) return openModal('Commit not in cache', <div className="muted">Provide a longer prefix or run <span className="mono">pnpm run fetch:jsc</span>.</div>);
      return openModal(`WebKit ${c.full.slice(0,12)}`, (
        <div className="kv">
          <label>Commit</label><div className="mono">{c.full}</div>
          <label>Subject</label><div>{c.subject}</div>
          <label>Author</label><div>{c.author}</div>
          <label>Time</label><div>{formatDate(c.time)}</div>
          <label>Link</label><div><a href={c.url} target="_blank" rel="noreferrer">{c.url}</a></div>
        </div>
      ));
    }

    openModal('How to use', <div className="muted">Try: <span className="mono">STP 198</span>, <span className="mono">r298000</span>, or a WebKit SHA/prefix.</div>);
  }

  return (
    <>
      <p className="resolver-hint">
        Enter a Safari Technology Preview (STP) number, WebKit revision (rXXXXXX), or commit SHA/prefix to resolve it to the matching release or changeset.
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
  const hint = 'Firefox 128.0.2 · nightly/beta/stable · hg changeset prefix';

  const versions = data.resolve?.versions || {};
  const idx = data.resolve?.commitIndex || {};
  const commits = data.commits?.commits || [];

  function findCommit(prefix) {
    const p = prefix.toLowerCase();
    if (idx[p]) return idx[p];
    const hit = commits.find(c => (c.commit || '').toLowerCase().startsWith(p));
    return hit ? { full: hit.commit.toLowerCase(), subject: hit.subject, author: hit.author, time: hit.time, url: hit.url } : null;
  }

  function resolve() {
    const s = q.trim();
    if (!s) return;

    if (/^\d+\.\d+(?:\.\d+)?$/.test(s)) {
      const v = s;
      const badge = (v === versions.stable) ? 'Stable' : (v === versions.beta) ? 'Beta' : (v === versions.nightly) ? 'Nightly' : 'Unknown';
      const link = (badge === 'Stable')
        ? 'https://www.mozilla.org/firefox/releases/'
        : (badge === 'Beta')
          ? 'https://www.mozilla.org/firefox/beta/notes/'
          : 'https://www.mozilla.org/firefox/nightly/notes/';
      return openModal(`Firefox ${v}`, (
        <div className="kv">
          <label>Train</label><div>{badge}</div>
          <label>Release notes</label><div><a href={link} target="_blank" rel="noreferrer">{link}</a></div>
        </div>
      ));
    }

    if (/^(nightly|beta|stable)$/i.test(s)) {
      const key = s.toLowerCase();
      const v = ({ nightly: versions.nightly, beta: versions.beta, stable: versions.stable })[key];
      const link = key==='stable'
        ? 'https://www.mozilla.org/firefox/releases/'
        : key==='beta'
          ? 'https://www.mozilla.org/firefox/beta/notes/'
          : 'https://www.mozilla.org/firefox/nightly/notes/';
      return openModal(`Firefox ${s}`, (
        <div className="kv">
          <label>Version</label><div>{v || '—'}</div>
          <label>Notes</label><div><a href={link} target="_blank" rel="noreferrer">{link}</a></div>
        </div>
      ));
    }

    if (/^[0-9a-f]{12,40}$/i.test(s)) {
      const c = findCommit(s.slice(0,12));
      if (!c) return openModal('Changeset not in cache', <div className="muted">Provide a longer prefix or run <span className="mono">pnpm run fetch:sm</span>.</div>);
      return openModal(`mozilla-central ${c.full.slice(0,12)}`, (
        <div className="kv">
          <label>Rev</label><div className="mono">{c.full}</div>
          <label>Subject</label><div>{c.subject}</div>
          <label>Author</label><div>{c.author}</div>
          <label>Time</label><div>{formatDate(c.time)}</div>
          <label>Link</label><div><a href={c.url} target="_blank" rel="noreferrer">{c.url}</a></div>
        </div>
      ));
    }

    openModal('How to use', <div className="muted">Try a Firefox version (<span className="mono">128.0.2</span>), a train (<span className="mono">nightly</span>/<span className="mono">beta</span>/<span className="mono">stable</span>), or an hg rev prefix.</div>);
  }

  return (
    <>
      <p className="resolver-hint">
        Enter a Firefox version, release train (nightly/beta/stable), or Mercurial changeset prefix to resolve it to the appropriate release or commit.
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
  const platLabel = { linux:'linux-release', mac:'mac-release', windows:'win32-release_x64', win64:'win64-release', chromeos:'linux-release-chromeos'};
  const archLabel = { x64:'x64', arm64:'arm64', arm:'arm', sandbox:'sandbox' };

  const v8Items = (data.gcls.items || []);
  const hasMoreV8 = v8Items.length > 14;

  function openMoreV8() {
    openModal('Recent V8 CLs — more', (
      <div>
        <ul className="list">
          {v8Items.slice(0, 50).map(x=>(
            <li key={x.url}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {v8Items.length === 0 && <li className="muted">No items.</li>}
        </ul>
      </div>
    ));
  }

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
        <header className="bsub"><h3>// Latest ASan d8 Builds</h3></header>
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
        <header className="bsub"><h3>// Resolver</h3></header>
        <ChromeResolver releases={data.releases} openModal={data.openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Chrome/V8]</h3></header>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr><th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Product</th></tr>
            </thead>
            <tbody>
              {data.cves.itw_chrome_related.slice(0,12).map(x=>(
                <tr key={x.cve}>
                  <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                  <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                  <td>{x.shortDescription || x.description || '—'}</td>
                  <td>{formatDate(x.dateAdded)}</td>
                  <td>{x.product}</td>
                </tr>
              ))}
              {data.cves.itw_chrome_related.length===0 && <tr><td colSpan={5} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent V8 CLs</h3></header>
        <ul className="list">
          {v8Items.slice(0,14).map(x=>(
            <li key={x.url}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {v8Items.length===0 && <li className="muted">No items.</li>}
        </ul>
        {hasMoreV8 && (
          <div style={{marginTop:8}}>
            <button className="linkish" onClick={openMoreV8} aria-label="Show more V8 CLs">≫ show more</button>
          </div>
        )}
      </section>

      <section className="block">
        <header className="bsub"><h3>// Chromium Tree</h3></header>
        <div className="notice" data-state={(String(data.tree.general_state||'').toLowerCase()==='open')?'good':'warn'}>
          {(data.tree.general_state||'unknown').toUpperCase()}
        </div>
        <div className="kv slim" style={{marginTop:10}}>
          <label>Updated</label><div>{formatDate(data.tree.date)}</div>
          <label>Message</label><div>{data.tree.message || ''}</div>
        </div>
        <div className="muted" style={{marginTop:10}}>
          CI <a href="https://ci.chromium.org/" target="_blank" rel="noreferrer">ci.chromium.org</a> · Sheriff <a href="https://sheriff-o-matic.appspot.com/" target="_blank" rel="noreferrer">Sheriff-O-Matic</a>
        </div>
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
  return (
    <>
      <section className="block">
        <header className="bhead">
          <h2>Safari / JavaScriptCore</h2><span className="tag">WebKit</span>
        </header>
        <div className="ruler" />
        <div className="muted">
          {(data.releases.releases||[]).length ? 'Data present' : 'Populate data/jsc_releases.json (STP/Beta/Stable).'}
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Latest Debug/ASan JSC Builds</h3></header>
        <div className="muted">{Object.keys(data.builds.latest||{}).length ? 'Data present' : 'Populate data/jsc_builds.json.'}</div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Resolver</h3></header>
        <JscResolver data={data} openModal={openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Safari/JSC]</h3></header>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr><th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Product</th></tr>
            </thead>
            <tbody>
              {(data.cves.itw_related||[]).slice(0,12).map(x=>(
                <tr key={x.cve}>
                  <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                  <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                  <td>{x.shortDescription || x.description || '—'}</td>
                  <td>{formatDate(x.dateAdded)}</td>
                  <td>{x.product}</td>
                </tr>
              ))}
              {(data.cves.itw_related||[]).length===0 && <tr><td colSpan={5} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent JSC/WebKit CLs</h3></header>
        <ul className="list">
          {(data.gcls.items||[]).slice(0,14).map((x,i)=>(
            <li key={i}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {(data.gcls.items||[]).length===0 && <li className="muted">No items.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// WebKit Queue / EWS</h3></header>
        <div className="notice" data-state={(String(data.tree.general_state||'').toLowerCase()==='open')?'good':'warn'}>
          {(data.tree.general_state||'unknown').toUpperCase()}
        </div>
        <div className="kv slim" style={{marginTop:10}}>
          <label>Updated</label><div>{formatDate(data.tree.date)}</div>
          <label>Message</label><div>{data.tree.message || ''}</div>
        </div>
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
  return (
    <>
      <section className="block">
        <header className="bhead">
          <h2>Firefox / SpiderMonkey</h2><span className="tag">Gecko</span>
        </header>
        <div className="ruler" />
        <div className="muted">
          {(data.releases.releases||[]).length ? 'Data present' : 'Populate data/sm_releases.json (Nightly/Beta/Stable).'}
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Latest ASan js shell Builds</h3></header>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr>
                <th>Platform</th><th>Arch</th><th>Filename</th><th>Created</th><th>SHA256</th><th></th>
              </tr>
            </thead>
            <tbody>
              {/* linux */}
              {data.builds?.latest?.linux && (
                <tr>
                  <td>linux64</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.linux.filename}</td>
                  <td>{formatDate(data.builds.latest.linux.created)}</td>
                  <td className="mono">{data.builds.latest.linux.sha256 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.linux.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* windows */}
              {data.builds?.latest?.win64 && (
                <tr>
                  <td>win64</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.win64.filename}</td>
                  <td>{formatDate(data.builds.latest.win64.created)}</td>
                  <td className="mono">{data.builds.latest.win64.sha256 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.win64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* mac x64 / arm64 */}
              {data.builds?.latest?.mac?.x64 && (
                <tr>
                  <td>macOS</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.mac.x64.filename}</td>
                  <td>{formatDate(data.builds.latest.mac.x64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.x64.sha256 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.mac.x64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}
              {data.builds?.latest?.mac?.arm64 && (
                <tr>
                  <td>macOS</td>
                  <td>arm64</td>
                  <td className="mono">{data.builds.latest.mac.arm64.filename}</td>
                  <td>{formatDate(data.builds.latest.mac.arm64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.sha256 || '—'}</td>
                  <td><a className="btn small" href={data.builds.latest.mac.arm64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* empty state */}
              {!data.builds || Object.keys(data.builds.latest || {}).length === 0 ? (
                <tr><td colSpan={6} className="muted">No SpiderMonkey ASan builds found yet. Run <span className="mono">node tools/fetch_sm_builds.js</span>.</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <div className="muted" style={{marginTop:8}}>
          Tip: Taskcluster “fuzzing-asan-opt” artifacts are <span className="mono">target.tar.xz</span> (Linux), <span className="mono">target.zip</span> (Windows), and <span className="mono">target.dmg</span> (macOS).
        </div>
      </section>  

      <section className="block">
        <header className="bsub"><h3>// Resolver</h3></header>
        <SmResolver data={data} openModal={openModal}/>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT IN-THE-WILD [Firefox/SpiderMonkey]</h3></header>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr><th>CVE</th><th>Class</th><th>Description</th><th>Date added</th><th>Product</th></tr>
            </thead>
            <tbody>
              {(data.cves.itw_related||[]).slice(0,12).map(x=>(
                <tr key={x.cve}>
                  <td><a href={`https://nvd.nist.gov/vuln/detail/${x.cve}`} target="_blank" rel="noreferrer">{x.cve}</a></td>
                  <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                  <td>{x.shortDescription || x.description || '—'}</td>
                  <td>{formatDate(x.dateAdded)}</td>
                  <td>{x.product}</td>
                </tr>
              ))}
              {(data.cves.itw_related||[]).length===0 && <tr><td colSpan={5} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Recent Gecko/SM CLs</h3></header>
        <ul className="list">
          {(data.gcls.items||[]).slice(0,14).map((x,i)=>(
            <li key={i}>
              <a href={x.url} target="_blank" rel="noreferrer">{x.subject}</a>
              <div className="subline">{x.owner} · {formatDate(x.submitted)}</div>
            </li>
          ))}
          {(data.gcls.items||[]).length===0 && <li className="muted">No items.</li>}
        </ul>
      </section>

      <section className="block">
        <header className="bsub"><h3>// Firefox Tree (Treeherder)</h3></header>
        <div className="notice" data-state={(String(data.tree.general_state||'').toLowerCase()==='open')?'good':'warn'}>
          {(data.tree.general_state||'unknown').toUpperCase()}
        </div>
        <div className="kv slim" style={{marginTop:10}}>
          <label>Updated</label><div>{formatDate(data.tree.date)}</div>
          <label>Message</label><div>{data.tree.message || ''}</div>
        </div>
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

function KeepMeAliveSnippet({ addr = "bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }) {
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
      <GlobalStyles/>

      <header className="hero">
        <div className="brand">
          <em />
          <span>Browser Research Hub</span>
        </div>
        <p className="lede">A surgical dashboard for fuzzing and vuln research across modern JS engines.</p>
        <nav className="tabs" role="tablist" aria-label="Engines">
          <div className="tab-group">
            <button className={`tab ${tab==='chrome'?'on':''}`} onClick={()=>setTab('chrome')} role="tab" aria-selected={tab==='chrome'}>Chrome / V8</button>
            <button className={`tab ${tab==='sm'?'on':''}`} onClick={()=>setTab('sm')} role="tab" aria-selected={tab==='sm'}>Firefox / SpiderMonkey</button>
            <button className={`tab ${tab==='jsc'?'on':''}`} onClick={()=>setTab('jsc')} role="tab" aria-selected={tab==='jsc'}>Safari / JSC</button>
          </div>
          <a
            className="gh-link"
            href="https://github.com/your-org/your-repo/issues/new?labels=feature&template=feature_request.md"
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
        <KeepMeAliveSnippet addr="bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" />
        <div className="ft-copy">
          © {new Date().getFullYear()} Browser Research Hub — minimal surface, maximum signal.
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
      .page{max-width:1280px;margin:0 auto;padding:34px 22px}

      /* Hero */
      .hero{margin-bottom:22px;border-bottom:1px solid var(--line);padding-bottom:18px}
      .brand{display:flex;align-items:center;gap:12px;font-weight:1000;font-size:26px;letter-spacing:.2px}
      .brand em{display:inline-block;width:12px;height:12px;border-radius:999px;background:var(--accent);box-shadow:0 0 22px var(--accent-ghost)}
      .lede{margin:8px 0 14px;color:#bbcadc}

      /* Tabs (syntax-colored active state) */
      .tabs{
        display:flex;
        justify-content:space-between;
        align-items:center;
        gap:8px;
      }
      .tab-group{
        display:flex;
        gap:8px;
      }
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
        width:60%;
        max-width:60%;
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
      .muted{color:var(--muted)}
      .linkish{background:none;border:none;padding:0;color:var(--accent);cursor:pointer;font-weight:800}
      .linkish:hover{text-decoration:underline dotted}

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
      .resolver-input .input{
        flex:1;
      }

      .ft{border-top:1px solid var(--line);padding-top:14px;margin-top:28px;font-size:12px;color:#98abc2}

      /* Footer actions row */
      .ft-row{
        display:flex;
        justify-content:flex-end;
        margin-bottom:10px;
      }
      .gh-link{
        display:inline-block;
        border:1px solid var(--line);
        border-radius:10px;
        padding:6px 10px;
        font-size:12px;
        background:linear-gradient(180deg,#0f1828,#0b1220);
        color:var(--text);
        text-decoration:none;
      }
      .gh-link:hover{
        box-shadow:0 0 0 4px var(--accent-ghost);
        text-decoration:none;
      }

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
      .toast.on{
        opacity:1;
        transform:translateY(0);
      }

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
