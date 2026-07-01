import path from 'node:path';
import fs from 'node:fs';
import { useMemo, useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';

/* ------------------ utils ------------------ */
function formatDate(v) {
  if (!v) return '-';
  const d = new Date(v);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function readJSON(rel, fallback) {
  try { return JSON.parse(fs.readFileSync(path.join(process.cwd(), rel), 'utf8')); }
  catch { return fallback; }
}
const truncate = (s, n) => (s ? (s.length > n ? s.slice(0, n-1) + '…' : s) : '');

// Compare CVE ids newest-first: year descending, then sequence number descending.
function cmpCveDesc(a, b) {
  const pa = String(a?.cve || '').match(/CVE-(\d+)-(\d+)/);
  const pb = String(b?.cve || '').match(/CVE-(\d+)-(\d+)/);
  if (!pa) return 1; if (!pb) return -1;
  return (Number(pb[1]) - Number(pa[1])) || (Number(pb[2]) - Number(pa[2]));
}
const cveYear = (cve) => { const m = String(cve || '').match(/CVE-(\d{4})/); return m ? Number(m[1]) : 0; };

// A Safari/JSC row to display: a resolved patch map (any year), or a WebKit CVE from 2022+.
// Pre-2022 WebKit CVEs are dropped: Apple published no bugzilla ids before then, so they are
// systematically unresolvable (no public CVE->commit linkage exists for them).
const jscShown = (x) => Boolean(x.patchmap?.confident || (x.webkit === true && cveYear(x.cve) >= 2022));

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
    { re: /\bheap(?:\s+buffer)?\s+overflow\b/,                         cls: 'Heap overflow' },
    { re: /\bstack(?:\s+buffer)?\s+overflow\b/,                        cls: 'Stack overflow' },
    { re: /\bbuffer\s+overflow\b/,                                     cls: 'Buffer overflow' },
    { re: /\bmemory\s+corruption\b/,                                   cls: 'Memory corruption' },
    // Apple's WebKit euphemism for a WebContent memory-safety bug.
    { re: /\bunexpected\s+(?:process|app|safari|system|device)\s+(?:crash|termination|reboot)\b|\bcorrupt\w*\s+(?:process\s+)?memory\b/, cls: 'Memory corruption' },
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

/* ------------------ cross-engine metadata + derivations ------------------ */
const ENGINES = {
  chrome: { key:'chrome', label:'Chrome / V8',            short:'V8',           vendor:'Google',  color:'#82aaff', cvesKey:'itw_chrome_related', project:'v8/v8' },
  jsc:    { key:'jsc',    label:'Safari / JSC',           short:'JSC',          vendor:'Apple',   color:'#ff8a8a', cvesKey:'itw_related',        project:'webkit/webkit' },
  sm:     { key:'sm',     label:'Firefox / SpiderMonkey', short:'SpiderMonkey', vendor:'Mozilla', color:'#f3d077', cvesKey:'itw_related',        project:'mozilla-firefox/firefox' },
};
const ENGINE_ORDER = ['chrome','jsc','sm'];

// Diff link between the vulnerable parent and the patched commit.
function compareUrl(unpatched, patched, project) {
  if (!unpatched || !patched) return null;
  const p = (project || '').toLowerCase();
  if (p === 'v8/v8')                   return `https://github.com/v8/v8/compare/${unpatched}...${patched}`;
  if (p === 'webkit/webkit')           return `https://github.com/WebKit/WebKit/compare/${unpatched}...${patched}`;
  if (p === 'mozilla-firefox/firefox') return `https://github.com/mozilla-firefox/firefox/compare/${unpatched}...${patched}`;
  // Gitiles has no range-diff page; the patched commit's own diff (against its parent =
  // the vulnerable commit) is exactly the fix. "<sha>^!" is Gitiles' single-commit diff view.
  if (p === 'chromium/src')            return `https://chromium.googlesource.com/chromium/src/+/${patched}%5E%21`;
  return null;
}

function fileUrl(file, sha, project) {
  if (!file || !sha) return null;
  const p = (project || '').toLowerCase();
  if (p === 'webkit/webkit')           return `https://github.com/WebKit/WebKit/blob/${sha}/${file}`;
  if (p === 'mozilla-firefox/firefox') return `https://github.com/mozilla-firefox/firefox/blob/${sha}/${file}`;
  if (p === 'v8/v8')                   return `https://github.com/v8/v8/blob/${sha}/${file}`;
  return null;
}

// Regression test / PoC files committed alongside a fix (the file a researcher actually wants).
function regressionFiles(files) {
  return (files || []).filter(f =>
    /(^|\/)(JSTests|jit-test)\//i.test(f) ||
    /\/(stress|regress[^/]*|crashtests?|reftests?)\//i.test(f)
  );
}

// Engine-relevant ITW CVEs. JSC's KEV slice bundles non-engine Apple components
// (Kernel/CoreAudio/ImageIO/...); keep only WebKit-family (JS engine) entries there.
function engineItwRows(props, key) {
  const arr = props[key]?.cves?.[ENGINES[key].cvesKey] || [];
  if (key === 'jsc') return arr.filter(jscShown);
  return arr;
}

// Flatten every engine's ITW CVEs into one list tagged with engine, newest first.
function allItwRows(props) {
  const rows = [];
  for (const key of ENGINE_ORDER) {
    for (const x of engineItwRows(props, key)) rows.push({ ...x, engine: key });
  }
  return rows.sort(cmpCveDesc);
}

// Flatten every engine's recent disclosures into one list tagged with engine, newest disclosed first.
function allDisclosureRows(props) {
  const rows = [];
  for (const key of ENGINE_ORDER) {
    for (const x of (props[key]?.disclosures?.items || [])) rows.push({ ...x, engine: key });
  }
  return rows.sort((a, b) => (new Date(b.disclosed || 0) - new Date(a.disclosed || 0)) || cmpCveDesc(a, b));
}

// Patch-map confidence breakdown for a set of rows: HIGH (verified), LOW (resolved but
// commits withheld), UNRESOLVED (no patch map).
function confidenceBreakdown(arr) {
  const high = arr.filter(x => x.patchmap?.confident).length;
  const low = arr.filter(x => x.patchmap && !x.patchmap.confident).length;
  return { total: arr.length, high, low, unresolved: arr.length - high - low };
}

// Per-engine in-the-wild patch-map coverage.
function coverage(props) {
  const out = {};
  for (const key of ENGINE_ORDER) out[key] = confidenceBreakdown(engineItwRows(props, key));
  return out;
}

// Per-engine recent-disclosure patch-map coverage.
function disclosureCoverage(props) {
  const out = {};
  for (const key of ENGINE_ORDER) out[key] = confidenceBreakdown(props[key]?.disclosures?.items || []);
  return out;
}

// Bug-class taxonomy: counts per class per engine across all ITW CVEs.
function taxonomy(rows) {
  const byClass = new Map();
  for (const r of rows) {
    const cls = kevClassFromShort(r.shortDescription || r.description);
    if (!byClass.has(cls)) byClass.set(cls, { chrome:0, jsc:0, sm:0, total:0 });
    const e = byClass.get(cls);
    e[r.engine] += 1; e.total += 1;
  }
  return [...byClass.entries()]
    .map(([cls, c]) => ({ cls, ...c }))
    .sort((a, b) => b.total - a.total);
}

function FreshnessBadge({ when }) {
  if (!when) return null;
  const d = new Date(when);
  if (isNaN(d)) return null;
  const day = `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,'0')}-${String(d.getUTCDate()).padStart(2,'0')}`;
  return <span className="fresh" title={`Data as of ${d.toISOString()}`}>as of {day}</span>;
}

// Next scheduled data refresh (CI runs ~07:00 and 21:00 UTC).
function nextRefreshUTC(now) {
  // Target :30, not the cron's :07, so the countdown lands when fresh data is actually live:
  // the build runs at 07:07 / 21:07 UTC and takes ~15-20 min, matching the 0730 / 2130 label.
  const out = [];
  for (const off of [0, 1]) for (const h of [7, 21]) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + off, h, 30, 0));
    if (d.getTime() > now.getTime()) out.push(d.getTime());
  }
  return Math.min(...out);
}
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60); if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60); if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}
// Hero status line: schedule + live "last refresh" and "next in" countdown.
// Renders schedule-only on the server/first paint (no `now`) to avoid hydration mismatch.
function UpdateStamp({ builtAt }) {
  const [now, setNow] = useState(null);
  useEffect(() => {
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  let live = '';
  if (now != null) {
    const built = builtAt ? new Date(builtAt).getTime() : null;
    const next = nextRefreshUTC(new Date(now));
    const ago = built != null && !isNaN(built) ? `${fmtDur(now - built)} AGO` : '-';
    live = ` · LAST REFRESH ${ago} · NEXT IN ${fmtDur(next - now)}`;
  }
  return <span className="cmt">// AUTO REFRESH 0730 & 2130 ZULU [UTC] {live}</span>;
}

// Inline diff for a verified row: loads the pre-fetched same-origin diff on demand
// (public/api/diff/<cve>.json) and renders the changed files + a colour-coded patch.
function DiffView({ data, patched, project, externalUrl }) {
  if (data === undefined) return <div className="diff-loading muted">loading diff…</div>;
  if (!data || !data.diff) return null; // chromium/src or unavailable -> the external link still shows

  return (
    <div className="diffbox">
      <div className="diff-files">
        {data.files.map((f, i) => {
          const u = fileUrl(f.file, patched, project);
          return (
            <div className="diff-file" key={i}>
              {u ? <a className="mono" href={u} target="_blank" rel="noreferrer">{f.file}</a> : <span className="mono">{f.file}</span>}
              <span className="diff-stat"><span className="add">+{f.additions}</span> <span className="del">-{f.deletions}</span></span>
            </div>
          );
        })}
      </div>
      <pre className="diff-pre">{data.diff.split('\n').map((ln, i) => {
        let cls = 'dl-ctx';
        if (/^diff --git|^new file|^deleted file/.test(ln)) cls = 'dl-file';
        else if (/^@@/.test(ln)) cls = 'dl-hunk';
        else if (ln[0] === '+') cls = 'dl-add';
        else if (ln[0] === '-') cls = 'dl-del';
        return <span key={i} className={`dl ${cls}`}>{ln || ' '}{'\n'}</span>;
      })}</pre>
      {data.truncated && <div className="muted diff-trunc">diff truncated · <a href={externalUrl} target="_blank" rel="noreferrer">view full diff →</a></div>}
    </div>
  );
}

// Full-detail view for a single CVE (opened from any ITW table; deep-linkable via #cve=).
function CveDetail({ row, engineKey }) {
  const eng = ENGINES[engineKey] || {};
  const pm = row.patchmap || {};
  const project = pm.project || eng.project;
  const patched = row.patched_commit || pm.patched_commit || null;
  const unpatched = row.unpatched_commit || pm.unpatched_commit || null;
  const diff = compareUrl(unpatched, patched, project);
  const tests = regressionFiles(pm.files);

  // Load the pre-fetched diff (changed files + colour-coded patch + full commit message) on open.
  const [diffData, setDiffData] = useState(undefined); // undefined = loading, null = none
  useEffect(() => {
    if (!patched || !unpatched) { setDiffData(null); return; }
    let alive = true;
    fetch(`/api/diff/${encodeURIComponent(row.cve)}.json`)
      .then(r => (r.ok ? r.json() : null))
      .then(d => { if (alive) setDiffData(d); })
      .catch(() => { if (alive) setDiffData(null); });
    return () => { alive = false; };
  }, [row.cve, patched, unpatched]);
  // Full commit message, only when we have a confident commit pair to attribute it to.
  const commitMessage = (patched && unpatched) ? (diffData?.message || pm.subject || pm.message_preview || null) : null;

  // For disclosure rows whose official text is generic (WebKit), the fix-commit subject is the
  // specific description; ITW rows keep their advisory/KEV text.
  const isDisc = Boolean(row.disclosed);
  const dc = disclosureDescClass(row, engineKey);
  const descText = isDisc ? (dc.desc === '-' ? 'No description.' : dc.desc) : (row.shortDescription || row.description || 'No description.');
  const classText = isDisc ? dc.cls : kevClassFromShort(row.shortDescription || row.description);
  // Explain a low/unresolved Chrome row that sits in an external dependency (fixed upstream via a roll).
  const depNote = (engineKey === 'chrome' && !pm.confident) ? chromiumExternalDep(row.shortDescription || row.description) : null;

  // The fix bug lives in the facts block below; only the Gerrit CL stays a bottom reference.
  const bugLabel = engineKey === 'chrome' ? 'Chromium bug' : engineKey === 'jsc' ? 'WebKit bug' : 'Bugzilla bug';
  const sources = [];
  if (engineKey === 'chrome' && pm.url) sources.push(['Gerrit CL', pm.url]);

  return (
    <div className="cve-detail">
      <div className="cd-tags">
        <span className="pill" style={{ marginLeft:0, color:eng.color, borderColor:'#243149' }}>{eng.short}</span>
        <span className="pill itw">{classText}</span>
        {row.patchmap
          ? <span className={`pill ${row.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}>{row.patchmap.confident ? 'Mapping Confidence: High' : 'Mapping Confidence: Low'}</span>
          : <span className="pill muted">Mapping Confidence: unresolved</span>}
      </div>

      <p className="cd-desc">{descText}</p>

      <div className="kv slim cd-kv">
        {row.severity && (<><label>Severity</label><div>{severityPill(row.severity)}</div></>)}
        {row.reporter && (<><label>Reporter</label><div>{row.reporter}</div></>)}
        {pm.patched_date && (<><label>Fix landed</label><div>{formatDate(pm.patched_date)}</div></>)}
        <label>Patched</label><div>{patched ? <MonoCommitLink commit={patched} project={project} /> : <span className="muted">withheld / unresolved</span>}</div>
        <label>Vulnerable</label><div>{unpatched ? <MonoCommitLink commit={unpatched} project={project} /> : <span className="muted">withheld / unresolved</span>}</div>
        {pm.bug && pm.bug_url && (<><label>{bugLabel}</label><div><a href={pm.bug_url} target="_blank" rel="noreferrer">{pm.bug}</a></div></>)}
      </div>

      {depNote && (
        <p className="cd-note muted">Fixed upstream in {depNote}, a Chromium dependency. Chromium integrates the fix via a version roll, so no single Chromium commit maps to this CVE; the upstream fix lives in the {depNote} repository.</p>
      )}

      {commitMessage && (
        <div className="cd-msg">
          <div className="cd-msg-h">Fix commit message</div>
          <pre className="cd-msg-pre">{commitMessage}</pre>
        </div>
      )}

      {patched && unpatched && (
        <div className="cd-fix">
          <div className="cd-fix-h">
            <span className="cd-msg-h" style={{ margin:0 }}>Diff</span>
            <div className="cd-fix-act">
              {tests.map((f, i) => {
                const u = fileUrl(f, patched, project);
                const name = f.split('/').pop();
                return u ? <a key={i} className="btn small trig" href={u} target="_blank" rel="noreferrer" title={f}>regression test: {name}</a> : null;
              })}
            </div>
          </div>
          <DiffView data={diffData} patched={patched} project={project} externalUrl={diff} />
          {diff && <div className="cd-fix-foot"><a className="btn small" href={diff} target="_blank" rel="noreferrer">view on source ↗</a></div>}
        </div>
      )}

      <div className="cd-links">
        <a href={`https://nvd.nist.gov/vuln/detail/${row.cve}`} target="_blank" rel="noreferrer">NVD</a>
        {sources.map(([label, url]) => <a key={label} href={url} target="_blank" rel="noreferrer">{label}</a>)}
        <a href={`https://www.cve.org/CVERecord?id=${row.cve}`} target="_blank" rel="noreferrer">CVE record</a>
      </div>
    </div>
  );
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

  // Recent researcher disclosures (90d, critical/high, attributed) per engine.
  const chrome_disc = readJSON('data/chrome_disclosures.json', { items: [] });
  const jsc_disc    = readJSON('data/jsc_disclosures.json', { items: [] });
  const sm_disc     = readJSON('data/sm_disclosures.json', { items: [] });

  return {
    props: {
      builtAt: new Date().toISOString(),   // build time ~= when data was fetched in CI
      chrome: { releases, v8, builds, cves, blog, gcls, disclosures: chrome_disc },
      jsc:    { releases: jsc_releases, commits: jsc_commits, cves: jsc_cves, blog: jsc_blog, gcls: jsc_gcls, resolve: jsc_resolve, disclosures: jsc_disc },
      sm:     { releases: sm_releases,  commits: sm_commits,  builds: sm_builds,  cves: sm_cves,  blog: sm_blog,  gcls: sm_gcls,  resolve: sm_resolve, disclosures: sm_disc }
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
  if (p === 'mozilla-firefox/firefox') return `https://github.com/mozilla-firefox/firefox/commit/${commit}`;
  if (p === 'mozilla-central') return `https://hg.mozilla.org/mozilla-central/rev/${commit}`;
  return null;
}

function MonoCommitLink({ commit, project }) {
  if (!commit) return <span className="muted">-</span>;
  const short = String(commit).slice(0, 12);
  const url = commitUrl(commit, project);
  return url
    ? <a className="mono" href={url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}>{short}</a>
    : <span className="mono">{short}</span>;
}

/* ------------------ modal ------------------ */
function Modal({ open, onClose, title, children }) {
  if (!open) return null;
  return (
    <div className="modal-root" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-h">
          <div className="modal-t">{title}</div>
          <button className="x" aria-label="Close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-b">{children}</div>
      </div>
      <style jsx>{`
        .modal-root{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:1000;padding:20px}
        .modal{width:min(1040px,96vw);border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--surface),var(--surface2));box-shadow:0 28px 80px rgba(0,0,0,.55);overflow:hidden}
        .modal-h{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}
        .modal-t{font-weight:900;letter-spacing:.3px}
        .modal-b{padding:18px;max-height:84vh;overflow:auto}
        .x{border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--text);padding:7px 11px;cursor:pointer}
        .x:hover{background:#131a29}
      `}</style>
    </div>
  );
}

/* ------------------ shared cells ------------------ */
/* Commit-only display: no links, just 12-char hashes */
function MonoCommit({ commit }) {
  if (!commit) return <span className="muted">-</span>;
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
  return <span className="muted">-</span>;
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
                ? <a className="mono" href={url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}>{short}</a>
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
  return <span className="muted">-</span>;
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
function severityPill(sev) {
  const s = (sev || '').toLowerCase();
  const cls = s === 'critical' ? 'sev-crit' : s === 'high' ? 'sev-high' : 'sev-mid';
  return <span className={`pill ${cls}`}>{s ? s[0].toUpperCase() + s.slice(1) : '-'}</span>;
}

// Mapping-confidence pill, shared by the ITW and disclosure tables.
function MappingPill({ patchmap }) {
  if (!patchmap) return <span className="pill muted help" title="No patch map could be mapped to this bug, manual effort needed">UNRESOLVED</span>;
  return <span className={`pill help ${patchmap.confident ? 'conf-hi' : 'conf-lo'}`}
    title={patchmap.confident
      ? 'The patched commit fixes this bug and the vulnerable commit is its exact parent.'
      : 'A fix was located but the single vulnerable parent is ambiguous, so the commits are withheld, manual effort needed.'}>{patchmap.confident ? 'HIGH' : 'LOW'}</span>;
}

// Chromium's external dependencies live in their own repos; a CVE in one is fixed upstream and
// reaches Chromium through a version roll (which spans many commits), so no single Chromium commit
// maps to it. Detect such a component from Google's own "<class> in <Component>" wording so the
// low/unresolved state can be explained rather than read as a resolver failure. Chromium-internal
// subsystems (GPU, WebML, FileSystem, Mojo, V8, Blink) are deliberately excluded.
const CHROMIUM_EXTERNAL_DEPS = ['ANGLE', 'Dawn', 'Skia', 'WebRTC', 'SwiftShader', 'FFmpeg', 'libvpx', 'PDFium', 'libxml', 'libxslt', 'SQLite', 'Perfetto', 'libwebp', 'BoringSSL', 'libavif'];
function chromiumExternalDep(text) {
  const s = (text || '').toLowerCase();
  return CHROMIUM_EXTERNAL_DEPS.find(d => new RegExp(`\\b${d.toLowerCase()}\\b`).test(s)) || null;
}

// Sub-area within WebKit/JSC, pulled from the fix-commit subject (a `Class::method` symbol, or a
// known engine module). Best-effort; null when nothing clean is detectable.
function webkitSubArea(subject) {
  const m = subject.match(/\b([A-Z][A-Za-z0-9]+)::/);
  if (m) return m[1] === 'Wasm' ? 'WebAssembly' : m[1];
  if (/\bwasm\b|webassembly/i.test(subject)) return 'WebAssembly';
  if (/\byarr\b|regular ?expression|regexp/i.test(subject)) return 'RegExp';
  return null;
}

// Best description + class for a disclosure row. Chrome and Firefox publish a per-CVE "<class> in
// <component>" description directly; Apple does not (its WebKit advisory impact is a generic line,
// identical across rows, and the bug is access-restricted). So for WebKit/JSC we synthesise the same
// shape from the resolved fix commit: class from the subject+impact, component (JavaScriptCore vs
// WebKit) and sub-area from the subject. Unresolved rows fall back to the generic Apple impact.
function disclosureDescClass(row, engineKey) {
  const impact = row.shortDescription || row.description || '';
  if (engineKey === 'jsc') {
    const subject = row.patchmap?.subject || '';
    const cls = kevClassFromShort(`${subject} ${impact}`.trim());
    if (subject) {
      const area = /\[jsc\]|\bwasm\b|webassembly|\byarr\b|\bdfg\b|\bftl\b|\bb3\b|ipint|llint|\bjsc\b|\bosr\b|regexp|regular expression/i.test(subject) ? 'JavaScriptCore' : 'WebKit';
      const sub = webkitSubArea(subject);
      return { desc: `${cls} in ${area}${sub ? ` (${sub})` : ''}`, cls };
    }
    return { desc: impact || '-', cls };
  }
  return { desc: impact || '-', cls: kevClassFromShort(impact) };
}

// Recent researcher disclosures (critical/high, not in-the-wild) for one engine.
function DisclosuresSection({ data, engineKey, openCve }) {
  const items = data.disclosures?.items || [];
  const ordered = useMemo(() => [...items].sort(cmpCveDesc), [items]);
  const [limit, setLimit] = useState(10);
  if (!items.length) return null;
  return (
    <section className="block">
      <header className="bsub"><h3>// RECENT DISCLOSURES [{ENGINES[engineKey].label}]</h3></header>
      <p className="resolver-hint">&gt;&gt; recent disclosures over the last 90 days, click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.</p>
      <div className="tableWrap">
        <table className="table itw">
          <thead>
            <tr>
              <th>CVE</th><th>Class</th><th>Description</th><th>Fix landed</th>
              <th>Patched</th><th>Vulnerable</th>
              <th className="help" title={"Mapping confidence: how reliably the patched/vulnerable commits map to this CVE.\nHIGH = verified fix + exact parent\nLOW  = fix spans multiple landings, commits withheld\n-     = no patch map resolved"}>Mapping confidence</th>
            </tr>
          </thead>
          <tbody>
            {ordered.slice(0, limit).map(x => {
              const p = coalescePatched(x); const u = coalesceUnpatched(x);
              const { desc, cls } = disclosureDescClass(x, engineKey);
              return (
                <tr key={x.cve} className="rowlink" onClick={() => openCve(x, engineKey)} tabIndex={0}
                    onKeyDown={e => (e.key==='Enter'||e.key===' ') && openCve(x, engineKey)}>
                  <td><span className="cve-link">{x.cve}</span></td>
                  <td>{cls}</td>
                  <td>{desc}</td>
                  <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
                  <td><PatchedCell patched_commit={p.commit} patched_version={p.version} project={x.patchmap?.project} /></td>
                  <td><UnpatchedCell unpatched_commits={u.commits} unpatched_version={u.version} project={x.patchmap?.project} /></td>
                  <td><MappingPill patchmap={x.patchmap} /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {ordered.length > limit && (
        <div style={{ marginTop:10 }}>
          <span className="more-link" role="button" tabIndex={0} onClick={() => setLimit(ordered.length)}
            onKeyDown={e => (e.key==='Enter'||e.key===' ') && setLimit(ordered.length)}>≫ show more ({ordered.length - limit} more)</span>
        </div>
      )}
    </section>
  );
}

function ChromeSection({ data, openModal, openCve }) {
  const ENGINE_TAB = 'chrome';
  const [itwLimit, setItwLimit] = useState(10);
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
                <div className="value">{r.version || '-'}</div>
                <div className="meta">M{r.milestone ?? '-'} · <span className="mono">{r.v8_commit ? r.v8_commit.slice(0,12) : '-'}</span> · {r.updated ? formatDate(r.updated) : '-'}</div>
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
                    <td className="mono">{row.filename || '-'}</td>
                    <td className="mono">{row.id || '-'}</td>
                    <td className="mono">{row.commit ? row.commit.slice(0,12) : '-'}</td>
                    <td>{formatDate(row.updated)}</td>
                    <td className="mono">{row.md5_hex || '-'}</td>
                    <td>{row.download ? <a className="btn small" href={row.download} target="_blank" rel="noreferrer">Download</a> : <span className="muted">-</span>}</td>
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

      <DisclosuresSection data={data} engineKey="chrome" openCve={openCve} />

      <section className="block">
        <header className="bsub"><h3>// IN-THE-WILD [Chrome/V8]</h3></header>
        <p className="resolver-hint">
        &gt;&gt; known ITW exploited vulnerabilities (non-exhaustive), click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.
      </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Fix landed</th>
                <th>Patched</th><th>Vulnerable</th>
                <th className="help" title={"HIGH = the patched commit fixes this bug, vulnerable commit is its exact parent)\nLOW  = a CL referencing the bug was found but is not confidently the fix (i.e. a dependency roll), so the commits are withheld\n-    = no patch CL could be resolved for this bug"}>Mapping confidence</th>
              </tr>
            </thead>
            <tbody>
              {[...data.cves.itw_chrome_related].sort(cmpCveDesc).slice(0,itwLimit).map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve} className="rowlink" onClick={()=>openCve(x, ENGINE_TAB)} tabIndex={0}
                      onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&openCve(x, ENGINE_TAB)}>
                    <td><span className="cve-link">{x.cve}</span></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '-'}</td>
                    <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
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
                    <td>{x.patchmap
                      ? <span
                          className={`pill help ${x.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}
                          title={x.patchmap.confident
                            ? 'The patched commit fixes this bug and the vulnerable commit is its exact parent.'
                            : 'A CL referencing the bug was found but is not confidently the fix (i.e. a dependency roll), so the patched/vulnerable commits are withheld, manual effort needed.'}
                        >{x.patchmap.confident ? 'HIGH' : 'LOW'}</span>
                      : <span className="pill muted help" title="No patch map could be mapped to this bug, manual effort needed">UNRESOLVED</span>}</td>
                  </tr>
                );
              })}
              {data.cves.itw_chrome_related.length===0 && <tr><td colSpan={7} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
        {data.cves.itw_chrome_related.length > itwLimit && (
          <div style={{ marginTop:10 }}>
            <span className="more-link" role="button" tabIndex={0}
              onClick={()=>setItwLimit(data.cves.itw_chrome_related.length)}
              onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&setItwLimit(data.cves.itw_chrome_related.length)}>≫ show more ({data.cves.itw_chrome_related.length - itwLimit} more)</span>
          </div>
        )}
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

    </>
  );
}

function JscSection({ data, openModal, openCve }) {
  const ENGINE_TAB = 'jsc';
  // Keep only WebKit-family (JS engine) CVEs, dropping non-engine Apple components and
  // pre-2022 WebKit CVEs (systematically unresolvable). Resolved rows always count. Newest first.
  const itwOrdered = [...(data.cves.itw_related||[])]
    .filter(jscShown)
    .sort(cmpCveDesc);
  const [itwLimit, setItwLimit] = useState(10);
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
                  <div className="value">{r.version || '-'}</div>
                  <div className="meta"><span className="mono">{r.webkit_commit ? r.webkit_commit.slice(0,12) : '-'}</span> · {r.updated ? formatDate(r.updated) : '-'}</div>
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

      <DisclosuresSection data={data} engineKey="jsc" openCve={openCve} />

      <section className="block">
        <header className="bsub"><h3>// IN-THE-WILD [Safari/JSC]</h3></header>
        <p className="resolver-hint">
          &gt;&gt; known ITW exploited vulnerabilities (non-exhaustive), click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.
        </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Fix landed</th>
                <th>Patched</th><th>Vulnerable</th>
                <th className="help" title={"HIGH = verified fix (>=2 Apple advisories agree on the WebKit bug and a single commit references it, vulnerable is its exact parent)\nLOW  = the fix spans multiple landings, so the single vulnerable parent is ambiguous and the commits are withheld\n-    = no WebKit bug was published for this bug (older or non-WebKit)"}>Mapping confidence</th>
              </tr>
            </thead>
            <tbody>
              {itwOrdered
                .slice(0, itwLimit)
                .map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve} className="rowlink" onClick={()=>openCve(x, ENGINE_TAB)} tabIndex={0}
                      onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&openCve(x, ENGINE_TAB)}>
                    <td><span className="cve-link">{x.cve}</span></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '-'}</td>
                    <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
                    <td><PatchedCell patched_commit={p.commit} patched_version={p.version} project={x.patchmap?.project} /></td>
                    <td><UnpatchedCell unpatched_commits={u.commits} unpatched_version={u.version} project={x.patchmap?.project} /></td>
                    <td>{x.patchmap
                      ? <span
                          className={`pill help ${x.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}
                          title={x.patchmap.confident
                            ? 'Multiple Apple advisories agree on the WebKit bug, a single commit references it, and the vulnerable commit is its exact parent on trunk.'
                            : 'The fix for this bug spans multiple landings, so a single vulnerable parent is ambiguous and the patched/vulnerable commits are withheld.'}
                        >{x.patchmap.confident ? 'HIGH' : 'LOW'}</span>
                      : <span className="pill muted help" title="No WebKit bug was published for this bug (older or non-WebKit), so no patched/vulnerable commit is shown, manual effort needed.">UNRESOLVED</span>}</td>
                  </tr>
                );
              })}
              {itwOrdered.length===0 && <tr><td colSpan={7} className="muted">No WebKit/JSC KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
        {itwOrdered.length > itwLimit && (
          <div style={{ marginTop:10 }}>
            <span className="more-link" role="button" tabIndex={0}
              onClick={()=>setItwLimit(itwOrdered.length)}
              onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&setItwLimit(itwOrdered.length)}>≫ show more ({itwOrdered.length - itwLimit} more)</span>
          </div>
        )}
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

    </>
  );
}

function SmSection({ data, openModal, openCve }) {
  const ENGINE_TAB = 'sm';
  const [itwLimit, setItwLimit] = useState(10);
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
                  <div className="value">{r.version || '-'}</div>
                  <div className="meta">M{r.milestone ?? '-'} · <span className="mono">{r.sm_commit ? r.sm_commit.slice(0,12) : '-'}</span> · {r.updated ? formatDate(r.updated) : '-'}</div>
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
                  <td className="mono">{data.builds.latest.linux.taskId || '-'}</td>
                  <td className="mono">{data.builds.latest.linux.commit ? data.builds.latest.linux.commit.slice(0,12) : '-'}</td>
                  <td>{formatDate(data.builds.latest.linux.created)}</td>
                  <td className="mono">{data.builds.latest.linux.md5 || '-'}</td>
                  <td><a className="btn small" href={data.builds.latest.linux.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* windows */}
              {data.builds?.latest?.win64 && (
                <tr>
                  <td>win64</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.win64.filename}</td>
                  <td className="mono">{data.builds.latest.win64.taskId || '-'}</td>
                  <td className="mono">{data.builds.latest.win64.commit ? data.builds.latest.win64.commit.slice(0,12) : '-'}</td>
                  <td>{formatDate(data.builds.latest.win64.created)}</td>
                  <td className="mono">{data.builds.latest.win64.md5 || '-'}</td>
                  <td><a className="btn small" href={data.builds.latest.win64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}

              {/* mac x64 / arm64 */}
              {data.builds?.latest?.mac?.x64 && (
                <tr>
                  <td>macOS</td>
                  <td>x64</td>
                  <td className="mono">{data.builds.latest.mac.x64.filename}</td>
                  <td className="mono">{data.builds.latest.mac.x64.taskId || '-'}</td>
                  <td className="mono">{data.builds.latest.mac.x64.commit ? data.builds.latest.mac.x64.commit.slice(0,12) : '-'}</td>
                  <td>{formatDate(data.builds.latest.mac.x64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.x64.md5 || '-'}</td>
                  <td><a className="btn small" href={data.builds.latest.mac.x64.download} target="_blank" rel="noreferrer">Download</a></td>
                </tr>
              )}
              {data.builds?.latest?.mac?.arm64 && (
                <tr>
                  <td>macOS</td>
                  <td>arm64</td>
                  <td className="mono">{data.builds.latest.mac.arm64.filename}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.taskId || '-'}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.commit ? data.builds.latest.mac.arm64.commit.slice(0,12) : '-'}</td>
                  <td>{formatDate(data.builds.latest.mac.arm64.created)}</td>
                  <td className="mono">{data.builds.latest.mac.arm64.md5 || '-'}</td>
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

      <DisclosuresSection data={data} engineKey="sm" openCve={openCve} />

      <section className="block">
        <header className="bsub"><h3>// IN-THE-WILD [Firefox/SpiderMonkey]</h3></header>
        <p className="resolver-hint">
          &gt;&gt; known ITW exploited vulnerabilities (non-exhaustive), click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.
        </p>
        <div className="tableWrap">
          <table className="table itw">
            <thead>
              <tr>
                <th>CVE</th><th>Class</th><th>Description</th><th>Fix landed</th>
                <th>Patched</th><th>Vulnerable</th>
                <th className="help" title={"HIGH = verified fix (a single landing fixes this bug, vulnerable is its exact parent)\nLOW  = the fix spans multiple landings, so the single vulnerable parent is ambiguous and the commits are withheld\n-    = no patch map could be resolved for this bug, manual effort needed"}>Mapping confidence</th>
              </tr>
            </thead>
            <tbody>
              {[...(data.cves.itw_related||[])].sort(cmpCveDesc).slice(0,itwLimit).map(x=>{
                const p = coalescePatched(x);
                const u = coalesceUnpatched(x);
                return (
                  <tr key={x.cve} className="rowlink" onClick={()=>openCve(x, ENGINE_TAB)} tabIndex={0}
                      onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&openCve(x, ENGINE_TAB)}>
                    <td><span className="cve-link">{x.cve}</span></td>
                    <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                    <td>{x.shortDescription || x.description || '-'}</td>
                    <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
                    <td><PatchedCell patched_commit={p.commit} patched_version={p.version} project={x.patchmap?.project} /></td>
                    <td><UnpatchedCell unpatched_commits={u.commits} unpatched_version={u.version} project={x.patchmap?.project} /></td>
                    <td>{x.patchmap
                      ? <span
                          className={`pill help ${x.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}
                          title={x.patchmap.confident
                            ? 'A single landing fixes this bug and the vulnerable commit is its exact parent on mozilla-central.'
                            : 'The fix for this bug spans multiple landings, so a single vulnerable parent is ambiguous and the patched/vulnerable commits are withheld, manual effort needed.'}
                        >{x.patchmap.confident ? 'HIGH' : 'LOW'}</span>
                      : <span className="pill muted help" title="No patch map could be resolved for this bug, manual effort needed.">UNRESOLVED</span>}</td>
                  </tr>
                );
              })}
              {(data.cves.itw_related||[]).length===0 && <tr><td colSpan={7} className="muted">No KEV entries.</td></tr>}
            </tbody>
          </table>
        </div>
        {(data.cves.itw_related||[]).length > itwLimit && (
          <div style={{ marginTop:10 }}>
            <span className="more-link" role="button" tabIndex={0}
              onClick={()=>setItwLimit((data.cves.itw_related||[]).length)}
              onKeyDown={e=>(e.key==='Enter'||e.key===' ')&&setItwLimit((data.cves.itw_related||[]).length)}>≫ show more ({(data.cves.itw_related||[]).length - itwLimit} more)</span>
          </div>
        )}
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

/* ------------------ overview (cross-engine) ------------------ */
function channelMap(rel) {
  const m = {};
  for (const r of (rel?.releases || [])) {
    if (r.channel && r.version && !(r.channel in m)) m[r.channel] = r.version;
  }
  return m;
}

function OverviewSection({ chrome, jsc, sm, openCve }) {
  const props = { chrome, jsc, sm };
  const rows = useMemo(() => allItwRows(props), [chrome, jsc, sm]);
  const cov = useMemo(() => coverage(props), [chrome, jsc, sm]);
  const discCov = useMemo(() => disclosureCoverage(props), [chrome, jsc, sm]);
  const taxo = useMemo(() => taxonomy(rows), [rows]);
  const [limit, setLimit] = useState(10);
  const discRows = useMemo(() => allDisclosureRows(props), [chrome, jsc, sm]);
  const [discLimit, setDiscLimit] = useState(10);
  const discHigh = discRows.filter(x => x.patchmap?.confident).length;
  const discWindow = chrome.disclosures?.window_days || jsc.disclosures?.window_days || sm.disclosures?.window_days || 90;

  const totalItw = rows.length;
  const totalHigh = ENGINE_ORDER.reduce((n, k) => n + cov[k].high, 0);
  const chans = {
    chrome: channelMap(chrome.releases),
    jsc:    channelMap(jsc.releases),
    sm:     channelMap(sm.releases),
  };
  const preview = {
    chrome: chans.chrome['Canary'] || chans.chrome['Dev'] || '-',
    jsc:    chans.jsc['STP'] || chans.jsc['Safari Technology Preview'] || chans.jsc['Preview'] || '-',
    sm:     chans.sm['Nightly'] || '-',
  };
  const maxTaxo = Math.max(1, ...taxo.map(t => t.total));
  const freshest = [chrome.cves, jsc.cves, sm.cves]
    .flatMap(c => Object.values(c || {}).flat())
    .map(x => x?.patchmap?.generated).filter(Boolean).sort().pop();

  return (
    <>
      <section className="block">
        <div className="bhead"><h2>// OVERVIEW</h2><span className="tag">all engines</span></div>
        <p className="resolver-hint"></p>

        <div className="statrow">
          <div className="stat"><div className="label">Engines tracked</div><div className="value">3</div><div className="meta">V8 / JSC / SpiderMonkey</div></div>
          <div className="stat"><div className="label">Recent disclosures</div><div className="value">{discRows.length}</div><div className="meta">researcher disclosed bugs, last {discWindow}d</div></div>
          <div className="stat"><div className="label">Known In-the-wild exploit</div><div className="value">{totalItw}</div><div className="meta">CISA KEV [browser scope]</div></div>
          <div className="stat"><div className="label">Mapped coverage</div><div className="value">{(totalItw + discRows.length) ? Math.round(((totalHigh + discHigh) / (totalItw + discRows.length)) * 100) : 0}%</div><div className="meta">verified patch maps across all engines</div></div>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// CURRENT RELEASES</h3></header>
        <div className="tableWrap">
          <table className="table vstrip">
            <thead><tr><th>Engine</th><th>Stable</th><th>Beta</th><th>Preview / Nightly</th><th>Patch-Map Confidence Coverage</th></tr></thead>
            <tbody>
              {ENGINE_ORDER.map(k => (
                <tr key={k}>
                  <td><span className="edot" style={{ background:ENGINES[k].color }} /> {ENGINES[k].label}</td>
                  <td className="mono">{chans[k]['Stable'] || '-'}</td>
                  <td className="mono">{chans[k]['Beta'] || '-'}</td>
                  <td className="mono">{preview[k]}</td>
                  <td className="muted cov-cell">
                    <div>{cov[k].high} high · {cov[k].low} low · {cov[k].unresolved} unresolved [ITW]</div>
                    <div>{discCov[k].high} high · {discCov[k].low} low · {discCov[k].unresolved} unresolved [Disclosures]</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// RECENT DISCLOSURES</h3></header>
        <p className="resolver-hint">&gt;&gt; recent disclosures over the last 90 days, click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.</p>
        <div className="tableWrap">
          <table className="table xtimeline">
            <thead><tr><th>Engine</th><th>CVE</th><th>Class</th><th>Fix landed</th><th>Mapping confidence</th></tr></thead>
            <tbody>
              {discRows.slice(0, discLimit).map((x, i) => (
                <tr key={`${x.engine}-${x.cve}-${i}`} className="rowlink" onClick={() => openCve(x, x.engine)} tabIndex={0}
                    onKeyDown={e => (e.key==='Enter'||e.key===' ') && openCve(x, x.engine)}>
                  <td><span className="epill" style={{ color:ENGINES[x.engine].color, borderColor:'#243149' }}>{ENGINES[x.engine].short}</span></td>
                  <td><span className="mono">{x.cve}</span></td>
                  <td>{disclosureDescClass(x, x.engine).cls}</td>
                  <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
                  <td>{x.patchmap
                    ? <span className={`pill ${x.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}>{x.patchmap.confident ? 'HIGH' : 'LOW'}</span>
                    : <span className="pill muted">UNRESOLVED</span>}</td>
                </tr>
              ))}
              {discRows.length === 0 && <tr><td colSpan={5} className="muted">No disclosures in the current window.</td></tr>}
            </tbody>
          </table>
        </div>
        {discLimit < discRows.length && (
          <div style={{ marginTop:10 }}>
            <span className="more-link" role="button" tabIndex={0} onClick={() => setDiscLimit(l => l + 30)}
              onKeyDown={e => (e.key==='Enter'||e.key===' ') && setDiscLimit(l => l + 30)}>≫ show more ({discRows.length - discLimit} more)</span>
          </div>
        )}
      </section>

      <section className="block">
        <header className="bsub"><h3>// IN-THE-WILD</h3></header>
        <p className="resolver-hint">&gt;&gt; known ITW exploited vulnerabilities (non-exhaustive), click any entry to view the corresponding patch map, diff, regression test (if available), bug tracker and more, verify before use to avoid misleading deltas.</p>
        <div className="tableWrap">
          <table className="table xtimeline">
            <thead><tr><th>Engine</th><th>CVE</th><th>Class</th><th>Fix landed</th><th>Mapping confidence</th></tr></thead>
            <tbody>
              {rows.slice(0, limit).map((x, i) => (
                <tr key={`${x.engine}-${x.cve}-${i}`} className="rowlink" onClick={() => openCve(x, x.engine)} tabIndex={0}
                    onKeyDown={e => (e.key==='Enter'||e.key===' ') && openCve(x, x.engine)}>
                  <td><span className="epill" style={{ color:ENGINES[x.engine].color, borderColor:'#243149' }}>{ENGINES[x.engine].short}</span></td>
                  <td><span className="mono">{x.cve}</span></td>
                  <td>{kevClassFromShort(x.shortDescription || x.description)}</td>
                  <td className="muted">{x.patchmap?.patched_date ? formatDate(x.patchmap.patched_date) : '-'}</td>
                  <td>{x.patchmap
                    ? <span className={`pill ${x.patchmap.confident ? 'conf-hi' : 'conf-lo'}`}>{x.patchmap.confident ? 'HIGH' : 'LOW'}</span>
                    : <span className="pill muted">UNRESOLVED</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {limit < rows.length && (
          <div style={{ marginTop:10 }}>
            <span className="more-link" role="button" tabIndex={0} onClick={() => setLimit(l => l + 30)}
              onKeyDown={e => (e.key==='Enter'||e.key===' ') && setLimit(l => l + 30)}>≫ show more ({rows.length - limit} more)</span>
          </div>
        )}
      </section>

      <section className="block">
        <header className="bsub"><h3>// IN-THE-WILD BUG CLASSES</h3></header>
        <p className="resolver-hint">&gt;&gt; vulnerability class distribution across the ITW (CISA KEV) set only.</p>
        <div className="tableWrap">
          <table className="table taxo">
            <thead><tr><th>Class</th><th>Distribution</th>
              <th style={{ color:ENGINES.chrome.color }}>V8</th>
              <th style={{ color:ENGINES.jsc.color }}>JSC</th>
              <th style={{ color:ENGINES.sm.color }}>SM</th>
              <th>Total</th></tr></thead>
            <tbody>
              {taxo.slice(0, 14).map(t => (
                <tr key={t.cls}>
                  <td>{t.cls}</td>
                  <td>
                    <span className="bar">
                      <span style={{ width:`${(t.chrome/maxTaxo)*100}%`, background:ENGINES.chrome.color }} />
                      <span style={{ width:`${(t.jsc/maxTaxo)*100}%`, background:ENGINES.jsc.color }} />
                      <span style={{ width:`${(t.sm/maxTaxo)*100}%`, background:ENGINES.sm.color }} />
                    </span>
                  </td>
                  <td className="mono">{t.chrome || '·'}</td>
                  <td className="mono">{t.jsc || '·'}</td>
                  <td className="mono">{t.sm || '·'}</td>
                  <td className="mono">{t.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="subline" style={{ marginTop:8 }}><FreshnessBadge when={freshest} /></p>
      </section>
    </>
  );
}

/* ------------------ reference ------------------ */
const JIT_TIERS = [
  { engine:'chrome', interp:'Ignition (bytecode)',        baseline:'Sparkplug',       mid:'Maglev',  opt:'TurboFan' },
  { engine:'jsc',    interp:'LLInt (low-level interp)',   baseline:'Baseline JIT',    mid:'DFG',     opt:'FTL (B3/Air)' },
  { engine:'sm',     interp:'C++ interp / Baseline interp', baseline:'Baseline JIT',  mid:'-',       opt:'WarpMonkey (Ion)' },
];
const MITIGATIONS = {
  chrome: ['V8 Sandbox (heap isolation, in-progress hardening)', 'Pointer compression', 'External pointer table', 'Code pointer sandboxing / CFI', '--jitless option for attack-surface reduction'],
  jsc:    ['Gigacage (bmalloc cage for JS/typed-array heaps)', 'StructureID randomization + entropy', 'JIT cage / fast permissions (APRR on Apple Silicon)', 'WebAssembly fast-memory guard pages', 'Poisoning of sensitive pointers'],
  sm:     ['W^X enforcement on JIT code', 'Project Fission (site isolation)', 'Spectre/JIT hardening + value masking', 'Frozen builtins / sealed intrinsics', 'malloc/jemalloc page protections'],
};
function ReferenceSection() {
  return (
    <>
      <section className="block">
        <div className="bhead"><h2>// REFERENCE</h2><span className="tag">internals</span></div>
        <p className="resolver-hint">&gt;&gt; quick cross-engine reference: JIT pipelines, notable mitigations, machine-readable data feeds, methodology and caveats.</p>
      </section>

      <section className="block">
        <header className="bsub"><h3>// JIT PIPELINES</h3></header>
        <div className="tableWrap">
          <table className="table reftable">
            <thead><tr><th>Engine</th><th>Interpreter</th><th>Baseline</th><th>Mid-tier</th><th>Optimizing</th></tr></thead>
            <tbody>
              {JIT_TIERS.map(t => (
                <tr key={t.engine}>
                  <td><span className="edot" style={{ background:ENGINES[t.engine].color }} /> {ENGINES[t.engine].short}</td>
                  <td className="mono">{t.interp}</td>
                  <td className="mono">{t.baseline}</td>
                  <td className="mono">{t.mid}</td>
                  <td className="mono">{t.opt}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// NOTABLE MITIGATIONS</h3></header>
        <div className="ref-grid">
          {ENGINE_ORDER.map(k => (
            <div className="ref-card" key={k}>
              <div className="ref-card-h"><span className="edot" style={{ background:ENGINES[k].color }} /> {ENGINES[k].short}</div>
              <ul className="ref-list">
                {MITIGATIONS[k].map((m, i) => <li key={i}>{m}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// DATA FEEDS</h3></header>
        <p className="resolver-hint">&gt;&gt; our data is published as machine readable feeds, regenerated on every deploy.</p>
        <div className="refs">
          <span className="l">ITW CVEs (JSON)</span><a href="/api/itw.json">/api/itw.json</a>
          <span className="l">Recent Disclosures (JSON)</span><a href="/api/disclosures.json">/api/disclosures.json</a>
          <span className="l">Patch Maps (JSON)</span><a href="/api/patchmap.json">/api/patchmap.json</a>
          <span className="l">Atom Feed</span><a href="/feed.xml">/feed.xml</a>
        </div>
      </section>

      <section className="block">
        <header className="bsub"><h3>// METHODOLOGY & CAVEATS</h3></header>
        <p className="resolver-hint">&gt;&gt; how each engine resolves a CVE to its patched commit and vulnerable parent, the confidence model, and how the in-the-wild and recent-disclosures sets are selected.</p>
        <div className="refs">
          <span className="l">Mapping</span><a href="/methodology#mapping">/methodology#mapping</a>
          <span className="l">Recent disclosures</span><a href="/methodology#disclosures">/methodology#disclosures</a>
          <span className="l">Caveats</span><a href="/methodology#caveats">/methodology#caveats</a>
        </div>
      </section>
    </>
  );
}

export default function BrowserResearchHub({ chrome, jsc, sm, builtAt }) {
  const [tab, setTab] = useState('overview');
  const [modal, setModal] = useState({ open:false, title:'', content:null });
  const openModal = (title, content) => setModal({ open:true, title, content });
  const closeModal = () => { setModal(s => ({ ...s, open:false })); if (typeof history !== 'undefined') history.replaceState(null, '', location.pathname); };
  const chromeData = { ...chrome, openModal };

  // Open a CVE detail modal and reflect it in the URL hash for deep-linking.
  const openCve = (row, engineKey) => {
    openModal(row.cve, <CveDetail row={row} engineKey={engineKey} />);
    if (typeof history !== 'undefined') history.replaceState(null, '', `#cve=${row.cve}`);
  };

  // On load (and hash change), open the referenced CVE if present.
  useEffect(() => {
    const fromHash = () => {
      const m = (typeof location !== 'undefined' ? location.hash : '').match(/cve=(CVE-\d{4}-\d+)/i);
      if (!m) return;
      const all = [...allItwRows({ chrome, jsc, sm }), ...allDisclosureRows({ chrome, jsc, sm })];
      const hit = all.find(x => x.cve.toLowerCase() === m[1].toLowerCase());
      if (hit) openModal(hit.cve, <CveDetail row={hit} engineKey={hit.engine} />);
    };
    fromHash();
    window.addEventListener('hashchange', fromHash);
    return () => window.removeEventListener('hashchange', fromHash);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="page">
      <Head>
        <title>JS Engine Hub</title>
        <meta name="description" content="A curated surgical dashboard for vulnerability research across modern JavaScript engines, updates daily." />
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
        <meta property="og:description" content="A curated surgical dashboard for vulnerability research across modern JavaScript engines" />
        <meta property="og:url" content="https://jsehub.dev/" />
        <meta property="og:image" content="https://jsehub.dev/og.png" />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="JS Engine Hub" />
        <meta name="twitter:description" content="vulnerability research across V8, SpiderMonkey, and JavaScriptCore." />
        <meta name="twitter:image" content="https://jsehub.dev/og.png" />
      </Head>
      <GlobalStyles/>

      <header className="hero">
        <div className="brand">
          <em />
          <span>JS Engine Hub</span>
        </div>
        <p className="lede">A curated surgical dashboard for vulnerability research across modern JS engines.</p>
        <p className="update-note">
          <UpdateStamp builtAt={builtAt} />
        </p>
        <nav className="tabs" role="tablist" aria-label="Engines">
          <div className="tab-group">
            <button className={`tab ${tab==='overview'?'on':''}`} onClick={()=>setTab('overview')} role="tab" aria-selected={tab==='overview'}>Overview</button>
            <button className={`tab ${tab==='chrome'?'on':''}`} onClick={()=>setTab('chrome')} role="tab" aria-selected={tab==='chrome'}>Chrome / V8</button>
            <button className={`tab ${tab==='sm'?'on':''}`} onClick={()=>setTab('sm')} role="tab" aria-selected={tab==='sm'}>Firefox / SpiderMonkey</button>
            <button className={`tab ${tab==='jsc'?'on':''}`} onClick={()=>setTab('jsc')} role="tab" aria-selected={tab==='jsc'}>Safari / JSC</button>
            <button className={`tab ${tab==='reference'?'on':''}`} onClick={()=>setTab('reference')} role="tab" aria-selected={tab==='reference'}>Reference</button>
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
        {tab==='overview' && <OverviewSection chrome={chrome} jsc={jsc} sm={sm} openCve={openCve}/>}
        {tab==='chrome' && <ChromeSection data={chromeData} openModal={openModal} openCve={openCve}/>}
        {tab==='jsc'    && <JscSection    data={jsc}       openModal={openModal} openCve={openCve}/>}
        {tab==='sm'     && <SmSection     data={sm}        openModal={openModal} openCve={openCve}/>}
        {tab==='reference' && <ReferenceSection/>}
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
export function GlobalStyles() {
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
      .cov-cell div{line-height:1.7;white-space:nowrap}
      .stat{padding:14px 12px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--surface2),#080d14);box-shadow:var(--shadow)}
      .stat .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.14em}
      .stat .value{font-weight:900;margin-top:4px;color:var(--syntax-number)}
      .stat .meta{margin-top:4px;color:var(--muted);font-size:12px}

      /* Tables & lists */
      .tableWrap{overflow-x:auto}
      .table{width:100%;border-collapse:collapse;font-size:12px}
      .table th,.table td{border-bottom:1px solid var(--line);padding:10px 10px;text-align:left;vertical-align:top}
      .table th{color:#cfe0f2;font-weight:700;text-transform:uppercase;letter-spacing:.08em}

      /* KEV table: shrink description column ~20% (scoped so it never hits the overview/reference tables) */
      .table:not(.vstrip):not(.taxo):not(.xtimeline):not(.reftable) th:nth-child(3),
      .table:not(.vstrip):not(.taxo):not(.xtimeline):not(.reftable) td:nth-child(3){
        width:40%;
        max-width:40%;
      }
      /* reference tables: even, content-sized columns */
      .reftable th, .reftable td{width:20%}
      .reftable th:first-child, .reftable td:first-child{width:16%;white-space:nowrap}

      /* ITW tables (CVE / Class / Description / Fix landed / Patched / Vulnerable / Mapping):
         CVE, Fix landed, Patched, Vulnerable, Mapping stay on one line; Description wraps */
      .table.itw th:nth-child(1), .table.itw td:nth-child(1),
      .table.itw th:nth-child(4), .table.itw td:nth-child(4),
      .table.itw th:nth-child(5), .table.itw td:nth-child(5),
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
      /* patchmap confidence */
      .pill.conf-hi{margin-left:0;color:var(--good);background:rgba(100,230,189,.10);border-color:#1f5a47}
      .pill.conf-lo{margin-left:0;color:var(--warn);background:rgba(243,208,119,.08);border-color:#5a4a22}
      .help{cursor:help}
      th.help{text-decoration:underline dotted;text-underline-offset:3px}
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
      .pill.muted{color:var(--muted);margin-left:0;background:rgba(159,176,197,.07);border-color:#2a3650}
      /* centre the mapping-confidence pills */
      .table.itw th:nth-child(7), .table.itw td:nth-child(7){text-align:center}
      .xtimeline th:nth-child(5), .xtimeline td:nth-child(5){text-align:center}

      /* severity pills */
      .pill.sev-crit{color:#ff8a8a;background:rgba(255,138,138,.10);border-color:#5a2330;margin-left:0}
      .pill.sev-high{color:#f3b06b;background:rgba(243,176,107,.10);border-color:#5a4326;margin-left:0}
      .pill.sev-mid{color:var(--muted);background:rgba(159,176,197,.07);border-color:#2a3650;margin-left:0}


      /* engine markers (overview / reference) */
      .edot{display:inline-block;width:9px;height:9px;border-radius:999px;vertical-align:middle;margin-right:7px;box-shadow:0 0 10px rgba(255,255,255,.06)}
      .epill,.cd-tags .pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800;letter-spacing:.04em;background:#0e1626}
      .fresh{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:11px;color:var(--muted);background:#0e1626}

      /* clickable rows / cve ids */
      .rowlink{cursor:pointer}
      .rowlink:hover td{background:rgba(127,240,190,.04)}
      .rowlink:focus{outline:none}
      .rowlink:focus td{background:rgba(127,240,190,.07)}
      .cve-link{cursor:pointer;color:var(--accent);font-weight:700}
      .cve-link:hover{text-decoration:underline dotted}

      /* overview tables */
      .vstrip th:first-child,.vstrip td:first-child{width:30%;white-space:nowrap}
      .vstrip th:nth-child(2),.vstrip td:nth-child(2),
      .vstrip th:nth-child(3),.vstrip td:nth-child(3),
      .vstrip th:nth-child(4),.vstrip td:nth-child(4){width:14%;white-space:nowrap}
      .vstrip th:last-child,.vstrip td:last-child{width:28%}
      .xtimeline td{white-space:nowrap}
      .xtimeline th:nth-child(3),.xtimeline td:nth-child(3){white-space:normal;width:40%}
      .taxo th:first-child,.taxo td:first-child{width:24%;white-space:nowrap}
      .taxo th:nth-child(2),.taxo td:nth-child(2){width:46%}
      .taxo th:nth-child(n+3),.taxo td:nth-child(n+3){width:8%;text-align:right;white-space:nowrap}
      .taxo .bar{display:flex;gap:2px;align-items:center;height:10px;min-width:120px}
      .taxo .bar span{display:block;height:10px;border-radius:2px;min-width:0}

      /* reference cards */
      .ref-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:6px}
      @media(max-width:900px){ .ref-grid{grid-template-columns:1fr} }
      .ref-card{border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--surface2),#080d14);padding:14px;box-shadow:var(--shadow)}
      .ref-card-h{font-weight:900;margin-bottom:8px;display:flex;align-items:center;gap:6px}
      .ref-list{list-style:none;margin:0;padding:0}
      .ref-list li{padding:6px 0;border-bottom:1px dashed var(--line);font-size:13px;color:#cdd9e8}
      .ref-list li:last-child{border-bottom:0}

      /* cve detail modal */
      .cve-detail{display:flex;flex-direction:column;gap:14px}
      .cd-tags{display:flex;gap:8px;flex-wrap:wrap}
      .cd-desc{margin:0;color:#cdd9e8;line-height:1.5}
      .cd-note{margin:0;font-size:12px;line-height:1.5;padding:8px 10px;border:1px solid var(--line);border-left:2px solid #5a4a22;border-radius:8px;background:#0f1422}
      .cd-kv{grid-template-columns:120px 1fr}
      .cd-subj{font-size:12px;color:var(--mono);word-break:break-word}
      .cd-msg-h{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.14em;margin-bottom:5px}
      .cd-fix-h{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
      .cd-fix-act{display:flex;gap:8px;flex-wrap:wrap}
      .cd-fix-foot{margin-top:8px}
      .cd-msg-pre{margin:0;max-height:240px;overflow:auto;padding:10px;border:1px solid var(--line);border-radius:10px;background:#0a0e16;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word;color:#cdd9e8}
      .cd-actions{display:flex;gap:8px;flex-wrap:wrap}
      .btn.trig{color:var(--syntax-string);border-color:#3a3320}
      .cd-links{display:flex;gap:16px;border-top:1px solid var(--line);padding-top:12px;font-size:13px}

      /* inline diff in the CVE modal */
      .diff-loading{font-size:12px;padding:6px 0}
      .diffbox{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#0a0e16}
      .diff-files{padding:8px 10px;border-bottom:1px solid var(--line);display:flex;flex-direction:column;gap:3px}
      .diff-file{display:flex;justify-content:space-between;gap:12px;font-size:12px;align-items:baseline}
      .diff-file .mono{word-break:break-all}
      .diff-stat{white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}
      .diff-stat .add{color:var(--good)}
      .diff-stat .del{color:#ff8a8a}
      .diff-pre{margin:0;max-height:340px;overflow:auto;padding:8px 10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.45;white-space:pre}
      .dl{display:inline}
      .dl-file{color:var(--syntax-func);font-weight:700}
      .dl-hunk{color:var(--syntax-keyword)}
      .dl-add{color:var(--good);background:rgba(100,230,189,.06)}
      .dl-del{color:#ff8a8a;background:rgba(255,138,138,.06)}
      .dl-ctx{color:var(--muted)}
      .diff-trunc{font-size:12px;padding:8px 10px;border-top:1px solid var(--line)}

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
