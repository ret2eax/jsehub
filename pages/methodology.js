import Head from 'next/head';
import Link from 'next/link';
import { GlobalStyles } from './index';

const ENGINE_METHOD = [
  {
    name: 'Chrome / V8',
    color: '#82aaff',
    chain: 'CVE → NVD/MITRE references → Chromium bug id → Gerrit CL (scored) → landed commit + parent',
    steps: [
      'Pull the Chromium/V8 bug id from the CVE’s NVD/MITRE references.',
      'Query Gerrit for merged CLs referencing that bug, scoring each: backports ([M###-LTS], [CfM]), cherry-picks and "Merged:" rank up; reverts, rolls, version bumps, fuzzer and test-only CLs rank down.',
      'Resolve the winning CL to its landed commit and exact parent; if it is a cherry-pick, follow it to the mainline original and use that commit + its parent.',
      'For older fixes that Gerrit’s text search no longer surfaces, fall back to searching the v8/v8 git mirror by bug id and take the real fixing commit + its parent (reverts and dependency rolls dropped, relands preferred).',
    ],
    verify: 'Both ends are public: NVD names the bug, the Gerrit CL names the bug, and the commit/parent are in Gitiles.',
  },
  {
    name: 'Firefox / SpiderMonkey',
    color: '#f3d077',
    chain: 'CVE → MFSA advisory (YAML) → Bugzilla bug → mozilla-central fix commit → parent',
    steps: [
      'Map the CVE to its Bugzilla bug via Mozilla’s authoritative foundation-security-advisories YAML.',
      'Find the fix by searching the mozilla-central git mirror for "Bug <id>", classifying each candidate by the files it changes: backouts and test-only landings are dropped, and multiple parts/uplifts of one fix are collapsed to the original engine-source landing.',
      'Take that commit’s exact git parent as the vulnerable commit.',
    ],
    verify: 'Both ends are public: the advisory YAML names the bug, the commit message names the bug, and the bug is publicly readable once disclosed.',
  },
  {
    name: 'Safari / JavaScriptCore',
    color: '#ff8a8a',
    chain: 'CVE → Apple advisories ("WebKit Bugzilla: N") → WebKit commit referencing the bug → parent',
    steps: [
      'Extract the WebKit Bugzilla id Apple lists for the CVE, binding each CVE to the bug that precedes it within its advisory entry.',
      'Require at least two independent product advisories (iOS, macOS, Safari, tvOS…) to agree on the same bug, which neutralises any single-page parse error.',
      'Find the WebKit commit whose own message references show_bug.cgi?id=N (a single, exact match), collapsing release-branch cherry-picks to their mainline original; take its exact parent.',
    ],
    verify: 'The bug→commit link is public (the commit names the bug) and the CVE→bug link is Apple’s own attribution, corroborated across advisories. WebKit history is linear, so the parent is exact.',
  },
];

export default function Methodology() {
  return (
    <div className="page">
      <Head>
        <title>Methodology · JS Engine Hub</title>
        <meta name="description" content="How JS Engine Hub derives its in-the-wild patch maps and confidence tiers across V8, SpiderMonkey, and JavaScriptCore." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="canonical" href="https://jsehub.dev/methodology" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </Head>
      <GlobalStyles/>

      <header className="hero">
        <div className="brand"><em /><span>JS Engine Hub</span></div>
        <p className="lede">Methodology: how the in-the-wild patch maps are derived.</p>
        <p className="update-note"><Link href="/" className="gh-link">← back to dashboard</Link></p>
      </header>

      <main className="flow">
        <section className="block">
          <div className="bhead"><h2>// APPROACH</h2><span className="tag">patch maps</span></div>
          <p className="resolver-hint">&gt;&gt; for each engine the dashboard resolves a known in-the-wild CVE to the exact commit that fixed it and the commit immediately before it (the vulnerable parent), so the fix can be diffed and the pre-patch state checked out. Every mapping is derived from public sources and labelled with a confidence tier; nothing is shown unless it can be resolved.</p>
        </section>

        <section className="block">
          <header className="bsub"><h3>// MAPPING CONFIDENCE</h3></header>
          <p className="resolver-hint">&gt;&gt; the confidence tier reflects how reliably the patched and vulnerable commits are mapped to a CVE, not the severity of the bug.</p>
          <div className="kv slim" style={{ gridTemplateColumns:'120px 1fr' }}>
            <label><span className="pill conf-hi">HIGH</span></label>
            <div>The fix commit is confidently identified and the vulnerable commit is its exact parent. Safe to diff and bisect.</div>
            <label><span className="pill conf-lo">LOW</span></label>
            <div>A fix was located but spans multiple landings (ambiguous single parent), so the commits are withheld rather than shown misleadingly.</div>
            <label><span className="pill muted">UNRESOLVED</span></label>
            <div>No fixing commit could be mapped (older pre-disclosure-era CVE, or a non-engine component), so nothing is shown.</div>
          </div>
        </section>

        {ENGINE_METHOD.map(e => (
          <section className="block" key={e.name}>
            <header className="bsub"><h3><span className="edot" style={{ background:e.color }} /> {e.name}</h3></header>
            <p className="resolver-hint" style={{ marginTop:8 }}><span className="code">{e.chain}</span></p>
            <ol className="ref-list" style={{ paddingLeft:18, listStyle:'decimal' }}>
              {e.steps.map((s, i) => <li key={i}>{s}</li>)}
            </ol>
            <p className="subline"><strong>Why it is trustworthy:</strong> {e.verify}</p>
          </section>
        ))}

        <section className="block">
          <header className="bsub"><h3>// CAVEATS</h3></header>
          <ul className="ref-list">
            <li>Coverage grows over time: a CVE only resolves once the vendor has published the bug/commit linkage its method depends on. Older in-the-wild CVEs and non-engine components stay blank.</li>
            <li>Some high-severity bugs receive multiple partial fixes or follow-up hardening. This method surfaces the single primary fix and may not capture every related commit.</li>
            <li>Very old bugs (especially pre-2019) have noisier histories and predate some of the bug-to-commit linkage these methods rely on. The vulnerable commit is still the exact parent of the fix, but pinning the single canonical fix can be less certain.</li>
            <li>Reverts, relands and backouts are filtered where possible, but complex landings may still warrant manual review.</li>
            <li>The Safari/JSC table is scoped to WebKit-family components (WebKit, JavaScriptCore) using Apple’s own per-CVE advisory attribution; non-engine Apple CVEs in the same KEV advisories (Kernel, CoreAudio, ImageIO, ...) are excluded since this is a JS-engine dashboard. Pre-2022 WebKit CVEs are also dropped: Apple published no bugzilla ids before then, so no public CVE-to-commit linkage exists and they are systematically unresolvable.</li>
            <li>The JSC map depends on Apple’s advisory HTML format; cross-advisory corroboration makes a format change fail safe (rows drop to blank, never to a wrong commit).</li>
            <li>Always verify a commit at the source before relying on it. Links are provided for exactly that.</li>
          </ul>
        </section>
      </main>

      <footer className="ft muted">
        <div className="ft-copy">{new Date().getFullYear()} JS Engine Hub : minimal surface, maximum signal.</div>
      </footer>
    </div>
  );
}
