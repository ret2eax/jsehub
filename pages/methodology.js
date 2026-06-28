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
        <meta name="description" content="How JS Engine Hub derives its patch maps and confidence tiers across V8, SpiderMonkey, and JavaScriptCore, and how the in-the-wild and recent-disclosures sets are selected." />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="robots" content="noindex, follow" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </Head>
      <GlobalStyles/>

      <header className="hero">
        <div className="brand"><em /><span>JS Engine Hub</span></div>
        <p className="lede">Methodology: how the patch maps are derived, and how the in-the-wild and recent-disclosures sets are selected.</p>
        <p className="update-note"><Link href="/" className="gh-link">← back to dashboard</Link></p>
      </header>

      <main className="flow">
        <section className="block" id="mapping">
          <div className="bhead"><h2>// APPROACH</h2></div>
          <p className="resolver-hint">&gt;&gt; for each engine the dashboard resolves a CVE to the exact commit that fixed it and the commit immediately before it (the vulnerable parent), so the fix can be diffed and the pre-patch state checked out. Every mapping is derived from public sources and labelled with a confidence tier; nothing is shown unless it can be resolved.</p>
          <p className="resolver-hint" style={{ marginTop:8 }}>The same resolution powers two CVE sets: <strong>in-the-wild</strong> (known-exploited, from CISA KEV) and <strong>recent disclosures</strong> (researcher-reported, patched but not known to be exploited). They share the per-engine chain and confidence model below and differ only in how CVEs are selected, see <a href="#disclosures">recent disclosures</a>.</p>
          <p className="resolver-hint" style={{ marginTop:8 }}>For a small number of in-the-wild CVEs the vendor advisory omits the bug id and no other machine-readable source carries the CVE&nbsp;&rarr;&nbsp;bug link. Where Google Project Zero has published a root-cause analysis for the 0-day, its authoritative bug attribution is used as a last-resort fallback; the bug is then run through the same verifiable bug&nbsp;&rarr;&nbsp;commit&nbsp;&rarr;&nbsp;parent resolution, so a mis-read fails safe (the CVE stays unresolved rather than mapping to a wrong commit).</p>
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
            <div>No fixing commit could be mapped, so nothing is shown. This covers an older pre-disclosure-era CVE, a non-engine component, or a recent disclosure whose fix could not be confidently pinned (for example a restricted bug with no public commit linkage).</div>
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

        <section className="block" id="disclosures">
          <header className="bsub"><h3>// RECENT DISCLOSURES</h3></header>
          <p className="resolver-hint">&gt;&gt; the Recent Disclosures tables use the same per-engine bug → fix-commit → vulnerable-parent resolution and the same HIGH / LOW / UNRESOLVED confidence tiers described above. They differ only in which CVEs are selected: these are researcher-reported bugs that were patched and publicly disclosed but are not (yet) known to be exploited in the wild, so they are not in CISA KEV.</p>
          <p className="subline" style={{ marginTop:10 }}><strong>Selection criteria, applied per engine:</strong></p>
          <ul className="ref-list">
            <li><strong>Window:</strong> a rolling 90-day window by disclosure date (the advisory or release-notes publication, which is when the fix ships).</li>
            <li><strong>Severity:</strong> Critical and High only, using the vendor’s own rating. WebKit publishes no severity, so it is filtered by impact class instead.</li>
            <li><strong>Externally reported:</strong> credited to an outside researcher; internal fuzzing roll-ups (Chrome’s internal finds, Mozilla’s batched “memory safety bugs”) are excluded.</li>
            <li><strong>Exploitation class:</strong> memory-corruption / engine bugs only (use-after-free, type confusion, out-of-bounds, overflow, JIT, WebAssembly, sandbox escape), matching the in-the-wild kind; web-logic, info-leak and spoofing issues are dropped.</li>
          </ul>
          <p className="subline" style={{ marginTop:10 }}><strong>Sources for the CVE → bug step</strong> (the resolution then proceeds exactly as above):</p>
          <ul className="ref-list">
            <li><strong>Chrome / V8:</strong> the Chrome Releases “Stable Channel Update for Desktop” posts, which list the reward, bug id, severity, CVE, title and reporter. The bug is resolved through Gerrit by both its <span className="code">Fixed:</span> (V8) and <span className="code">Bug:</span> (Chromium) commit footers, so a restricted bug-tracker entry still resolves.</li>
            <li><strong>Firefox / SpiderMonkey:</strong> the full set of CVEs in each MFSA advisory (not just the KEV subset), via the same foundation-security-advisories YAML.</li>
            <li><strong>Safari / JavaScriptCore:</strong> Apple’s security-releases index, taking the WebKit / JavaScriptCore-component CVEs from each in-window advisory and their credited reporter. The per-CVE description is synthesised from the fix commit, since Apple’s advisory impact line is generic and the bug is access-restricted.</li>
          </ul>
        </section>

        <section className="block" id="caveats">
          <header className="bsub"><h3>// CAVEATS</h3></header>
          <ul className="ref-list">
            <li>Coverage grows over time: a CVE only resolves once the vendor has published the bug/commit linkage its method depends on. Older in-the-wild CVEs and non-engine components stay blank.</li>
            <li>Some high-severity bugs receive multiple partial fixes or follow-up hardening. This method surfaces the single primary fix and may not capture every related commit.</li>
            <li>Very old bugs (especially pre-2019) have noisier histories and predate some of the bug-to-commit linkage these methods rely on. The vulnerable commit is still the exact parent of the fix, but pinning the single canonical fix can be less certain.</li>
            <li>Reverts, relands and backouts are filtered where possible, but complex landings may still warrant manual review.</li>
            <li>The Safari/JSC table is scoped to WebKit-family components (WebKit, JavaScriptCore) using Apple’s own per-CVE advisory attribution; non-engine Apple CVEs in the same KEV advisories (Kernel, CoreAudio, ImageIO, ...) are excluded since this is a JS-engine dashboard. Pre-2022 WebKit CVEs are also dropped: Apple published no bugzilla ids before then, so no public CVE-to-commit linkage exists and they are systematically unresolvable.</li>
            <li>The JSC map depends on Apple’s advisory HTML format; cross-advisory corroboration makes a format change fail safe (rows drop to blank, never to a wrong commit).</li>
            <li>The in-the-wild set is sourced from CISA KEV and includes only CVEs cataloged there as exploitation evidence emerges; it is not a complete record of all in-the-wild browser or JS-engine exploitation, and is further scoped to engine components.</li>
            <li>The in-the-wild versus disclosure split reflects current public knowledge. A bug shown as a recent disclosure may later be added to CISA KEV if exploitation is discovered; the dashboard reclassifies it on the next build.</li>
            <li>Recent Disclosures is a rolling 90-day window by disclosure date, not a complete disclosure history; older entries age out, and the set is intentionally a recent slice rather than exhaustive.</li>
            <li>Disclosure selection (Critical/High, externally-reported, exploitation-class) is derived from vendor advisories and release notes with pattern-based filters, so it is best-effort rather than exhaustive. Severity is rated per vendor and is not directly comparable across engines.</li>
            <li>For Safari/JSC disclosures the per-CVE description is synthesised from the fix commit (class and component), because Apple’s advisory impact line is generic; it is an inference from the commit, not Apple’s own wording.</li>
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
