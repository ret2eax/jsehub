// Single source of truth for "is this CVE a JS-engine bug?" — shared by the feed
// generator (tools/gen_feeds.js) and the dashboard (pages/index.js) so both
// classify identically.
//
// jsehub tracks JavaScript engines (V8 / JavaScriptCore / SpiderMonkey), but the
// upstream sources (CISA KEV / Apple / Mozilla advisories) are whole-browser, so
// many entries are DOM, graphics, IPC, media, etc. classifyComponent() resolves
// the real component and whether it is the JS engine, using the strongest signal
// available per engine: the resolved patch repo (Chrome), the fix-commit subject
// (JSC), and the advisory component text (Firefox).
//   component        - best-guess component label (e.g. 'V8', 'WebCore', 'GPU')
//   engine_relevant  - true (JS engine) | false (other component) | null (unknown)
// null means "not determinable from the indexed data", never "irrelevant".

export const ENGINE_COMPONENT = { chrome: 'V8', jsc: 'JavaScriptCore', sm: 'SpiderMonkey' };
const DEFAULT_PROJECT = { chrome: 'v8/v8', jsc: 'webkit/webkit', sm: 'mozilla-firefox/firefox' };

// Non-engine components, matched against advisory text / commit subject.
const NON_ENGINE_RE = [
  [/\bangle\b/i, 'ANGLE'], [/\bskia\b/i, 'Skia'], [/\bmojo\b/i, 'Mojo'],
  [/webrtc/i, 'WebRTC'], [/webgpu/i, 'WebGPU'], [/webgl/i, 'WebGL'],
  [/libvpx|\bvp8\b|\bvp9\b/i, 'libvpx'], [/\bwebp\b/i, 'WebP'],
  [/freetype|\bfont\b/i, 'Fonts'], [/webaudio|web audio|audiobuffer|waveshaper/i, 'Web Audio'],
  [/web codecs|audio\/video|\bmedia\b/i, 'Audio/Video'], [/indexed ?db/i, 'IndexedDB'],
  [/network service|networking|\bhttp\b/i, 'Networking'], [/\bcss\b|cssfontface/i, 'CSS'],
  [/\bsvg\b/i, 'SVG'], [/\bxslt\b/i, 'XSLT'], [/readablestream|transformstream|streams?\b/i, 'Streams'],
  [/nsdocshell|docshell|navigation/i, 'DocShell/Navigation'], [/canvas/i, 'Canvas'],
  [/graphics|\btext\b/i, 'Graphics'], [/service ?worker|\bworkers?\b/i, 'Workers'],
  [/sandbox|process sandboxing|gpuprocess|coreipc|\bipc\b/i, 'IPC/Sandbox'],
  [/same[-\s]?origin|firstpartyfor/i, 'Same-Origin'], [/\bblink\b/i, 'Blink'],
  [/\bgpu\b|\bvisuals?\b/i, 'GPU'], [/intents?\b/i, 'Intents'], [/popupblocker/i, 'PopupBlocker'],
  [/portals?\b/i, 'Portals'], [/animation/i, 'Animation'], [/htmldialog|input|didchangevalue/i, 'HTML Forms'],
  [/frameloader|htmlelement|\bdom\b|bindings|webidl|core ?& ?html/i, 'DOM'],
];
// Strong JS-engine signals in a commit subject / advisory component string.
// Substring-prone tokens are word-bounded so an engine term embedded in an
// unrelated identifier (e.g. 'arraybuffer' inside a Gecko media class name like
// ThreadSharedFloatArrayBufferList) does not read as an engine signal.
const JS_ENGINE_RE = /\[jsc\]|javascriptcore|spidermonkey|ionmonkey|javascript engine|javascript:|\bwasm\b|\bwebassembly\b|\bdfg\b|\bftl\b|\byarr\b|\bregexp\b|\bbytecode\b|\bjit\b|\bbbq\b|\bomg\b|\btypedarray\b|\barraybuffer\b|\bbutterfly\b|\bstructureid\b|\bmarked(vector|space)\b/i;

export function classifyComponent(engine, { project, subject, text }) {
  const engineComponent = ENGINE_COMPONENT[engine];
  const subj = String(subject || '');
  const desc = String(text || '');

  // Chrome: the patch resolver already routes non-V8 fixes to chromium/src.
  if (engine === 'chrome') {
    if (project === 'chromium/src') {
      for (const [re, name] of NON_ENGINE_RE) if (re.test(desc)) return { component: name, engine_relevant: false };
      return { component: 'Chromium (non-V8)', engine_relevant: false };
    }
    if (project === 'v8/v8') {
      // Guard against an unresolved entry that names a non-engine component.
      if (!/\bv8\b/i.test(desc)) for (const [re, name] of NON_ENGINE_RE) if (re.test(desc)) return { component: name, engine_relevant: false };
      return { component: 'V8', engine_relevant: true };
    }
  }

  // JSC / SpiderMonkey share a repo with the DOM engine, so project can't
  // separate them; classify from the advisory component text plus the fix-commit
  // subject. Strip the subject's bug-number prefix and reviewer tags first
  // ("Bug 123 - ... r=webidl,emilio" would otherwise match component words like
  // 'webidl'/'dom' on a reviewer's name rather than the actual component).
  const cleanSubj = subj.replace(/^bug\s+\d+\s*[:-]?\s*/i, '').replace(/\br=\S*/gi, '');
  const haystack = `${desc} ${cleanSubj}`;
  // A strong engine signal (JIT, Wasm, DFG/FTL, RegExp, ...) wins over the
  // component label: "JIT miscompilation in the DOM: Core & HTML component" is a
  // SpiderMonkey JIT bug even though Mozilla filed it under a DOM component.
  if (JS_ENGINE_RE.test(haystack)) return { component: engineComponent, engine_relevant: true };
  for (const [re, name] of NON_ENGINE_RE) if (re.test(haystack)) return { component: name, engine_relevant: false };
  // Nothing to go on (e.g. "unspecified WebKit vulnerability", memory-safety rollup).
  return { component: null, engine_relevant: null };
}

// Authoritative engine check from the fix commit's actual changed files. This is
// ground truth (unlike advisory prose): returns true when engine source was
// patched, false when only non-engine components were, or null when indecisive
// (tests-only, shared WTF utilities, or no file list resolved).
export function engineFromFiles(project, paths) {
  if (!paths || !paths.length) return null;
  if (project === 'v8/v8') return paths.some(p => /^(src|include|test)\//.test(p)) ? true : null;
  if (project === 'chromium/src') return paths.some(p => /^v8\//.test(p)) || null;
  if (project === 'webkit/webkit') {
    if (paths.some(p => /Source\/JavaScriptCore\//.test(p))) return true;
    if (paths.some(p => /Source\/(WebCore|WebKit|WebGPU|WebInspector)/.test(p))) return false;
    return null; // WTF-only / LayoutTests-only
  }
  if (project === 'mozilla-firefox/firefox') {
    if (paths.some(p => /(^|\/)js\/(src|public)\//.test(p))) return true;
    if (paths.some(p => /^(dom|content|gfx|layout|netwerk|media|widget|toolkit|security|ipc|caps|docshell|image|xpcom|modules|third_party|intl|parser|editor|accessible)\//.test(p))) return false;
    return null;
  }
  return null;
}

// Row-level convenience: pull the fields off a data/feed row and classify it.
export function componentOf(engine, row) {
  const project = row?.patchmap?.project || DEFAULT_PROJECT[engine];
  return classifyComponent(engine, {
    project,
    subject: row?.patchmap?.subject,
    text: row?.shortDescription || row?.description,
  });
}

// Full classification, using the resolved patch files to break ties the advisory
// text leaves undetermined (e.g. an old CVE with vague KEV wording whose fix
// clearly lands in a non-engine component). Files are consulted only for the
// undetermined case, so a decision the text already makes is never overridden.
export function classifyWithFiles(engine, row, paths) {
  const base = componentOf(engine, row);
  if (base.engine_relevant !== null) return base;
  const project = row?.patchmap?.project || DEFAULT_PROJECT[engine];
  const byFiles = engineFromFiles(project, paths);
  if (byFiles === true) return { component: ENGINE_COMPONENT[engine], engine_relevant: true };
  if (byFiles === false) return { component: base.component || 'non-engine', engine_relevant: false };
  return base;
}

// A JS-engine bug for display purposes: keep confirmed-engine and still-undetermined
// rows, drop what we can confirm is a non-engine component (from advisory text, or
// from the resolved patch files when the text is inconclusive).
export function isEngineBug(engine, row, paths) {
  return classifyWithFiles(engine, row, paths).engine_relevant !== false;
}
