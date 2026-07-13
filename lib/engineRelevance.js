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
const JS_ENGINE_RE = /\[jsc\]|javascriptcore|spidermonkey|ionmonkey|javascript engine|javascript:|\bwasm\b|webassembly|\bdfg\b|\bftl\b|\byarr\b|\bregexp\b|bytecode|\bjit\b|\bbbq\b|\bomg\b|typedarray|arraybuffer|butterfly|structureid|marked(vector|space)/i;

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
  // separate them; use the fix-commit subject then the advisory text.
  for (const s of [subj, desc]) {
    if (!s) continue;
    if (JS_ENGINE_RE.test(s)) return { component: engineComponent, engine_relevant: true };
    for (const [re, name] of NON_ENGINE_RE) if (re.test(s)) return { component: name, engine_relevant: false };
  }
  // Nothing to go on (e.g. "unspecified WebKit vulnerability", memory-safety rollup).
  return { component: null, engine_relevant: null };
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

// A JS-engine bug for display purposes: keep confirmed-engine and undetermined
// rows, drop only what we can confirm is a non-engine browser component. This
// avoids hiding real engine bugs that merely lack a resolved fix commit.
export function isEngineBug(engine, row) {
  return componentOf(engine, row).engine_relevant !== false;
}
