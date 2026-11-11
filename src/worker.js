// Worker logic for the homepage brief on cyberuser.de. The runtime entry point is index.js.
//
// scheduled: fetch the sources that are due (NVD every two hours, the rest
//            every hour), keep the last good copy of each in KV,
//            render the brief once and store the finished HTML in KV.
// fetch:     for / pass the request to the origin and put the stored brief
//            into the homepage; /news and /news/ (the former page) redirect
//            to /; 404 for anything else.
//
// All heavy work happens in the cron run. A homepage request costs one KV read
// and no parsing or rendering.

import { collectAll, mergeEuvdIntoNvd } from './sources.js';
import { renderBrief, SOURCE_KEYS, itemKey } from './render.js';

/* ---------- Configuration ---------- */

export const KV_STATE = 'state';
export const KV_BRIEF = 'brief';
const STATE_VERSION = 3;

// Minimum time between two fetch attempts per source, failed attempts
// included. NVD asks automated clients to check for updates no more than once
// every two hours (NVD API workflows, "Stay up to date with new data"). The
// tolerance absorbs small differences between planned run times.
export const SOURCE_INTERVAL_MS = Object.freeze({
  nvd: 2 * 3_600_000,
  euvd: 3_600_000,
  wid: 3_600_000,
  buergercert: 3_600_000,
  bits: 3_600_000,
  presse: 3_600_000,
});
export const INTERVAL_TOLERANCE_MS = 5 * 60_000;

// A failed source shows its last good copy for at most this long, then "KEINE DATEN"
export const STALE_MAX_MS = 7 * 86_400_000;

// Same policy as the static site (nginx). HSTS is added by Cloudflare at the edge.
export const SECURITY_HEADERS = Object.freeze({
  'content-security-policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});

// no-transform also stops Cloudflare from injecting its JavaScript Detections snippet
export const PAGE_CACHE_CONTROL = 'public, max-age=300, no-transform';
const ERROR_CACHE_CONTROL = 'no-store, no-transform';

// The former Lagezentrum page; both paths now redirect to the homepage
const NEWS_PATHS = new Set(['/news', '/news/']);

/* ---------- Source state ---------- */

function validCopy(entry, nowMs) {
  return (
    entry !== null &&
    typeof entry === 'object' &&
    typeof entry.asOf === 'number' &&
    Number.isFinite(entry.asOf) &&
    entry.asOf <= nowMs &&
    nowMs - entry.asOf <= STALE_MAX_MS &&
    Array.isArray(entry.items)
  );
}

function validTime(ms, nowMs) {
  return typeof ms === 'number' && Number.isFinite(ms) && ms <= nowMs;
}

// Pure. A source is due when its interval has passed since the last recorded
// attempt, or when there is no usable record (missing, invalid, in the future).
export function dueSources(attempts, nowMs) {
  const due = new Set();
  for (const key of SOURCE_KEYS) {
    const at = attempts?.[key];
    if (!validTime(at, nowMs) || nowMs - at >= SOURCE_INTERVAL_MS[key] - INTERVAL_TOLERANCE_MS) due.add(key);
  }
  return due;
}

// Pure. Records this run as the last attempt for every source it fetched,
// successful or not, and keeps the previous record for the others.
export function nextAttempts(results, attempts, nowMs) {
  const next = {};
  for (const key of SOURCE_KEYS) {
    if (results?.[key] !== undefined) next[key] = nowMs;
    else if (validTime(attempts?.[key], nowMs)) next[key] = attempts[key];
  }
  return next;
}

// Pure. Decides per source what the page shows (view) and what is stored for
// the next run (next): fresh data when the fetch worked, otherwise the last good
// copy while it is younger than STALE_MAX_MS, otherwise nothing. A source that
// was not fetched in this run (not due yet) and whose last attempt succeeded is
// still current, so it is shown as ok with the time of that attempt.
export function resolveSources(results, previous, nowMs, attempts) {
  const view = {};
  const next = {};
  for (const key of SOURCE_KEYS) {
    const r = results?.[key];
    const prev = previous?.[key];
    if (r?.ok === true && Array.isArray(r.items)) {
      view[key] = { state: 'ok', asOf: nowMs, items: r.items };
      next[key] = { asOf: nowMs, items: r.items };
    } else if (validCopy(prev, nowMs)) {
      const current = r === undefined && attempts?.[key] === prev.asOf;
      view[key] = { state: current ? 'ok' : 'stale', asOf: prev.asOf, items: prev.items };
      next[key] = { asOf: prev.asOf, items: prev.items };
    } else {
      // Expired or unusable copies are dropped from the stored state
      view[key] = { state: 'missing', asOf: null, items: [] };
    }
  }
  return { view, next };
}

// An EUVD entry that matches a KEV entry is folded into it, so it is not shown
// twice. Lists are stored unmerged, so the merge runs on what is shown, whether
// it is fresh or a fallback copy. render.js still hides EUVD entries already
// covered by KEV.
export function mergeView(view, log) {
  if (view.nvd.state === 'missing' || view.euvd.state === 'missing') return view;
  try {
    const m = mergeEuvdIntoNvd(view.nvd.items, view.euvd.items);
    log(JSON.stringify({ source: 'merge', mergedIntoNvd: m.merged, euvdOnly: m.euvd.length }));
    return { ...view, nvd: { ...view.nvd, items: m.nvd }, euvd: { ...view.euvd, items: m.euvd } };
  } catch {
    // A malformed stored item must not stop the run; the brief is rendered unmerged
    log(JSON.stringify({ source: 'merge', error: 'failed' }));
    return view;
  }
}

/* ---------- First-seen times for the NEU mark ---------- */

const MAX_SEEN_PER_SOURCE = 500;

// Stored maps come from KV: keep only sane entries
function cleanSeen(map, nowMs) {
  const out = {};
  if (!isPlainObject(map)) return out;
  let n = 0;
  for (const [k, t] of Object.entries(map)) {
    if (n >= MAX_SEEN_PER_SOURCE) break;
    if (k === '__proto__' || k.length > 300) continue;
    if (typeof t !== 'number' || !Number.isFinite(t) || t < 0 || t > nowMs) continue;
    out[k] = t;
    n++;
  }
  return out;
}

// Pure. Records per source when each shown item was first seen. A map holds
// only the items shown now, so it cleans itself.
//   - a source without a map so far: everything gets 0 (never NEU), so a
//     deploy or a state reset does not flag the whole page as new
//   - known item keeps its time, unknown item gets nowMs
//   - a missing source keeps its map, so returning items are not flagged
export function updateSeen(view, previousSeen, nowMs) {
  const next = {};
  for (const key of SOURCE_KEYS) {
    const hasPrev = isPlainObject(previousSeen?.[key]);
    const prev = cleanSeen(previousSeen?.[key], nowMs);
    const v = view?.[key];
    if (!v || v.state === 'missing' || !Array.isArray(v.items)) {
      if (hasPrev) next[key] = prev;
      continue;
    }
    const map = {};
    let n = 0;
    for (const item of v.items) {
      if (n >= MAX_SEEN_PER_SOURCE) break;
      const k = itemKey(key, item);
      if (k === null || Object.hasOwn(map, k)) continue;
      map[k] = !hasPrev ? 0 : Object.hasOwn(prev, k) ? prev[k] : nowMs;
      n++;
    }
    next[key] = map;
  }
  return next;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readState(kv, log) {
  const empty = { sources: {}, attempts: {}, seen: {} };
  try {
    const raw = await kv.get(KV_STATE, 'json');
    if (isPlainObject(raw) && raw.v === STATE_VERSION && isPlainObject(raw.sources) && isPlainObject(raw.attempts)) {
      return { sources: raw.sources, attempts: raw.attempts, seen: isPlainObject(raw.seen) ? raw.seen : {} };
    }
    // Older versions and unexpected shapes are ignored: every source is due once
    if (raw !== null) log(JSON.stringify({ source: 'kv', op: 'get_state', error: 'unexpected_shape' }));
    return empty;
  } catch {
    // Unreadable or corrupted JSON: continue as if there were no previous copies
    log(JSON.stringify({ source: 'kv', op: 'get_state', error: 'read_failed' }));
    return empty;
  }
}

/* ---------- Cron ---------- */

export async function runCron(nowMs, env, options = {}) {
  const log = options.log ?? ((line) => console.log(line));
  // The stored state comes first: it decides which sources are due
  const previous = await readState(env.LAGE, log);
  const due = dueSources(previous.attempts, nowMs);
  const results = await collectAll(nowMs, { fetchImpl: options.fetchImpl, log, only: due });
  const { view, next } = resolveSources(results, previous.sources, nowMs, previous.attempts);
  const attempts = nextAttempts(results, previous.attempts, nowMs);
  // First-seen times use the unmerged lists, so EUVD keys stay stable
  const seen = updateSeen(view, previous.seen, nowMs);
  const merged = mergeView(view, log);
  // The homepage fragment, rendered once per run
  const brief = renderBrief({ nowMs, sources: merged, seen });

  // State first: if the brief write fails, the next run still has the newest copies.
  // A failed write rejects, so the invocation is reported as failed in Metrics.
  await env.LAGE.put(KV_STATE, JSON.stringify({ v: STATE_VERSION, sources: next, attempts, seen }));
  await env.LAGE.put(KV_BRIEF, brief, { metadata: { generatedAt: nowMs } });

  const states = {};
  for (const key of SOURCE_KEYS) states[key] = view[key].state;
  const fetched = SOURCE_KEYS.filter((key) => due.has(key));
  const summary = { source: 'cron', chars: brief.length, fetched, states };
  log(JSON.stringify(summary));
  return summary;
}

/* ---------- Requests ---------- */

function respond(method, status, body, headers) {
  return new Response(method === 'HEAD' ? null : body, { status, headers: { ...SECURITY_HEADERS, ...headers } });
}

function plain(method, status, text, extra = {}) {
  return respond(method, status, text, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': ERROR_CACHE_CONTROL,
    ...extra,
  });
}

/* ---------- Homepage ---------- */

// The brief is shown for at most this long after the cron run that wrote it;
// older means the cron has stopped, and the homepage keeps its own fallback text
export const BRIEF_MAX_AGE_MS = 24 * 3_600_000;
export const BRIEF_START = '<!-- lage:start -->';
export const BRIEF_END = '<!-- lage:end -->';

// These describe the origin body and are wrong once the brief is inserted
const BODY_HEADERS = ['etag', 'last-modified', 'content-length'];

// Put the brief between the markers. null unless the page has exactly one
// start marker followed by exactly one end marker. Built by slicing, so
// nothing in the brief is interpreted as a replacement pattern.
export function insertBrief(pageHtml, brief) {
  const start = pageHtml.indexOf(BRIEF_START);
  const end = pageHtml.indexOf(BRIEF_END);
  if (start === -1 || end === -1 || end < start + BRIEF_START.length) return null;
  if (pageHtml.includes(BRIEF_START, start + 1) || pageHtml.includes(BRIEF_END, end + 1)) return null;
  return pageHtml.slice(0, start + BRIEF_START.length) + '\n' + brief + pageHtml.slice(end);
}

async function readBrief(kv, nowMs, log) {
  try {
    const { value, metadata } = await kv.getWithMetadata(KV_BRIEF);
    const at = metadata?.generatedAt;
    if (typeof value !== 'string' || typeof at !== 'number' || !Number.isFinite(at)) return null;
    if (at > nowMs + INTERVAL_TOLERANCE_MS || nowMs - at > BRIEF_MAX_AGE_MS) return null;
    return value;
  } catch {
    log(JSON.stringify({ source: 'fetch', error: 'kv_get_brief' }));
    return null;
  }
}

// The homepage comes from the origin (nginx on lab01, through the tunnel).
// Only a GET answered with 200 HTML gets the brief; everything else, and every
// failure on the way, passes the origin response through unchanged (fail-open).
async function handleHome(request, env, options, log) {
  const fetchImpl = options.fetchImpl ?? ((r) => fetch(r));
  let origin;
  try {
    origin = await fetchImpl(request);
  } catch {
    log(JSON.stringify({ source: 'fetch', error: 'origin' }));
    return plain(request.method, 502, 'Die Seite ist gerade nicht erreichbar. Bitte später erneut versuchen.\n');
  }
  if (request.method !== 'GET') return origin;
  const type = origin.headers.get('content-type') ?? '';
  if (origin.status !== 200 || !/^text\/html\b/i.test(type)) return origin;

  const body = await origin.text();
  const brief = await readBrief(env.LAGE, options.nowMs ?? Date.now(), log);
  const merged = brief === null ? null : insertBrief(body, brief);
  const headers = new Headers(origin.headers);
  if (merged === null) return new Response(body, { status: origin.status, headers });
  for (const name of BODY_HEADERS) headers.delete(name);
  return new Response(merged, { status: origin.status, headers });
}

// No visitor data (IP, headers, query) is ever logged here.
export async function handleRequest(request, env, options = {}) {
  const log = options.log ?? ((line) => console.log(line));
  const method = request.method;
  // Every method goes to the origin here, so nginx keeps answering and
  // logging non-GET requests exactly as before
  if (new URL(request.url).pathname === '/') return handleHome(request, env, options, log);
  if (method !== 'GET' && method !== 'HEAD') {
    return plain(method, 405, 'Methode nicht erlaubt.\n', { allow: 'GET, HEAD' });
  }
  if (!NEWS_PATHS.has(new URL(request.url).pathname)) return plain(method, 404, 'Nicht gefunden.\n');

  // The cards moved to the homepage. The query string is dropped on purpose:
  // the homepage route is exact, so "/?x=1" would bypass this Worker.
  return respond(method, 301, 'Die Sicherheitslage steht jetzt auf der Startseite: https://cyberuser.de/\n', {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': PAGE_CACHE_CONTROL,
    location: '/',
  });
}
