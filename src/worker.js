// Worker logic for /news (Lagezentrum). The runtime entry point is index.js.
//
// scheduled: fetch the sources that are due (NVD every two hours, the rest
//            every hour), keep the last good copy of each in KV,
//            render the page once and store the finished HTML in KV.
// fetch:     serve that HTML for /news and /news/; 404 for anything else.
//
// All heavy work happens in the cron run. A visitor request costs one KV read
// and no parsing or rendering.

import { collectAll, mergeEuvdIntoNvd } from './sources.js';
import { renderPage, SOURCE_KEYS } from './render.js';

/* ---------- Configuration ---------- */

export const KV_STATE = 'state';
export const KV_PAGE = 'page';
const STATE_VERSION = 2;

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

// KEV cards show the EUVD link and EPSS of a matching EUVD entry. Lists are
// stored unmerged, so the merge runs on what is shown, whether it is fresh or a
// fallback copy. render.js still hides EUVD entries already covered by KEV.
export function mergeView(view, log) {
  if (view.nvd.state === 'missing' || view.euvd.state === 'missing') return view;
  try {
    const m = mergeEuvdIntoNvd(view.nvd.items, view.euvd.items);
    log(JSON.stringify({ source: 'merge', mergedIntoNvd: m.merged, euvdOnly: m.euvd.length }));
    return { ...view, nvd: { ...view.nvd, items: m.nvd }, euvd: { ...view.euvd, items: m.euvd } };
  } catch {
    // A malformed stored item must not stop the run; the page is rendered unmerged
    log(JSON.stringify({ source: 'merge', error: 'failed' }));
    return view;
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readState(kv, log) {
  const empty = { sources: {}, attempts: {} };
  try {
    const raw = await kv.get(KV_STATE, 'json');
    if (isPlainObject(raw) && raw.v === STATE_VERSION && isPlainObject(raw.sources) && isPlainObject(raw.attempts)) {
      return { sources: raw.sources, attempts: raw.attempts };
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
  const page = renderPage({ nowMs, sources: mergeView(view, log) });

  // State first: if the page write fails, the next run still has the newest copies.
  // A failed write rejects, so the invocation is reported as failed in Metrics.
  await env.LAGE.put(KV_STATE, JSON.stringify({ v: STATE_VERSION, sources: next, attempts }));
  await env.LAGE.put(KV_PAGE, page, { metadata: { generatedAt: nowMs } });

  const states = {};
  for (const key of SOURCE_KEYS) states[key] = view[key].state;
  const fetched = SOURCE_KEYS.filter((key) => due.has(key));
  const summary = { source: 'cron', chars: page.length, fetched, states };
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

// No visitor data (IP, headers, query) is ever logged here.
export async function handleRequest(request, env, options = {}) {
  const log = options.log ?? ((line) => console.log(line));
  const method = request.method;
  if (method !== 'GET' && method !== 'HEAD') {
    return plain(method, 405, 'Methode nicht erlaubt.\n', { allow: 'GET, HEAD' });
  }
  if (!NEWS_PATHS.has(new URL(request.url).pathname)) return plain(method, 404, 'Nicht gefunden.\n');

  let page = null;
  try {
    page = await env.LAGE.get(KV_PAGE);
  } catch {
    log(JSON.stringify({ source: 'fetch', error: 'kv_get' }));
  }
  if (typeof page !== 'string') {
    return plain(method, 503, 'Das Lagezentrum wird gerade aufgebaut. Bitte später erneut versuchen.\n', {
      'retry-after': '600',
    });
  }
  return respond(method, 200, page, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': PAGE_CACHE_CONTROL,
  });
}
