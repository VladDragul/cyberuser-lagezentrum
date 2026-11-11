// Worker logic for /news (Lagezentrum). The runtime entry point is index.js.
//
// scheduled: fetch all sources, keep the last good copy of each in KV,
//            render the page once and store the finished HTML in KV.
// fetch:     serve that HTML for /news and /news/; 404 for anything else.
//
// All heavy work happens in the cron run. A visitor request costs one KV read
// and no parsing or rendering.

import { collectAll } from './sources.js';
import { renderPage, SOURCE_KEYS } from './render.js';

/* ---------- Configuration ---------- */

export const KV_STATE = 'state';
export const KV_PAGE = 'page';
const STATE_VERSION = 1;

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

// Pure. Decides per source what the page shows (view) and what is stored for
// the next run (next): fresh data when the fetch worked, otherwise the last good
// copy while it is younger than STALE_MAX_MS, otherwise nothing.
export function resolveSources(results, previous, nowMs) {
  const view = {};
  const next = {};
  for (const key of SOURCE_KEYS) {
    const r = results?.[key];
    const prev = previous?.[key];
    if (r?.ok === true && Array.isArray(r.items)) {
      view[key] = { state: 'ok', asOf: nowMs, items: r.items };
      next[key] = { asOf: nowMs, items: r.items };
    } else if (validCopy(prev, nowMs)) {
      view[key] = { state: 'stale', asOf: prev.asOf, items: prev.items };
      next[key] = { asOf: prev.asOf, items: prev.items };
    } else {
      // Expired or unusable copies are dropped from the stored state
      view[key] = { state: 'missing', asOf: null, items: [] };
    }
  }
  return { view, next };
}

async function readState(kv, log) {
  try {
    const raw = await kv.get(KV_STATE, 'json');
    if (raw !== null && typeof raw === 'object' && raw.v === STATE_VERSION && raw.sources && typeof raw.sources === 'object') {
      return raw.sources;
    }
    if (raw !== null) log(JSON.stringify({ source: 'kv', op: 'get_state', error: 'unexpected_shape' }));
    return {};
  } catch {
    // Unreadable or corrupted JSON: continue as if there were no previous copies
    log(JSON.stringify({ source: 'kv', op: 'get_state', error: 'read_failed' }));
    return {};
  }
}

/* ---------- Cron ---------- */

export async function runCron(nowMs, env, options = {}) {
  const log = options.log ?? ((line) => console.log(line));
  const results = await collectAll(nowMs, { fetchImpl: options.fetchImpl, log });
  const previous = await readState(env.LAGE, log);
  const { view, next } = resolveSources(results, previous, nowMs);
  const page = renderPage({ nowMs, sources: view });

  // State first: if the page write fails, the next run still has the newest copies.
  // A failed write rejects, so the invocation is reported as failed in Metrics.
  await env.LAGE.put(KV_STATE, JSON.stringify({ v: STATE_VERSION, sources: next }));
  await env.LAGE.put(KV_PAGE, page, { metadata: { generatedAt: nowMs } });

  const states = {};
  for (const key of SOURCE_KEYS) states[key] = view[key].state;
  const summary = { source: 'cron', chars: page.length, states };
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
