// Tests for src/worker.js and the entry point in src/index.js: source state resolution, the cron run against an
// in-memory KV, and request handling. No test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as src from '../src/sources.js';
import { SOURCE_KEYS } from '../src/render.js';
import {
  resolveSources,
  dueSources,
  nextAttempts,
  mergeView,
  runCron,
  handleRequest,
  KV_STATE,
  KV_BRIEF,
  BRIEF_START,
  BRIEF_END,
  BRIEF_MAX_AGE_MS,
  insertBrief,
  STALE_MAX_MS,
  SECURITY_HEADERS,
  PAGE_CACHE_CONTROL,
} from '../src/worker.js';
import worker from '../src/index.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

// Same reference time as the other test files
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);
const HOUR = 3_600_000;

class MemoryKV {
  constructor({ failPut = false, failGet = false } = {}) {
    this.store = new Map();
    this.meta = new Map();
    this.failPut = failPut;
    this.failGet = failGet;
  }
  async get(key, type) {
    if (this.failGet) throw new Error('kv down');
    if (!this.store.has(key)) return null;
    const v = this.store.get(key);
    return type === 'json' ? JSON.parse(v) : v;
  }
  async getWithMetadata(key, type) {
    const value = await this.get(key, type);
    return { value, metadata: value === null ? null : (this.meta.get(key) ?? null) };
  }
  async put(key, value, options) {
    if (this.failPut) throw new Error('kv down');
    this.store.set(key, value);
    if (options?.metadata) this.meta.set(key, options.metadata);
  }
}

function fixtureFetch(overrides = {}) {
  const files = { wid: 'wid.xml', buergercert: 'buergercert.xml', bits: 'bits.xml', presse: 'presse.xml' };
  return async (url) => {
    if (overrides[url]) return overrides[url]();
    if (url.startsWith('https://services.nvd.nist.gov/')) return new Response(fixture('nvd-kev.json'));
    if (url.startsWith('https://euvdservices.enisa.europa.eu/')) return new Response(fixture('euvd-exploited.json'));
    for (const [k, f] of Object.entries(files)) if (url === src.FEEDS[k]) return new Response(fixture(f));
    return new Response(null, { status: 404 });
  };
}

const cards = (s) => (s.match(/<li class="lage-item">/g) ?? []).length;
const quiet = { log: () => {} };

/* ---------- resolveSources ---------- */

test('resolveSources: fresh, stale, expired and unusable copies', () => {
  const item = { id: 'x' };
  const results = {
    nvd: { ok: true, items: [item] },
    euvd: { ok: false, items: [] },
    wid: { ok: false, items: [] },
    buergercert: { ok: false, items: [] },
    bits: { ok: false, items: [] },
    presse: { ok: true, items: 'not an array' },
  };
  const previous = {
    euvd: { asOf: NOW - HOUR, items: [item] },
    wid: { asOf: NOW - STALE_MAX_MS - 1, items: [item] },
    buergercert: { asOf: NOW + HOUR, items: [item] },
    bits: { asOf: 'gestern', items: [item] },
  };
  const { view, next } = resolveSources(results, previous, NOW);
  assert.deepEqual(view.nvd, { state: 'ok', asOf: NOW, items: [item] });
  assert.deepEqual(view.euvd, { state: 'stale', asOf: NOW - HOUR, items: [item] });
  for (const k of ['wid', 'buergercert', 'bits', 'presse']) assert.equal(view[k].state, 'missing', k);
  assert.deepEqual(Object.keys(next).sort(), ['euvd', 'nvd']);
  assert.equal(next.euvd.asOf, NOW - HOUR, 'a stale copy keeps its original date');
});

test('resolveSources: a copy exactly at the age limit is still used', () => {
  const { view } = resolveSources({}, { wid: { asOf: NOW - STALE_MAX_MS, items: [] } }, NOW);
  assert.equal(view.wid.state, 'stale');
});

test('resolveSources: no input at all gives six missing sources', () => {
  const { view, next } = resolveSources(undefined, undefined, NOW);
  for (const k of SOURCE_KEYS) assert.equal(view[k].state, 'missing');
  assert.deepEqual(next, {});
});

test('resolveSources: a source not fetched in this run is current only if its last attempt succeeded', () => {
  const item = { id: 'x' };
  const previous = { nvd: { asOf: NOW - HOUR, items: [item] }, wid: { asOf: NOW - 3 * HOUR, items: [item] } };
  const attempts = { nvd: NOW - HOUR, wid: NOW - HOUR };
  const { view, next } = resolveSources({}, previous, NOW, attempts);
  assert.deepEqual(view.nvd, { state: 'ok', asOf: NOW - HOUR, items: [item] });
  assert.equal(view.wid.state, 'stale', 'the last attempt for wid failed');
  assert.equal(next.nvd.asOf, NOW - HOUR);
});

/* ---------- Schedule ---------- */

test('dueSources: NVD every two hours, the others every hour, with tolerance', () => {
  const all = (t) => Object.fromEntries(SOURCE_KEYS.map((k) => [k, t]));
  assert.deepEqual([...dueSources({}, NOW)], [...SOURCE_KEYS]);
  assert.deepEqual([...dueSources(all(NOW - HOUR), NOW)], SOURCE_KEYS.filter((k) => k !== 'nvd'));
  assert.deepEqual([...dueSources(all(NOW - 2 * HOUR), NOW)], [...SOURCE_KEYS]);
  // A run a few minutes early still counts, more than the tolerance does not
  assert.ok(dueSources(all(NOW - 2 * HOUR + 4 * 60_000), NOW).has('nvd'));
  assert.ok(!dueSources(all(NOW - 2 * HOUR + 6 * 60_000), NOW).has('nvd'));
  // Unusable records make a source due
  assert.ok(dueSources({ nvd: NOW + HOUR }, NOW).has('nvd'));
  assert.ok(dueSources({ nvd: 'gestern' }, NOW).has('nvd'));
});

test('nextAttempts records fetched sources, failures included, and keeps the rest', () => {
  const results = { wid: { ok: false, items: [] }, bits: { ok: true, items: [] } };
  const n = nextAttempts(results, { nvd: NOW - HOUR, euvd: NOW + HOUR, presse: 'x' }, NOW);
  assert.deepEqual(n, { nvd: NOW - HOUR, wid: NOW, bits: NOW });
});

test('mergeView merges a stale KEV copy with fresh EUVD and survives malformed items', () => {
  const view = {
    nvd: { state: 'stale', asOf: NOW - HOUR, items: [{ id: 'CVE-2026-0001' }] },
    euvd: {
      state: 'ok',
      asOf: NOW,
      items: [
        { id: 'EUVD-2026-1', link: 'a', epss: 1, cves: ['CVE-2026-0001'] },
        { id: 'EUVD-2026-2', link: 'b', epss: 2, cves: ['CVE-2026-0002'] },
      ],
    },
  };
  const m = mergeView(view, () => {});
  assert.equal(m.nvd.state, 'stale');
  assert.equal(m.nvd.items[0].euvd.id, 'EUVD-2026-1');
  assert.deepEqual(m.euvd.items.map((i) => i.id), ['EUVD-2026-2']);
  assert.equal(view.nvd.items[0].euvd, undefined, 'the input view is not changed');

  const logs = [];
  const broken = { ...view, euvd: { ...view.euvd, items: [null] } };
  assert.equal(mergeView(broken, (l) => logs.push(JSON.parse(l))), broken);
  assert.ok(logs.some((l) => l.source === 'merge' && l.error === 'failed'));

  const missing = { ...view, nvd: { state: 'missing', asOf: null, items: [] } };
  assert.equal(mergeView(missing, () => {}), missing);
});

/* ---------- runCron ---------- */

test('runCron on fixtures stores state and brief, then falls back per source', async () => {
  const kv = new MemoryKV();
  const env = { LAGE: kv };

  const first = await runCron(NOW, env, { fetchImpl: fixtureFetch(), ...quiet });
  for (const k of SOURCE_KEYS) assert.equal(first.states[k], 'ok', k);
  const state = JSON.parse(kv.store.get(KV_STATE));
  assert.equal(state.v, 3);
  assert.deepEqual(state.attempts, Object.fromEntries(SOURCE_KEYS.map((k) => [k, NOW])));
  assert.deepEqual(Object.keys(state.sources).sort(), [...SOURCE_KEYS].sort());
  assert.equal(cards(kv.store.get(KV_BRIEF)), 40);
  assert.deepEqual(kv.meta.get(KV_BRIEF), { generatedAt: NOW });

  // Two hours later NVD is due again but down: its copy from the first run is shown as stale
  const later = NOW + 2 * HOUR;
  const second = await runCron(later, env, {
    fetchImpl: fixtureFetch({ [src.nvdKevUrl(later)]: () => new Response(null, { status: 503 }) }),
    ...quiet,
  });
  assert.equal(second.states.nvd, 'stale');
  const brief = kv.store.get(KV_BRIEF);
  assert.ok(brief.includes('QUELLE NICHT ERREICHBAR, STAND: 11.11.2026 21:00 Uhr'));
  assert.equal(JSON.parse(kv.store.get(KV_STATE)).sources.nvd.asOf, NOW);
  // The stale KEV copy is still merged with the fresh EUVD list, so nothing is shown twice
  assert.equal(cards(brief), 40);
});

test('runCron one hour later fetches everything except NVD and shows NVD as current', async () => {
  const kv = new MemoryKV();
  const env = { LAGE: kv };
  await runCron(NOW, env, { fetchImpl: fixtureFetch(), ...quiet });

  const nvdHost = new URL(src.nvdKevUrl(NOW)).host;
  const calls = [];
  const inner = fixtureFetch();
  const counting = async (...args) => {
    calls.push(String(args[0]));
    return inner(...args);
  };
  const later = NOW + HOUR;
  const r = await runCron(later, env, { fetchImpl: counting, ...quiet });
  assert.deepEqual(r.fetched, SOURCE_KEYS.filter((k) => k !== 'nvd'));
  assert.ok(!calls.some((u) => new URL(u).host === nvdHost), 'no request to NVD');
  assert.equal(r.states.nvd, 'ok');
  const state = JSON.parse(kv.store.get(KV_STATE));
  assert.equal(state.attempts.nvd, NOW);
  assert.equal(state.attempts.wid, later);
  assert.equal(state.sources.nvd.asOf, NOW);
  assert.equal(cards(kv.store.get(KV_BRIEF)), 40);
});

test('runCron does not retry a failed NVD request before two hours', async () => {
  const kv = new MemoryKV();
  const env = { LAGE: kv };
  const down = fixtureFetch({ [src.nvdKevUrl(NOW)]: () => new Response(null, { status: 503 }) });
  const first = await runCron(NOW, env, { fetchImpl: down, ...quiet });
  assert.equal(first.states.nvd, 'missing');

  const second = await runCron(NOW + HOUR, env, { fetchImpl: fixtureFetch(), ...quiet });
  assert.ok(!second.fetched.includes('nvd'));
  assert.equal(second.states.nvd, 'missing');

  const third = await runCron(NOW + 2 * HOUR, env, { fetchImpl: fixtureFetch(), ...quiet });
  assert.ok(third.fetched.includes('nvd'));
  assert.equal(third.states.nvd, 'ok');
});

test('runCron ignores a stored state of the previous version and fetches everything', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_STATE, JSON.stringify({ v: 1, sources: {} }));
  const logs = [];
  const r = await runCron(NOW, { LAGE: kv }, { fetchImpl: fixtureFetch(), log: (l) => logs.push(JSON.parse(l)) });
  assert.deepEqual(r.fetched, [...SOURCE_KEYS]);
  assert.ok(logs.some((l) => l.source === 'kv' && l.error === 'unexpected_shape'));
});

test('runCron survives a corrupted stored state', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_STATE, '{not json');
  const logs = [];
  const r = await runCron(NOW, { LAGE: kv }, { fetchImpl: fixtureFetch(), log: (l) => logs.push(JSON.parse(l)) });
  assert.equal(r.states.wid, 'ok');
  assert.ok(logs.some((l) => l.source === 'kv' && l.error === 'read_failed'));
  assert.equal(JSON.parse(kv.store.get(KV_STATE)).v, 3);
});

test('runCron rejects when KV cannot be written', async () => {
  const env = { LAGE: new MemoryKV({ failPut: true }) };
  await assert.rejects(runCron(NOW, env, { fetchImpl: fixtureFetch(), ...quiet }));
});

test('scheduled handler uses the planned time, not the clock', async () => {
  const kv = new MemoryKV();
  const realFetch = globalThis.fetch;
  globalThis.fetch = fixtureFetch();
  const realLog = console.log;
  console.log = () => {};
  try {
    await worker.scheduled({ scheduledTime: NOW, cron: '17 * * * *' }, { LAGE: kv }, {});
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
  }
  assert.deepEqual(kv.meta.get(KV_BRIEF), { generatedAt: NOW });
});

/* ---------- handleRequest ---------- */

function assertSecurityHeaders(res) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) assert.equal(res.headers.get(name), value, name);
  assert.match(res.headers.get('cache-control'), /no-transform/);
}

const req = (path, method = 'GET') => new Request(`https://cyberuser.de${path}`, { method });

test('GET /news and /news/ redirect to the homepage without reading KV', async () => {
  for (const path of ['/news', '/news/', '/news?x=1']) {
    const res = await handleRequest(req(path), { LAGE: new MemoryKV({ failGet: true }) }, quiet);
    assert.equal(res.status, 301, path);
    assert.equal(res.headers.get('location'), '/', path);
    assert.equal(res.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.equal(res.headers.get('cache-control'), PAGE_CACHE_CONTROL);
    assertSecurityHeaders(res);
    assert.match(await res.text(), /Startseite/);
  }
});

test('HEAD /news redirects without a body', async () => {
  const res = await handleRequest(req('/news', 'HEAD'), { LAGE: new MemoryKV() }, quiet);
  assert.equal(res.status, 301);
  assert.equal(res.headers.get('location'), '/');
  assertSecurityHeaders(res);
  assert.equal(await res.text(), '');
});

test('everything else under the route is 404, other methods are 405', async () => {
  const kv = new MemoryKV();
  for (const path of ['/news/terminal.js', '/newsletter', '/news/x', '/news//']) {
    const res = await handleRequest(req(path), { LAGE: kv }, quiet);
    assert.equal(res.status, 404, path);
    assertSecurityHeaders(res);
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    const res = await handleRequest(req('/news', method), { LAGE: kv }, quiet);
    assert.equal(res.status, 405, method);
    assert.equal(res.headers.get('allow'), 'GET, HEAD');
    assertSecurityHeaders(res);
  }
});

test('entry module has a default export only, as workerd requires', async () => {
  const entry = await import('../src/index.js');
  assert.deepEqual(Object.keys(entry), ['default']);
});

/* ---------- Homepage ---------- */

const BRIEF = '<aside class="lage">Sicherheitslage</aside>';
const HOME = `<!doctype html><html><body><main>${BRIEF_START}\n<p>Die Sicherheitslage wird geladen.</p>\n${BRIEF_END}</main></body></html>`;
const HOME_WITH_BRIEF = `<!doctype html><html><body><main>${BRIEF_START}\n${BRIEF}${BRIEF_END}</main></body></html>`;

// Same headers as the real nginx answer for /
const NGINX_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'content-security-policy': SECURITY_HEADERS['content-security-policy'],
  'cache-control': 'public, max-age=300, no-transform',
  etag: '"6af4775c-edb"',
  'last-modified': 'Wed, 11 Nov 2026 14:10:36 GMT',
};

// Stand-in for nginx behind the tunnel; records the methods it was asked for
function origin(body = HOME, { status = 200, headers = NGINX_HEADERS } = {}) {
  const calls = [];
  const fetchImpl = async (request) => {
    calls.push(request.method);
    return new Response(request.method === 'HEAD' ? null : body, { status, headers });
  };
  return { fetchImpl, calls };
}

function briefKV(value = BRIEF, generatedAt = NOW) {
  const kv = new MemoryKV();
  kv.store.set(KV_BRIEF, value);
  // null = no metadata at all (undefined would select the default above)
  if (generatedAt !== null) kv.meta.set(KV_BRIEF, { generatedAt });
  return kv;
}

const home = (kv, o, method = 'GET') =>
  handleRequest(req('/', method), { LAGE: kv }, { ...quiet, fetchImpl: o.fetchImpl, nowMs: NOW });

test('insertBrief needs exactly one start marker followed by one end marker', () => {
  assert.equal(insertBrief(HOME, BRIEF), HOME_WITH_BRIEF);
  assert.equal(insertBrief('<p>no markers</p>', BRIEF), null);
  assert.equal(insertBrief(`${BRIEF_START}<p>`, BRIEF), null);
  assert.equal(insertBrief(`<p>${BRIEF_END}`, BRIEF), null);
  assert.equal(insertBrief(`${BRIEF_END}x${BRIEF_START}`, BRIEF), null);
  assert.equal(insertBrief(`${BRIEF_START}${BRIEF_START}${BRIEF_END}`, BRIEF), null);
  assert.equal(insertBrief(`${BRIEF_START}${BRIEF_END}${BRIEF_END}`, BRIEF), null);
  // No replacement patterns: the brief is copied as it is
  assert.ok(insertBrief(HOME, '$& $1 $$').includes('$& $1 $$'));
});

test('GET / puts the brief into the homepage and keeps the nginx headers', async () => {
  const o = origin();
  const res = await home(briefKV(), o);
  assert.equal(res.status, 200);
  assert.equal(await res.text(), HOME_WITH_BRIEF);
  assert.equal(res.headers.get('content-security-policy'), NGINX_HEADERS['content-security-policy']);
  assert.equal(res.headers.get('cache-control'), NGINX_HEADERS['cache-control']);
  assert.equal(res.headers.get('etag'), null);
  assert.equal(res.headers.get('last-modified'), null);
  assert.equal(res.headers.get('content-length'), null);
  assert.deepEqual(o.calls, ['GET']);
});

test('homepage fails open: unchanged page whenever the brief cannot be used', async () => {
  const noMarkers = '<!doctype html><p>no markers</p>';
  const cases = [
    ['no brief', new MemoryKV(), HOME],
    ['KV down', new MemoryKV({ failGet: true }), HOME],
    ['brief too old', briefKV(BRIEF, NOW - BRIEF_MAX_AGE_MS - 1), HOME],
    ['brief from the future', briefKV(BRIEF, NOW + 2 * HOUR), HOME],
    ['no metadata', briefKV(BRIEF, null), HOME],
    ['page without markers', briefKV(), noMarkers],
  ];
  for (const [name, kv, body] of cases) {
    const res = await home(kv, origin(body));
    assert.equal(res.status, 200, name);
    assert.equal(await res.text(), body, name);
    assert.equal(res.headers.get('etag'), NGINX_HEADERS.etag, name);
  }
});

test('homepage: non-200 or non-HTML origin answers pass through unchanged', async () => {
  const notFound = await home(briefKV(), origin('<p>404</p>', { status: 404 }));
  assert.equal(notFound.status, 404);
  assert.equal(await notFound.text(), '<p>404</p>');

  const text = await home(briefKV(), origin(HOME, { headers: { 'content-type': 'text/plain' } }));
  assert.equal(await text.text(), HOME);
});

test('homepage: HEAD and other methods go to nginx and come back unchanged', async () => {
  const head = origin();
  const h = await home(briefKV(), head, 'HEAD');
  assert.equal(h.status, 200);
  assert.equal(await h.text(), '');
  assert.deepEqual(head.calls, ['HEAD']);

  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    const o = origin('<p>405</p>', { status: 405, headers: { ...NGINX_HEADERS, allow: 'GET, HEAD' } });
    const res = await home(briefKV(), o, method);
    assert.equal(res.status, 405, method);
    assert.equal(await res.text(), '<p>405</p>', method);
    assert.deepEqual(o.calls, [method]);
  }
});

test('homepage: unreachable origin gives 502 without caching', async () => {
  const down = { fetchImpl: async () => { throw new Error('tunnel down'); } };
  const res = await home(briefKV(), down);
  assert.equal(res.status, 502);
  assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
  assertSecurityHeaders(res);
});

test('/news never calls the origin', async () => {
  const o = origin();
  const res = await handleRequest(req('/news'), { LAGE: new MemoryKV() }, { ...quiet, fetchImpl: o.fetchImpl });
  assert.equal(res.status, 301);
  assert.deepEqual(o.calls, []);
});

test('runCron also stores the homepage brief with its time', async () => {
  const kv = new MemoryKV();
  await runCron(NOW, { LAGE: kv }, { fetchImpl: fixtureFetch(), ...quiet });
  assert.ok(kv.store.get(KV_BRIEF).startsWith('<aside class="lage"'));
  assert.deepEqual(kv.meta.get(KV_BRIEF), { generatedAt: NOW });
});
