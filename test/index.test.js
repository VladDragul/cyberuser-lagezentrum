// Tests for src/worker.js and the entry point in src/index.js: source state resolution, the cron run against an
// in-memory KV, and request handling. No test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as src from '../src/sources.js';
import { SOURCE_KEYS } from '../src/render.js';
import {
  resolveSources,
  runCron,
  handleRequest,
  KV_STATE,
  KV_PAGE,
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

const cards = (s) => (s.match(/<article class="slip">/g) ?? []).length;
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

/* ---------- runCron ---------- */

test('runCron on fixtures stores state and page, then falls back per source', async () => {
  const kv = new MemoryKV();
  const env = { LAGE: kv };

  const first = await runCron(NOW, env, { fetchImpl: fixtureFetch(), ...quiet });
  for (const k of SOURCE_KEYS) assert.equal(first.states[k], 'ok', k);
  const state = JSON.parse(kv.store.get(KV_STATE));
  assert.equal(state.v, 1);
  assert.deepEqual(Object.keys(state.sources).sort(), [...SOURCE_KEYS].sort());
  assert.equal(cards(kv.store.get(KV_PAGE)), 29);
  assert.deepEqual(kv.meta.get(KV_PAGE), { generatedAt: NOW });

  // One hour later NVD is down: its copy from the first run is shown as stale
  const later = NOW + HOUR;
  const second = await runCron(later, env, {
    fetchImpl: fixtureFetch({ [src.nvdKevUrl(later)]: () => new Response(null, { status: 503 }) }),
    ...quiet,
  });
  assert.equal(second.states.nvd, 'stale');
  const page = kv.store.get(KV_PAGE);
  assert.ok(page.includes('QUELLE NICHT ERREICHBAR, STAND: 11.11.2026 20:00 UTC'));
  assert.equal(JSON.parse(kv.store.get(KV_STATE)).sources.nvd.asOf, NOW);
  // EUVD was not merged this time, but nothing is shown twice
  assert.equal(cards(page), 29);
});

test('runCron survives a corrupted stored state', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_STATE, '{not json');
  const logs = [];
  const r = await runCron(NOW, { LAGE: kv }, { fetchImpl: fixtureFetch(), log: (l) => logs.push(JSON.parse(l)) });
  assert.equal(r.states.wid, 'ok');
  assert.ok(logs.some((l) => l.source === 'kv' && l.error === 'read_failed'));
  assert.equal(JSON.parse(kv.store.get(KV_STATE)).v, 1);
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
    await worker.scheduled({ scheduledTime: NOW, cron: '0 */6 * * *' }, { LAGE: kv }, {});
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
  }
  assert.deepEqual(kv.meta.get(KV_PAGE), { generatedAt: NOW });
});

/* ---------- handleRequest ---------- */

function assertSecurityHeaders(res) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) assert.equal(res.headers.get(name), value, name);
  assert.match(res.headers.get('cache-control'), /no-transform/);
}

const req = (path, method = 'GET') => new Request(`https://cyberuser.de${path}`, { method });

test('GET /news and /news/ serve the stored page', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_PAGE, '<!doctype html><p>ok</p>');
  for (const path of ['/news', '/news/', '/news?x=1']) {
    const res = await handleRequest(req(path), { LAGE: kv }, quiet);
    assert.equal(res.status, 200, path);
    assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.equal(res.headers.get('cache-control'), PAGE_CACHE_CONTROL);
    assertSecurityHeaders(res);
    assert.equal(await res.text(), '<!doctype html><p>ok</p>');
  }
});

test('HEAD returns headers without a body', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_PAGE, '<p>ok</p>');
  const res = await handleRequest(req('/news', 'HEAD'), { LAGE: kv }, quiet);
  assert.equal(res.status, 200);
  assertSecurityHeaders(res);
  assert.equal(await res.text(), '');
});

test('everything else under the route is 404, other methods are 405', async () => {
  const kv = new MemoryKV();
  kv.store.set(KV_PAGE, '<p>ok</p>');
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

test('no page yet or KV down gives 503 with Retry-After', async () => {
  for (const kv of [new MemoryKV(), new MemoryKV({ failGet: true })]) {
    const res = await handleRequest(req('/news'), { LAGE: kv }, quiet);
    assert.equal(res.status, 503);
    assert.equal(res.headers.get('retry-after'), '600');
    assert.equal(res.headers.get('cache-control'), 'no-store, no-transform');
    assertSecurityHeaders(res);
  }
});

test('entry module has a default export only, as workerd requires', async () => {
  const entry = await import('../src/index.js');
  assert.deepEqual(Object.keys(entry), ['default']);
});
