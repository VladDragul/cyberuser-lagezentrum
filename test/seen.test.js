// PAS B: first-seen times (worker.js) and the NEU mark (render.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { itemKey, isFresh, renderPage, NEW_WINDOW_MS, SOURCE_KEYS } from '../src/render.js';
import { updateSeen, runCron, KV_STATE, KV_PAGE } from '../src/worker.js';
import { FINGERPRINT_RIDGES } from '../src/fingerprint.js';

const NOW = Date.UTC(2026, 10, 11, 20, 17, 0);
const HOUR = 3_600_000;
const DAY = 86_400_000;
const A = 'CVE-2026-10001';
const B = 'CVE-2026-10002';
const C = 'CVE-2026-10003';
const quiet = { log: () => {} };

const kev = (id) => ({ id, title: 'Example product flaw', kevAdded: NOW - DAY, kevDue: null, description: '' });

function view(over = {}) {
  const v = {};
  for (const key of SOURCE_KEYS) v[key] = { state: 'missing', asOf: null, items: [] };
  return { ...v, ...over };
}
const okNvd = (...ids) => ({ nvd: { state: 'ok', asOf: NOW, items: ids.map(kev) } });

const marks = (s) => (s.match(/<span class="print"/g) ?? []).length;
const symbols = (s) => (s.match(/<symbol id="fp"/g) ?? []).length;

/* ---------- itemKey ---------- */

test('itemKey uses the card validators and rejects anything else', () => {
  assert.equal(itemKey('nvd', kev(A)), A);
  assert.equal(itemKey('nvd', { id: '<script>' }), null);
  assert.equal(itemKey('nvd', null), null);
  assert.equal(itemKey('unknown', kev(A)), null);
  assert.equal(itemKey('bits', { link: 'javascript:alert(1)' }), null);
});

/* ---------- updateSeen ---------- */

test('first map for a source is a baseline: nothing is new after a deploy', () => {
  const seen = updateSeen(view(okNvd(A, B)), {}, NOW);
  assert.deepEqual(seen, { nvd: { [A]: 0, [B]: 0 } });
});

test('unknown items get the run time, known items keep theirs, gone items are dropped', () => {
  const seen = updateSeen(view(okNvd(A, C)), { nvd: { [A]: NOW - 5 * HOUR, [B]: NOW - 2 * HOUR } }, NOW);
  assert.deepEqual(seen, { nvd: { [A]: NOW - 5 * HOUR, [C]: NOW } });
});

test('an empty stored map is not a baseline: the next item is new', () => {
  const seen = updateSeen(view(okNvd(A)), { nvd: {} }, NOW);
  assert.deepEqual(seen, { nvd: { [A]: NOW } });
});

test('a missing source keeps its map, a source never seen gets none', () => {
  const prev = { wid: { 'X-1': NOW - HOUR } };
  const seen = updateSeen(view(), prev, NOW);
  assert.deepEqual(seen, { wid: { 'X-1': NOW - HOUR } });
});

test('stored maps are cleaned: bad times dropped, no prototype pollution', () => {
  const prev = JSON.parse(`{"nvd":{"__proto__":{"polluted":1},"${A}":"x","${B}":${NOW + 1},"${C}":-1}}`);
  const seen = updateSeen(view(okNvd(A, B, C)), prev, NOW);
  assert.equal(Object.getPrototypeOf(seen.nvd), Object.prototype);
  assert.equal({}.polluted, undefined);
  for (const t of Object.values(seen.nvd)) assert.ok(t >= 0 && t <= NOW);
});

test('duplicate items are recorded once', () => {
  const seen = updateSeen(view(okNvd(A, A)), { nvd: {} }, NOW);
  assert.deepEqual(seen, { nvd: { [A]: NOW } });
});

/* ---------- isFresh ---------- */

test('isFresh: inside the window only, never for baseline, future or inherited keys', () => {
  const item = kev(A);
  const at = (t) => isFresh({ nvd: { [A]: t } }, 'nvd', item, NOW);
  assert.equal(at(NOW - HOUR), true);
  assert.equal(at(NOW), true);
  assert.equal(at(0), false);
  assert.equal(at(NOW - NEW_WINDOW_MS), false);
  assert.equal(at(NOW + 1), false);
  assert.equal(at('1'), false);
  assert.equal(isFresh({ nvd: {} }, 'nvd', { id: 'toString' }, NOW), false);
  assert.equal(isFresh(undefined, 'nvd', item, NOW), false);
  assert.equal(isFresh({ nvd: [] }, 'nvd', item, NOW), false);
});

/* ---------- renderPage ---------- */

test('NEU cards carry the mark; the fingerprint symbol is defined once', () => {
  const out = renderPage({
    nowMs: NOW,
    sources: okNvd(A, B, C),
    seen: { nvd: { [A]: NOW - HOUR, [B]: NOW - 2 * HOUR, [C]: 0 } },
  });
  assert.equal(marks(out), 2);
  assert.equal(symbols(out), 1);
  assert.equal((out.match(/<path /g) ?? []).length, FINGERPRINT_RIDGES.length);
  assert.ok(!/ style="/.test(out), 'no inline style attributes (CSP style-src self)');
});

test('without new items there is no mark and no symbol', () => {
  for (const seen of [undefined, {}, { nvd: { [A]: 0 } }, { nvd: { [A]: NOW - 2 * DAY } }]) {
    const out = renderPage({ nowMs: NOW, sources: okNvd(A), seen });
    assert.equal(marks(out), 0);
    assert.equal(symbols(out), 0);
  }
});

test('item text cannot fake the mark', () => {
  const item = { ...kev(A), title: '<span class="print">' };
  const out = renderPage({ nowMs: NOW, sources: { nvd: { state: 'ok', asOf: NOW, items: [item] } }, seen: {} });
  assert.equal(marks(out), 0);
  assert.equal(symbols(out), 0);
});

/* ---------- runCron with KV state v3 ---------- */

function memoryKv(initial) {
  const store = new Map(initial === undefined ? [] : [[KV_STATE, JSON.stringify(initial)]]);
  return {
    store,
    async get(key, type) {
      const v = store.get(key) ?? null;
      return type === 'json' && v !== null ? JSON.parse(v) : v;
    },
    async put(key, value) {
      store.set(key, value);
    },
  };
}
const failingFetch = async () => new Response('', { status: 503 });

test('runCron stores seen in state v3 and marks an item new on the page', async () => {
  const asOf = NOW - HOUR;
  const kv = memoryKv({
    v: 3,
    sources: { nvd: { asOf, items: [kev(A)] } },
    attempts: { nvd: asOf },
    seen: { nvd: {} },
  });
  await runCron(NOW, { LAGE: kv }, { fetchImpl: failingFetch, ...quiet });
  const state = JSON.parse(kv.store.get(KV_STATE));
  assert.equal(state.v, 3);
  assert.deepEqual(state.seen.nvd, { [A]: NOW });
  assert.equal(marks(kv.store.get(KV_PAGE)), 1);
});

test('runCron ignores a v2 state: no copies, no seen, nothing marked', async () => {
  const kv = memoryKv({ v: 2, sources: { nvd: { asOf: NOW - HOUR, items: [kev(A)] } }, attempts: {} });
  await runCron(NOW, { LAGE: kv }, { fetchImpl: failingFetch, ...quiet });
  const state = JSON.parse(kv.store.get(KV_STATE));
  assert.equal(state.v, 3);
  assert.deepEqual(state.seen, {});
  assert.equal(marks(kv.store.get(KV_PAGE)), 0);
});
