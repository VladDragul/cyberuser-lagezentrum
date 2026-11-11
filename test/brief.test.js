// Tests for renderBrief in src/render.js: the short homepage fragment.
// Counts, ordering, validation, source states, escaping, NEU mark, links.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderBrief, renderPage, BRIEF_COUNTS } from '../src/render.js';

// Same reference time as render.test.js
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);
const DAY = 86_400_000;
const EVIL = `<script>alert(1)</script>"'&<img src=x onerror=alert(2)>`;

const ok = (items) => ({ state: 'ok', asOf: NOW, items });
const input = (over = {}) => ({ nowMs: NOW, sources: { nvd: ok([]), wid: ok([]), ...over } });

const count = (s, re) => (s.match(re) ?? []).length;
const rows = (out) => count(out, /<li class="lage-item">/g);
const hrefs = (out) => [...out.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
const ids = (out, re) => [...new Set(out.match(re) ?? [])];

// Internal paths and the official hosts; nothing else
const ALLOWED_HREF = /^(?:\/[A-Za-z0-9._?=#\/-]*|https:\/\/(?:nvd\.nist\.gov|wid\.cert-bund\.de)\/[^\s"<>]*)$/;

const kev = (n, over = {}) => ({
  source: 'nvd',
  id: `CVE-2026-${1000 + n}`,
  title: `Example flaw ${n}`,
  description: 'An example flaw.',
  kevAdded: NOW - n * DAY,
  cvss: { score: 9.8, version: '3.1' },
  ...over,
});

const wid = (n, over = {}) => ({
  source: 'wid',
  id: `WID-SEC-2026-${1000 + n}`,
  title: `Produkt ${n}: Mehrere Schwachstellen`,
  description: 'Ein Angreifer kann Code ausführen.',
  status: 'NEU',
  unpatched: false,
  severity: 'kritisch',
  date: NOW - n * 3_600_000,
  ...over,
});

const many = (fn, n) => Array.from({ length: n }, (_, i) => fn(i));

test('brief shows exactly the configured number of entries per source', () => {
  assert.deepEqual({ ...BRIEF_COUNTS }, { nvd: 5, wid: 5 });
  const out = renderBrief(input({ nvd: ok(many(kev, 10)), wid: ok(many(wid, 10)) }));
  assert.equal(count(out, /CISA KEV/g), 5);
  assert.equal(count(out, /CERT-Bund WID/g), 5);
  assert.equal(rows(out), 10);
});

test('brief sorts newest first, whatever the feed order', () => {
  const shuffled = [kev(3), kev(0), kev(5), kev(1), kev(4), kev(2), kev(6)];
  const out = renderBrief(input({ nvd: ok(shuffled) }));
  assert.deepEqual(ids(out, /CVE-2026-\d{4}/g), ['CVE-2026-1000', 'CVE-2026-1001', 'CVE-2026-1002', 'CVE-2026-1003', 'CVE-2026-1004']);
});

test('invalid items are skipped and do not take a place', () => {
  const nvd = [kev(0, { id: 'CVE-26-1' }), kev(1, { kevAdded: 'yesterday' }), null, 'x', ...many((i) => kev(i + 2), 6)];
  const widItems = [wid(0, { severity: 'mittel' }), wid(1, { status: 'NEW' }), wid(2, { id: 'WID-1' }), ...many((i) => wid(i + 3), 4)];
  const out = renderBrief(input({ nvd: ok(nvd), wid: ok(widItems) }));
  assert.equal(count(out, /CISA KEV/g), 5);
  assert.equal(count(out, /CERT-Bund WID/g), 4);
  assert.ok(!out.includes('CVE-26-1') && !out.includes('mittel'));
});

test('fewer items than the limit: all of them, nothing invented', () => {
  const out = renderBrief(input({ nvd: ok(many(kev, 2)), wid: ok(many(wid, 1)) }));
  assert.equal(rows(out), 3);
});

test('empty ok sources show the empty text for each group', () => {
  const out = renderBrief(input());
  assert.equal(count(out, /Derzeit keine Einträge\./g), 2);
  assert.equal(rows(out), 0);
});

test('missing source: notice only; stale source: items with the outage notice', () => {
  const missing = renderBrief(input({ nvd: { state: 'missing', items: [kev(0)] } }));
  assert.ok(missing.includes('QUELLE NICHT ERREICHBAR, KEINE DATEN'));
  assert.ok(!missing.includes('CVE-2026-1000'));
  assert.equal(count(missing, /Derzeit keine Einträge\./g), 1);

  const stale = renderBrief(input({ wid: { state: 'stale', asOf: NOW - DAY, items: [wid(0)] } }));
  assert.ok(stale.includes('QUELLE NICHT ERREICHBAR, STAND'));
  assert.ok(stale.includes('WID-SEC-2026-1000'));
});

test('hostile text is escaped', () => {
  const out = renderBrief(input({ nvd: ok([kev(0, { title: EVIL })]), wid: ok([wid(0, { title: EVIL })]) }));
  assert.ok(!out.includes('<script') && !out.includes('<img'));
  assert.ok(out.includes('&lt;script&gt;'));
});

test('NEU mark brings its fingerprint definition once; none without NEU', () => {
  const seen = { nvd: { 'CVE-2026-1000': NOW - 3_600_000 } };
  const marked = renderBrief({ ...input({ nvd: ok([kev(0), kev(1)]) }), seen });
  assert.equal(count(marked, /<span class="print"/g), 1);
  assert.equal(count(marked, /<symbol id="fp"/g), 1);

  const plain = renderBrief(input({ nvd: ok([kev(0), kev(1)]) }));
  assert.ok(!plain.includes('<span class="print"') && !plain.includes('<symbol id="fp"'));
});

test('links are internal only; the general /news link shows only when there are no cards', () => {
  const out = renderBrief(input({ nvd: ok(many(kev, 5)), wid: ok(many(wid, 5)) }));
  const all = hrefs(out);
  assert.ok(all.length === 10 && !all.includes('/news'));
  for (const h of all) assert.match(h, ALLOWED_HREF);
  assert.ok(hrefs(renderBrief(input())).includes('/news'));
});

test('no input at all still renders the complete fragment', () => {
  const out = renderBrief();
  assert.ok(out.includes('<aside class="lage"'));
  assert.ok(out.includes('Sicherheitslage'));
  assert.ok(out.includes('Gesamte Lage ansehen'));
});

test('output is a deterministic fragment, never a page or a script', () => {
  const data = input({ nvd: ok(many(kev, 5)), wid: ok(many(wid, 5)) });
  const out = renderBrief(data);
  assert.equal(out, renderBrief(data));
  assert.ok(out.trimStart().startsWith('<aside'));
  assert.ok(!/<html|<body|<head|<script/i.test(out));
});

test('every card links to its own card on /news, with no external link', () => {
  const out = renderBrief(input({ nvd: ok(many(kev, 5)), wid: ok(many(wid, 5)) }));
  const all = hrefs(out);
  assert.equal(count(out, /<a class="slip-link" href="\/news#/g), 10);
  assert.ok(all.includes('/news#nvd-CVE-2026-1000'));
  assert.ok(all.includes('/news#wid-WID-SEC-2026-1000'));
  assert.ok(all.every((h) => h.startsWith('/')));
});

test('two columns: KEV under the heading on one side, CERT-Bund on the other', () => {
  const out = renderBrief(input({ nvd: ok(many(kev, 5)), wid: ok(many(wid, 5)) }));
  assert.equal(count(out, /<div class="lage-col /g), 2);
  const [left, right] = out.split('<div class="lage-col lage-col-wid">');
  assert.ok(left.includes('id="lage-title"') && left.includes('CVE-2026-1000') && !left.includes('WID-SEC'));
  assert.ok(right.includes('WID-SEC-2026-1000') && !right.includes('CVE-2026'));
});

test('every homepage link target exists as a card anchor on /news', () => {
  const data = input({ nvd: ok(many(kev, 5)), wid: ok(many(wid, 5)) });
  const page = renderPage(data);
  const targets = hrefs(renderBrief(data)).filter((h) => h.startsWith('/news#'));
  assert.equal(targets.length, 10);
  for (const h of targets) assert.ok(page.includes(`<li id="${h.slice('/news#'.length)}">`), h);
});

test('both columns start with the same Stand line', () => {
  const out = renderBrief(input());
  assert.equal(count(out, /<p class="status">Stand: /g), 2);
});
