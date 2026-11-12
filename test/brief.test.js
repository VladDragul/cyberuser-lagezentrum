// Tests for renderBrief in src/render.js: the homepage cards for all six sources.
// Grouping, ordering, limits, validation, source states, escaping, NEU mark, links.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderBrief, SOURCE_KEYS, SOURCE_QUOTAS, MAX_CARDS } from '../src/render.js';

// Same reference time as render.test.js
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);
const DAY = 86_400_000;
const HOUR = 3_600_000;
const EVIL = `<script>alert(1)</script>"'&<img src=x onerror=alert(2)>`;

const ok = (items) => ({ state: 'ok', asOf: NOW, items });

function input(over = {}) {
  const sources = {};
  for (const k of SOURCE_KEYS) sources[k] = ok([]);
  return { nowMs: NOW, sources: { ...sources, ...over } };
}

const count = (s, re) => (s.match(re) ?? []).length;
const rows = (out) => count(out, /<li class="lage-item">/g);
const heads = (out, head) => count(out, new RegExp(`<span>${head}</span>`, 'g'));
const hrefs = (out) => [...out.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
const ids = (out, re) => [...new Set(out.match(re) ?? [])];

// The four official hosts; nothing else, and no internal links
const ALLOWED_HREF =
  /^https:\/\/(?:nvd\.nist\.gov|euvd\.enisa\.europa\.eu|wid\.cert-bund\.de|www\.bsi\.bund\.de)\/[^\s"<>]*$/;

const kev = (n, over = {}) => ({
  source: 'nvd',
  id: `CVE-2026-${1000 + n}`,
  title: `Example flaw ${n}`,
  description: 'An example flaw.',
  kevAdded: NOW - n * DAY,
  cvss: { score: 9.8, version: '3.1' },
  ...over,
});

const euvd = (n, over = {}) => ({
  source: 'euvd',
  id: `EUVD-2026-${1000 + n}`,
  title: `Vendor: Product ${n}`,
  description: 'Another flaw.',
  cves: [`CVE-2026-${5000 + n}`],
  baseScore: 7.5,
  exploitedSince: NOW - n * DAY,
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
  date: NOW - n * HOUR,
  ...over,
});

const bcId = (n) => `12345678-1234-1234-1234-${100000000000 + n}`;
const bc = (n, over = {}) => ({
  source: 'buergercert',
  id: bcId(n),
  title: `Warnung ${n}`,
  description: '',
  date: NOW - n * HOUR,
  ...over,
});

const bitsLink = (n) => `https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2026/w${n}.html`;
const bits = (n, over = {}) => ({
  source: 'bits',
  title: `Meldung ${n}`,
  description: '',
  date: NOW - n * HOUR,
  link: bitsLink(n),
  ...over,
});

const presseLink = (n) => `https://www.bsi.bund.de/DE/Service-Navi/Presse/Pressemitteilungen/Presse2026/p${n}.html`;
const presse = (n, over = {}) => ({
  source: 'presse',
  title: `Pressemitteilung ${n}`,
  description: '',
  date: NOW - n * HOUR,
  link: presseLink(n),
  ...over,
});

const many = (fn, n) => Array.from({ length: n }, (_, i) => fn(i));

const one = () =>
  input({
    nvd: ok([kev(0)]),
    euvd: ok([euvd(0)]),
    wid: ok([wid(0)]),
    buergercert: ok([bc(0)]),
    bits: ok([bits(0)]),
    presse: ok([presse(0)]),
  });

test('every source shows its entries, below its quota all of them', () => {
  const out = renderBrief(
    input({
      nvd: ok(many(kev, 3)),
      euvd: ok(many(euvd, 2)),
      wid: ok(many(wid, 4)),
      buergercert: ok(many(bc, 2)),
      bits: ok(many(bits, 3)),
      presse: ok(many(presse, 1)),
    }),
  );
  assert.equal(heads(out, 'CISA KEV'), 3);
  assert.equal(heads(out, 'ENISA EUVD'), 2);
  assert.equal(heads(out, 'CERT-Bund WID'), 4);
  assert.equal(heads(out, 'Bürger-CERT'), 2);
  assert.equal(heads(out, 'BSI'), 3);
  assert.equal(heads(out, 'BSI Presse'), 1);
  assert.equal(rows(out), 15);
});

test('the last line of a card is never empty', () => {
  const out = renderBrief(one());
  for (const line of [
    'CVE-2026-1000, CVSS 9,8 (v3.1)',
    'CVE-2026-5000, CVSS 7,5',
    'WID-SEC-2026-1000, Schweregrad kritisch',
    'Warnung für Privatanwender',
    'Cybersicherheitswarnung',
    'Presse und Veranstaltungen',
  ]) {
    assert.ok(out.includes(`<p class="lage-id">${line}</p>`), line);
  }
  assert.ok(out.includes('<span class="slip-time"><time datetime="2026-11-11">11.11.2026</time></span>'));

  const bare = renderBrief(input({ nvd: ok([kev(0, { cvss: null, title: '' })]) }));
  assert.ok(bare.includes('>CVE-2026-1000</a></p>'));
  assert.ok(bare.includes('<p class="lage-id">CVE-2026-1000</p>'));
});

test('WID: UNGEPATCHT is marked, and only a literal true counts', () => {
  const marked = renderBrief(input({ wid: ok([wid(0, { severity: 'hoch', status: 'UPDATE', unpatched: true })]) }));
  assert.ok(marked.includes('WID-SEC-2026-1000, Schweregrad hoch, <strong>UNGEPATCHT</strong></p>'));
  assert.ok(!renderBrief(input({ wid: ok([wid(0, { unpatched: 'yes' })]) })).includes('UNGEPATCHT'));
});

test('entries are sorted newest first, whatever the feed order', () => {
  const shuffled = [kev(3), kev(0), kev(5), kev(1), kev(4), kev(2), kev(6)];
  const out = renderBrief(input({ nvd: ok(shuffled) }));
  // The sorted list is dealt into the two columns in turn, so the left column
  // holds the 1st, 3rd, 5th entry and the right column the 2nd, 4th, 6th
  const [left, right] = out.split('<div class="lage-col lage-col-wid">');
  assert.deepEqual(ids(left, /CVE-2026-\d{4}/g), ['CVE-2026-1000', 'CVE-2026-1002', 'CVE-2026-1004', 'CVE-2026-1006']);
  assert.deepEqual(ids(right, /CVE-2026-\d{4}/g), ['CVE-2026-1001', 'CVE-2026-1003', 'CVE-2026-1005']);
});

test('every source keeps its quota, and no more while the others fill theirs', () => {
  assert.deepEqual({ ...SOURCE_QUOTAS }, { nvd: 8, euvd: 2, wid: 14, buergercert: 5, bits: 6, presse: 5 });
  assert.equal(MAX_CARDS, 40);
  assert.equal(
    Object.values(SOURCE_QUOTAS).reduce((a, b) => a + b, 0),
    MAX_CARDS,
    'the quotas add up to the total',
  );
  const out = renderBrief(
    input({
      nvd: ok(many(kev, 30)),
      euvd: ok(many(euvd, 30)),
      wid: ok(many(wid, 30)),
      buergercert: ok(many(bc, 30)),
      bits: ok(many(bits, 30)),
      presse: ok(many(presse, 30)),
    }),
  );
  assert.equal(rows(out), MAX_CARDS);
  for (const [key, head] of [
    ['nvd', 'CISA KEV'],
    ['euvd', 'ENISA EUVD'],
    ['wid', 'CERT-Bund WID'],
    ['buergercert', 'Bürger-CERT'],
    ['bits', 'BSI Presse'],
  ]) {
    if (key === 'bits') continue;
    assert.equal(heads(out, head), SOURCE_QUOTAS[key], head);
  }
  // Only the newest of each source, counted from its own quota
  assert.ok(out.includes('CVE-2026-1007') && !out.includes('CVE-2026-1008'));
});

test('places a source cannot fill go to the others, newest first', () => {
  const out = renderBrief(input({ nvd: ok(many(kev, 30)), wid: ok(many(wid, 2)) }));
  // 40 places, WID brings 2, the other four sources nothing: KEV takes the rest
  assert.equal(rows(out), 32);
  assert.equal(heads(out, 'CISA KEV'), 30);
  assert.equal(heads(out, 'CERT-Bund WID'), 2);
});

test('invalid items are skipped and do not take a place', () => {
  const out = renderBrief(
    input({
      nvd: ok([kev(0, { id: 'CVE-26-1' }), kev(1, { kevAdded: 'yesterday' }), null, 'x', 42, kev(2)]),
      euvd: ok([euvd(0, { id: 'EUVD-1' }), euvd(1, { exploitedSince: null })]),
      wid: ok([wid(0, { severity: 'mittel' }), wid(1, { status: 'NEW' }), wid(2, { id: 'WID-1' }), wid(3, { date: null }), wid(4)]),
      buergercert: ok([{ id: 'not-a-uuid', title: 'T', date: NOW }, bc(1, { title: '' })]),
      bits: ok([bits(0, { title: '' }), bits(1, { date: NaN })]),
    }),
  );
  assert.equal(heads(out, 'CISA KEV'), 1);
  assert.equal(heads(out, 'CERT-Bund WID'), 1);
  assert.equal(rows(out), 2);
  assert.ok(!out.includes('CVE-26-1') && !out.includes('mittel'));
  assert.equal(count(out, /Derzeit keine Einträge\./g), 0, 'the empty text is only for a completely empty page');
});

test('all sources empty: one empty text, no cards', () => {
  const out = renderBrief(input());
  assert.equal(count(out, /Derzeit keine Einträge\./g), 1);
  assert.equal(rows(out), 0);
});

test('missing source: notice only; stale source: entries with the outage notice', () => {
  const missing = renderBrief(input({ nvd: { state: 'missing', items: [kev(0)] } }));
  assert.equal(count(missing, /QUELLE NICHT ERREICHBAR, KEINE DATEN/g), 1);
  assert.ok(missing.includes('<p class="lage-source-state">CISA KEV</p>'), 'the notice names its source');
  assert.ok(!missing.includes('CVE-2026-1000'));
  assert.equal(count(missing, /Derzeit keine Einträge\./g), 0);

  const stale = renderBrief(input({ wid: { state: 'stale', asOf: NOW - DAY, items: [wid(0)] } }));
  assert.ok(stale.includes('QUELLE NICHT ERREICHBAR, STAND: 10.11.2026 21:00 Uhr'));
  assert.ok(stale.includes('WID-SEC-2026-1000'));

  const bad = renderBrief(input({ wid: { state: 'stale', asOf: 'gestern', items: [] } }));
  assert.ok(bad.includes('QUELLE NICHT ERREICHBAR, STAND: UNBEKANNT'));

  for (const s of [{ state: 'weird', items: [wid(0)] }, null, undefined]) {
    const out = renderBrief(input({ wid: s }));
    assert.equal(rows(out), 0);
    assert.equal(count(out, /QUELLE NICHT ERREICHBAR, KEINE DATEN/g), 1);
  }
});

test('no input at all still renders the complete fragment', () => {
  const out = renderBrief();
  assert.ok(out.includes('<aside class="lage"'));
  assert.ok(out.includes('Sicherheitslage'));
  assert.equal(count(out, /QUELLE NICHT ERREICHBAR, KEINE DATEN/g), 6);
  assert.equal(count(out, /Stand: unbekannt/g), 2);
  assert.ok(!out.includes('/news'));
});

test('hostile text is escaped everywhere and hostile links never appear', () => {
  const out = renderBrief(
    input({
      nvd: ok([kev(0, { title: EVIL, description: EVIL, link: 'javascript:alert(1)' })]),
      euvd: ok([euvd(0, { title: EVIL, description: EVIL, link: 'https://evil.example/' })]),
      wid: ok([wid(0, { title: EVIL, description: EVIL, link: 'javascript:alert(1)' })]),
      buergercert: ok([bc(0, { title: EVIL, description: EVIL, link: 'https://evil.example/' })]),
      bits: ok([bits(0, { title: EVIL, link: 'https://evil.example/x.html' })]),
      presse: ok([presse(0, { title: EVIL, link: 'javascript:alert(1)' })]),
    }),
  );
  assert.ok(!out.includes('<script') && !out.includes('<img'));
  assert.ok(out.includes('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;'));
  assert.ok(!out.includes('javascript:'));
  assert.ok(!out.includes('evil.example'));
  assert.equal(rows(out), 6);
  const all = hrefs(out);
  // The two BSI cards lose their link, the other four are rebuilt from IDs
  assert.equal(all.length, 4);
  for (const h of all) assert.match(h, ALLOWED_HREF);
});

test('links go straight to the source, rebuilt from IDs, not taken from stored items', () => {
  const data = one();
  data.sources.nvd.items[0].link = 'https://nvd.nist.gov.evil.example/';
  data.sources.wid.items[0].link = 'https://evil.example/';
  const out = renderBrief(data);
  // The order follows the columns, so compare the set, not the sequence
  assert.deepEqual(hrefs(out).slice().sort(), [
    'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-1000',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-1000',
    `https://wid.cert-bund.de/portal/wid/buergercert/details?uuid=${bcId(0)}`,
    'https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1000',
    presseLink(0),
    bitsLink(0),
  ].sort());
  assert.equal(count(out, /<a class="slip-link" href="[^"]+" rel="noopener noreferrer">/g), 6);
  assert.ok(!out.includes('evil.example'));
  assert.ok(!out.includes('/news'));
});

test('a BSI item with an unsafe link keeps its title without a link', () => {
  const out = renderBrief(input({ bits: ok([bits(0, { title: 'Nur Text', link: 'https://www.bsi.bund.de/%2e%2e/x.html' })]) }));
  assert.ok(out.includes('<p class="lage-title">Nur Text</p>'));
  assert.ok(!out.includes('%2e'));
  assert.equal(hrefs(out).length, 0);
});

test('EUVD entries already covered by KEV are not shown twice', () => {
  const dup = euvd(0, { cves: ['CVE-2026-1000'] });
  const both = renderBrief(input({ nvd: ok([kev(0)]), euvd: { state: 'stale', asOf: NOW, items: [dup, euvd(1)] } }));
  assert.equal(rows(both), 2);
  assert.ok(both.includes('CVE-2026-5001, CVSS 7,5'));
  assert.ok(!both.includes('EUVD-2026-1000'));
  // KEV down: the EUVD copy is the only place the vulnerability appears
  const kevDown = renderBrief(input({ nvd: { state: 'missing' }, euvd: ok([dup]) }));
  assert.equal(rows(kevDown), 1);
});

test('EUVD card lists at most five CVEs, or its own ID when it has none', () => {
  const cves = Array.from({ length: 7 }, (_, i) => `CVE-2026-${2000 + i}`);
  const out = renderBrief(input({ euvd: ok([euvd(0, { cves })]) }));
  assert.ok(out.includes('CVE-2026-2004 (+2), CVSS 7,5'));
  assert.ok(!out.includes('CVE-2026-2005'));
  const none = renderBrief(input({ euvd: ok([euvd(0, { cves: [] })]) }));
  assert.ok(none.includes('<p class="lage-id">EUVD-2026-1000, CVSS 7,5</p>'));
});

test('NEU mark brings its fingerprint definition once; none without NEU', () => {
  const seen = { nvd: { 'CVE-2026-1000': NOW - HOUR }, bits: { [bitsLink(0)]: NOW - HOUR } };
  const marked = renderBrief({ ...input({ nvd: ok([kev(0), kev(1)]), bits: ok([bits(0), bits(1)]) }), seen });
  assert.equal(count(marked, /<span class="print"/g), 2);
  assert.equal(count(marked, /<symbol id="fp"/g), 1);

  const plain = renderBrief(input({ nvd: ok([kev(0), kev(1)]) }));
  assert.ok(!plain.includes('<span class="print"') && !plain.includes('<symbol id="fp"'));
});

test('output is a deterministic fragment, never a page or a script', () => {
  const out = renderBrief(one());
  assert.equal(out, renderBrief(one()));
  assert.ok(out.trimStart().startsWith('<aside'));
  assert.ok(!/<html|<body|<head|<script/i.test(out));
  assert.ok(!/\sstyle=/i.test(out), 'no inline styles (CSP)');
  assert.ok(!out.includes('\u2014'), 'no em dash');
});

test('newest first across all sources, whatever the source', () => {
  // One entry per source, each an hour older than the one before
  const out = renderBrief(
    input({
      wid: ok([wid(0, { date: NOW - HOUR })]),
      buergercert: ok([bc(0, { date: NOW - 2 * HOUR })]),
      bits: ok([bits(0, { date: NOW - 3 * HOUR })]),
      presse: ok([presse(0, { date: NOW - 4 * HOUR })]),
    }),
  );
  const order = ['CERT-Bund WID', 'Bürger-CERT', 'BSI</span>', 'BSI Presse'].map((h) => out.indexOf(`<span>${h}`));
  assert.ok(order.every((p) => p !== -1), 'all four are shown');
  // Two columns, filled in turn: 1st and 3rd on the left, 2nd and 4th on the right
  const [left, right] = out.split('<div class="lage-col lage-col-wid">');
  assert.ok(left.includes('<span>CERT-Bund WID</span>') && left.includes('<span>BSI</span>'));
  assert.ok(right.includes('<span>Bürger-CERT</span>') && right.includes('<span>BSI Presse</span>'));
});

test('a day without a time of day counts as the end of that day', () => {
  // KEV has no time; a WID entry from 10:00 the same day must come after it
  const sameDay = Date.UTC(2026, 10, 11);
  const out = renderBrief(
    input({
      nvd: ok([kev(0, { kevAdded: sameDay })]),
      wid: ok([wid(0, { date: sameDay + 10 * HOUR })]),
    }),
  );
  const [left, right] = out.split('<div class="lage-col lage-col-wid">');
  assert.ok(left.includes('<span>CISA KEV</span>'), 'KEV first');
  assert.ok(right.includes('<span>CERT-Bund WID</span>'), 'WID second');
});

test('two columns of about the same height, both with cards', () => {
  const out = renderBrief(
    input({ nvd: ok(many(kev, 8)), wid: ok(many(wid, 14)), bits: ok(many(bits, 6)) }),
  );
  const [left, right] = out.split('<div class="lage-col lage-col-wid">');
  const l = (left.match(/<li class="lage-item">/g) ?? []).length;
  const r = (right.match(/<li class="lage-item">/g) ?? []).length;
  assert.equal(l + r, 28);
  assert.ok(Math.abs(l - r) <= 2, `columns differ by ${Math.abs(l - r)}`);
  assert.equal(count(out, /<div class="lage-col /g), 2);
  assert.ok(left.includes('id="lage-title"'));
  assert.ok(right.includes('<p class="lage-sources">Quellen: CISA, NIST (NVD), ENISA (EUVD), CERT-Bund, BSI</p>'));
});

test('both columns start with the same Stand line, in German time', () => {
  const out = renderBrief(input());
  assert.equal(
    count(out, /<p class="status">Stand: <time datetime="2026-11-11T20:00:00\.000Z">11\.11\.2026 21:00 Uhr<\/time><\/p>/g),
    2,
  );
});
