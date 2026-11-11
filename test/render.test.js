// Tests for src/render.js: escaping, formatting, source states, link rebuilding,
// and the full pipeline on the saved fixtures. No test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import * as src from '../src/sources.js';
import {
  renderPage,
  html,
  formatDay,
  formatDateTime,
  formatDecimal,
  ACTIONS,
  SOURCE_KEYS,
  STYLE_HREF,
} from '../src/render.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

// Same reference time as sources.test.js
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);
const EVIL = `<script>alert(1)</script>"'&<img src=x onerror=alert(2)>`;

const ok = (items) => ({ state: 'ok', asOf: NOW, items });

function input(overrides = {}) {
  const sources = {};
  for (const k of SOURCE_KEYS) sources[k] = ok([]);
  return { nowMs: NOW, sources: { ...sources, ...overrides } };
}

const count = (s, re) => (s.match(re) ?? []).length;
const cards = (out) => count(out, /<article class="slip">/g);
const hrefs = (out) => [...out.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);

// Internal paths, the footer badge, and the five official hosts; nothing else
const ALLOWED_HREF =
  /^(?:\/[A-Za-z0-9._?=\/-]*|https:\/\/internet\.nl\/|https:\/\/cyberuser\.de\/news|https:\/\/(?:nvd\.nist\.gov|euvd\.enisa\.europa\.eu|wid\.cert-bund\.de|www\.bsi\.bund\.de)\/[^\s"<>]*)$/;

const kev = (over = {}) => ({
  source: 'nvd',
  id: 'CVE-2026-1234',
  title: 'Example Remote Code Execution',
  description: 'An example flaw.',
  kevAdded: Date.UTC(2026, 10, 10),
  kevDue: Date.UTC(2026, 11, 1),
  cvss: { score: 9.8, version: '3.1' },
  euvd: { id: 'EUVD-2026-5678', link: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-5678', epss: 12.3 },
  date: Date.UTC(2026, 10, 10),
  link: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234',
  ...over,
});

const wid = (over = {}) => ({
  source: 'wid',
  id: 'WID-SEC-2026-1001',
  title: 'Produkt: Mehrere Schwachstellen',
  description: 'Ein Angreifer kann Code ausführen.',
  status: 'NEU',
  unpatched: false,
  severity: 'kritisch',
  date: Date.UTC(2026, 10, 11, 10, 34),
  link: 'https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1001',
  ...over,
});

const euvd = (over = {}) => ({
  source: 'euvd',
  id: 'EUVD-2026-9999',
  title: 'Vendor: Product',
  description: 'Another flaw.',
  cves: ['CVE-2026-9999'],
  baseScore: 7.5,
  epss: 0.5,
  exploitedSince: Date.UTC(2026, 10, 9),
  date: Date.UTC(2026, 10, 9),
  link: 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-9999',
  ...over,
});

const bsi = (over = {}) => ({
  source: 'bits',
  title: 'Warnung vor Phishing',
  description: '',
  date: Date.UTC(2026, 10, 11, 8, 0),
  link: 'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2026/x.html',
  ...over,
});

/* ---------- Escaping tag ---------- */

test('html tag escapes values, keeps nested fragments, drops non-text values', () => {
  const out = html`<p title="${'"x'}">${'<b>'}${html`<i>ok</i>`}${null}${undefined}${false}${{ a: 1 }}${[1, '<']}</p>`;
  assert.equal(out.value, '<p title="&quot;x">&lt;b&gt;<i>ok</i>1&lt;</p>');
});

/* ---------- Formatting ---------- */

test('dates are formatted in UTC, invalid input gives null', () => {
  const t = Date.UTC(2026, 10, 11, 10, 34, 59);
  assert.equal(formatDay(t), '11.11.2026');
  assert.equal(formatDateTime(t), '11.11.2026 10:34 UTC');
  assert.equal(formatDateTime(Date.UTC(2026, 0, 5, 3, 7)), '05.01.2026 03:07 UTC');
  for (const bad of [NaN, Infinity, 1e20, '1', null, undefined, {}]) {
    assert.equal(formatDay(bad), null);
    assert.equal(formatDateTime(bad), null);
  }
});

test('decimals use a comma, optional trimming of trailing zeros', () => {
  assert.equal(formatDecimal(9.8, 1), '9,8');
  assert.equal(formatDecimal(9, 1), '9,0');
  assert.equal(formatDecimal(12.3, 2, true), '12,3');
  assert.equal(formatDecimal(5, 2, true), '5');
  assert.equal(formatDecimal(0.05, 2, true), '0,05');
});

/* ---------- Page skeleton ---------- */

test('page skeleton: German, site stylesheet, no scripts, all six sections', () => {
  const out = renderPage(input());
  assert.ok(out.startsWith('<!doctype html>\n<html lang="de">'));
  assert.ok(out.includes(`<link rel="stylesheet" href="${STYLE_HREF}">`));
  assert.ok(!/<script/i.test(out));
  assert.ok(!/\sstyle=/i.test(out), 'no inline styles (CSP)');
  assert.ok(out.includes('Stand: <time datetime="2026-11-11T20:00:00.000Z">11.11.2026 20:00 UTC</time>'));
  assert.ok(out.includes('seit dem 04.11.2026'));
  for (const k of SOURCE_KEYS) assert.ok(out.includes(`<section class="fp-section" id="${k}"`), k);
  assert.equal(cards(out), 0);
  assert.ok(!out.includes('\u2014'), 'no em dash');
});

test('rendering is deterministic', () => {
  const i = input({ nvd: ok([kev()]), wid: ok([wid()]), bits: ok([bsi()]) });
  assert.equal(renderPage(i), renderPage(i));
});

/* ---------- Hostile and broken input ---------- */

test('hostile text is escaped everywhere and hostile links never appear', () => {
  const out = renderPage(
    input({
      nvd: ok([kev({ title: EVIL, description: EVIL, link: 'javascript:alert(1)' })]),
      euvd: ok([euvd({ title: EVIL, description: EVIL, link: 'https://evil.example/' })]),
      wid: ok([wid({ title: EVIL, description: EVIL, link: 'javascript:alert(1)' })]),
      buergercert: ok([
        { id: '12345678-1234-1234-1234-123456789abc', title: EVIL, description: EVIL, date: NOW, link: 'https://evil.example/' },
      ]),
      bits: ok([bsi({ title: EVIL, link: 'https://evil.example/x.html' })]),
      presse: ok([bsi({ source: 'presse', title: EVIL, link: 'javascript:alert(1)' })]),
    }),
  );
  assert.ok(!out.includes('<script>alert'));
  assert.ok(!out.includes('<img src=x'));
  assert.ok(out.includes('&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;'));
  assert.ok(!out.includes('javascript:'));
  assert.ok(!out.includes('evil.example'));
  assert.equal(cards(out), 4);
  for (const h of hrefs(out)) assert.match(h, ALLOWED_HREF);
});

test('links are rebuilt from IDs, not taken from stored items', () => {
  const out = renderPage(input({ nvd: ok([kev({ link: 'https://nvd.nist.gov.evil.example/' })]) }));
  assert.ok(out.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2026-1234"'));
  assert.ok(out.includes('href="https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-5678"'));
  assert.ok(!out.includes('evil.example'));
});

test('invalid items are dropped, a section with none left shows its empty text', () => {
  const out = renderPage(
    input({
      nvd: ok([kev({ id: 'CVE-26-1' }), kev({ kevAdded: 'yesterday' }), null, 'x', 42]),
      wid: ok([wid({ severity: 'mittel' }), wid({ status: 'NEW' }), wid({ id: 'WID-1' }), wid({ date: null })]),
      buergercert: ok([{ id: 'not-a-uuid', title: 'T', date: NOW }]),
      bits: ok([bsi({ title: '' }), bsi({ date: NaN })]),
    }),
  );
  assert.equal(cards(out), 0);
  assert.ok(out.includes('Im Zeitraum wurden keine neuen Einträge aufgenommen.'));
  assert.ok(out.includes('Im aktuellen Feed stehen keine Hinweise dieser Stufen.'));
});

test('a BSI item with an unsafe link keeps its title without a link', () => {
  const out = renderPage(input({ bits: ok([bsi({ title: 'Nur Text', link: 'https://www.bsi.bund.de/%2e%2e/x.html' })]) }));
  assert.ok(out.includes(': Nur Text</li>'));
  assert.ok(!out.includes('%2e'));
});

test('too many items are capped per section', () => {
  const many = Array.from({ length: 80 }, (_, i) => kev({ id: `CVE-2026-${10000 + i}` }));
  assert.equal(cards(renderPage(input({ nvd: ok(many) }))), 50);
});

/* ---------- Source states ---------- */

test('stale source: items shown with the outage notice and its date', () => {
  const out = renderPage(input({ wid: { state: 'stale', asOf: Date.UTC(2026, 10, 11, 4, 0), items: [wid()] } }));
  assert.ok(out.includes('QUELLE NICHT ERREICHBAR, STAND: 11.11.2026 04:00 UTC'));
  assert.equal(cards(out), 1);
  const bad = renderPage(input({ wid: { state: 'stale', asOf: 'gestern', items: [] } }));
  assert.ok(bad.includes('QUELLE NICHT ERREICHBAR, STAND: UNBEKANNT'));
});

test('missing or unknown state: notice only, items ignored, no empty text', () => {
  for (const s of [{ state: 'missing', items: [wid()] }, { state: 'weird', items: [wid()] }, null, undefined]) {
    const out = renderPage(input({ wid: s }));
    assert.equal(cards(out), 0);
    assert.equal(count(out, /QUELLE NICHT ERREICHBAR, KEINE DATEN/g), 1);
    assert.ok(!out.includes('Im aktuellen Feed stehen keine Hinweise dieser Stufen.'));
  }
});

test('no input at all still renders a complete page', () => {
  const out = renderPage();
  assert.equal(count(out, /QUELLE NICHT ERREICHBAR, KEINE DATEN/g), 6);
  assert.ok(out.includes('Stand: unbekannt'));
  assert.ok(!out.includes('seit dem'));
});

/* ---------- Field content ---------- */

test('KEV card: CVSS, CISA due date, EPSS, NVD and EUVD links, English description', () => {
  const out = renderPage(input({ nvd: ok([kev()]) }));
  assert.ok(out.includes('<dt>TARGET</dt><dd>CVE-2026-1234, CVSS 9,8 (v3.1)</dd>'));
  assert.ok(out.includes('Aktiv ausgenutzt, CISA-Frist <time datetime="2026-12-01">01.12.2026</time>, EPSS 12,3 %'));
  assert.ok(out.includes(`<dd>${ACTIONS.kev}</dd>`));
  assert.ok(out.includes('<p class="noscript" lang="en">An example flaw.</p>'));
  assert.ok(out.includes('<span class="slip-time"><time datetime="2026-11-10">10.11.2026</time></span>'));

  const bare = renderPage(input({ nvd: ok([kev({ cvss: null, euvd: null, kevDue: null, title: '' })]) }));
  assert.ok(bare.includes('<dt>THREAT</dt><dd>CVE-2026-1234</dd>'));
  assert.ok(bare.includes('<dt>TARGET</dt><dd>CVE-2026-1234</dd>'));
  assert.ok(bare.includes('<dt>STATUS</dt><dd>Aktiv ausgenutzt</dd>'));
  assert.ok(!bare.includes('euvd.enisa.europa.eu'));
});

test('WID card: UNGEPATCHT is marked and selects its own action', () => {
  const cases = [
    [wid({ severity: 'kritisch' }), ACTIONS.widCritical, 'Erstmeldung, Schweregrad kritisch</dd>'],
    [wid({ severity: 'hoch' }), ACTIONS.widHigh, 'Erstmeldung, Schweregrad hoch</dd>'],
    [
      wid({ severity: 'hoch', status: 'UPDATE', unpatched: true }),
      ACTIONS.widUnpatched,
      'Aktualisiert, Schweregrad hoch, <strong>UNGEPATCHT</strong></dd>',
    ],
  ];
  for (const [item, action, status] of cases) {
    const out = renderPage(input({ wid: ok([item]) }));
    assert.ok(out.includes(`<dd>${action}</dd>`), action);
    assert.ok(out.includes(status), status);
  }
  // only a literal true counts as unpatched
  assert.ok(!renderPage(input({ wid: ok([wid({ unpatched: 'yes' })]) })).includes('UNGEPATCHT'));
});

test('EUVD entries already covered by KEV are not shown twice', () => {
  const dup = euvd({ cves: ['CVE-2026-1234'] });
  const both = renderPage(input({ nvd: ok([kev()]), euvd: { state: 'stale', asOf: NOW, items: [dup, euvd()] } }));
  assert.equal(cards(both), 2);
  assert.ok(both.includes('CVE-2026-9999, CVSS 7,5'));
  // KEV down: the EUVD copy is the only place the vulnerability appears
  const kevDown = renderPage(input({ nvd: { state: 'missing' }, euvd: ok([dup]) }));
  assert.equal(cards(kevDown), 1);
});

test('EUVD card lists at most five CVEs', () => {
  const cves = Array.from({ length: 7 }, (_, i) => `CVE-2026-${2000 + i}`);
  const out = renderPage(input({ euvd: ok([euvd({ cves })]) }));
  assert.ok(out.includes('CVE-2026-2004 (+2), CVSS 7,5'));
});

/* ---------- Full pipeline on fixtures ---------- */

function fixtureFetch() {
  const files = { wid: 'wid.xml', buergercert: 'buergercert.xml', bits: 'bits.xml', presse: 'presse.xml' };
  return async (url) => {
    if (url.startsWith('https://services.nvd.nist.gov/')) return new Response(fixture('nvd-kev.json'));
    if (url.startsWith('https://euvdservices.enisa.europa.eu/')) return new Response(fixture('euvd-exploited.json'));
    for (const [k, f] of Object.entries(files)) if (url === src.FEEDS[k]) return new Response(fixture(f));
    return new Response(null, { status: 404 });
  };
}

test('fixtures: collectAll then renderPage gives the expected cards and only allowed links', async (t) => {
  const r = await src.collectAll(NOW, { fetchImpl: fixtureFetch(), log: () => {} });
  // Same merge as worker.js applies before rendering
  const m = src.mergeEuvdIntoNvd(r.nvd.items, r.euvd.items);
  r.nvd.items = m.nvd;
  r.euvd.items = m.euvd;
  const sources = {};
  for (const k of SOURCE_KEYS) sources[k] = { state: r[k].ok ? 'ok' : 'missing', asOf: NOW, items: r[k].items };

  const started = performance.now();
  const out = renderPage({ nowMs: NOW, sources });
  t.diagnostic(`render ms (cold): ${(performance.now() - started).toFixed(2)}, bytes: ${out.length}`);

  // 12 KEV + 0 EUVD (all merged into KEV) + 12 WID + 5 Buerger-CERT
  assert.equal(cards(out), 29);
  assert.equal(count(out, /<div class="rules"><ul>/g), 2);
  assert.equal(count(out, /QUELLE NICHT ERREICHBAR/g), 0);
  assert.ok(out.includes('href="https://euvd.enisa.europa.eu/vulnerability/EUVD-'));
  assert.ok(!/<script/i.test(out));
  for (const h of hrefs(out)) assert.match(h, ALLOWED_HREF);
});
