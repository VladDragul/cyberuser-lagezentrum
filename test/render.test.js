// Tests for src/render.js: the escaping tag, formatting, and the full pipeline
// on the saved fixtures. The cards themselves are covered in brief.test.js.
// No test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import * as src from '../src/sources.js';
import { renderBrief, html, formatDay, formatDateTime, formatDecimal, SOURCE_KEYS } from '../src/render.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

// Same reference time as sources.test.js
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);

const count = (s, re) => (s.match(re) ?? []).length;
const heads = (out, head) => count(out, new RegExp(`<span>${head}</span>`, 'g'));
const hrefs = (out) => [...out.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);

// The four official hosts; nothing else
const ALLOWED_HREF =
  /^https:\/\/(?:nvd\.nist\.gov|euvd\.enisa\.europa\.eu|wid\.cert-bund\.de|www\.bsi\.bund\.de)\/[^\s"<>]*$/;

/* ---------- Escaping tag ---------- */

test('html tag escapes values, keeps nested fragments, drops non-text values', () => {
  const out = html`<p title="${'"x'}">${'<b>'}${html`<i>ok</i>`}${null}${undefined}${false}${{ a: 1 }}${[1, '<']}</p>`;
  assert.equal(out.value, '<p title="&quot;x">&lt;b&gt;<i>ok</i>1&lt;</p>');
});

/* ---------- Formatting ---------- */

test('days are formatted in UTC, date and time in Europe/Berlin', () => {
  const t = Date.UTC(2026, 10, 11, 10, 34, 59);
  assert.equal(formatDay(t), '11.11.2026');
  // Winter: CET is UTC+1
  assert.equal(formatDateTime(t), '11.11.2026 11:34 Uhr');
  assert.equal(formatDateTime(Date.UTC(2026, 0, 5, 3, 7)), '05.01.2026 04:07 Uhr');
  // Summer: CEST is UTC+2
  assert.equal(formatDateTime(Date.UTC(2026, 6, 1, 10, 34)), '01.07.2026 12:34 Uhr');
  // Late in the UTC day it is already the next day in Germany; midnight is 00, not 24
  assert.equal(formatDateTime(Date.UTC(2026, 10, 11, 23, 30)), '12.11.2026 00:30 Uhr');
  assert.equal(formatDay(Date.UTC(2026, 10, 11, 23, 30)), '11.11.2026');
  for (const bad of [NaN, Infinity, 1e20, '1', null, undefined, {}]) {
    assert.equal(formatDay(bad), null);
    assert.equal(formatDateTime(bad), null);
  }
});

test('date and time follow the daylight saving changes', () => {
  // 29 March 2026: clocks go from 02:00 to 03:00 at 01:00 UTC
  assert.equal(formatDateTime(Date.UTC(2026, 2, 29, 0, 59)), '29.03.2026 01:59 Uhr');
  assert.equal(formatDateTime(Date.UTC(2026, 2, 29, 1, 0)), '29.03.2026 03:00 Uhr');
  // 25 October 2026: clocks go from 03:00 back to 02:00 at 01:00 UTC
  assert.equal(formatDateTime(Date.UTC(2026, 9, 25, 0, 59)), '25.10.2026 02:59 Uhr');
  assert.equal(formatDateTime(Date.UTC(2026, 9, 25, 1, 0)), '25.10.2026 02:00 Uhr');
});

test('decimals use a comma, optional trimming of trailing zeros', () => {
  assert.equal(formatDecimal(9.8, 1), '9,8');
  assert.equal(formatDecimal(9, 1), '9,0');
  assert.equal(formatDecimal(12.3, 2, true), '12,3');
  assert.equal(formatDecimal(5, 2, true), '5');
  assert.equal(formatDecimal(0.05, 2, true), '0,05');
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

test('fixtures: collectAll then renderBrief gives the expected cards and only allowed links', async (t) => {
  const r = await src.collectAll(NOW, { fetchImpl: fixtureFetch(), log: () => {} });
  // Same merge as worker.js applies before rendering
  const m = src.mergeEuvdIntoNvd(r.nvd.items, r.euvd.items);
  r.nvd.items = m.nvd;
  r.euvd.items = m.euvd;
  const sources = {};
  for (const k of SOURCE_KEYS) sources[k] = { state: r[k].ok ? 'ok' : 'missing', asOf: NOW, items: r[k].items };

  const started = performance.now();
  const out = renderBrief({ nowMs: NOW, sources });
  t.diagnostic(`render ms (cold): ${(performance.now() - started).toFixed(2)}, bytes: ${out.length}`);

  // 12 KEV + 0 EUVD (all merged into KEV) + 12 WID + 5 Buerger-CERT + 10 BSI + 10 BSI Presse
  assert.equal(heads(out, 'CISA KEV'), 12);
  assert.equal(heads(out, 'ENISA EUVD'), 0);
  assert.equal(heads(out, 'CERT-Bund WID'), 12);
  assert.equal(heads(out, 'Bürger-CERT'), 5);
  assert.equal(heads(out, 'BSI'), 10);
  assert.equal(heads(out, 'BSI Presse'), 10);
  assert.equal(count(out, /<li class="lage-item">/g), 49);
  assert.equal(count(out, /Derzeit keine Einträge\./g), 1);
  assert.equal(count(out, /QUELLE NICHT ERREICHBAR/g), 0);
  assert.ok(!/<script/i.test(out));
  const all = hrefs(out);
  assert.equal(all.length, 49);
  for (const h of all) assert.match(h, ALLOWED_HREF);
});
