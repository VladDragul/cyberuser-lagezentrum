// Tests for src/sources.js: parsers on the saved real-world fixtures,
// constructed edge cases, and the network layer with a fake fetch.
// No test touches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as src from '../src/sources.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

// Evening of the day the fixtures were saved
const NOW = Date.UTC(2026, 10, 11, 20, 0, 0);
const WINDOW_START = Date.UTC(2026, 10, 4);

/* ---------- Time window and URLs ---------- */

test('window starts at midnight UTC seven days back', () => {
  assert.equal(src.windowStartMs(NOW), WINDOW_START);
  assert.equal(src.windowStartMs(Date.UTC(2026, 10, 11, 0, 0, 0)), WINDOW_START);
  assert.equal(src.windowStartMs(Date.UTC(2026, 10, 11, 23, 59, 59, 999)), WINDOW_START);
});

test('source URLs match the ones the fixtures were saved from', () => {
  assert.equal(
    src.nvdKevUrl(NOW),
    'https://services.nvd.nist.gov/rest/json/cves/2.0?kevStartDate=2026-11-04T00:00:00.000&kevEndDate=2026-11-11T23:59:59.999',
  );
  assert.equal(
    src.euvdSearchUrl(NOW),
    'https://euvdservices.enisa.europa.eu/api/search?exploited=true&fromUpdatedDate=2026-11-04&toUpdatedDate=2026-11-11&size=100&page=0',
  );
  assert.match(src.euvdSearchUrl(NOW, 1), /&page=1$/);
  const sources = fixture('SOURCES.md');
  for (const url of Object.values(src.FEEDS)) assert.ok(sources.includes(url), url);
});

/* ---------- RSS ---------- */

test('parseRss reads only item children, never channel links', () => {
  const xml = `<rss><channel><title>T</title><link>https://evil.example/</link>
    <atom:link href="x"/><item><title>A &amp; B</title><link>L1</link><pubDate>P</pubDate></item>
    <item><title><![CDATA[<b>raw &amp;</b>]]></title></item></channel></rss>`;
  const items = src.parseRss(xml);
  assert.equal(items.length, 2);
  assert.deepEqual(items[0], { title: 'A & B', link: 'L1', description: null, pubDate: 'P' });
  // CDATA is literal: no entity decoding, markup stays text (escaped at render)
  assert.equal(items[1].title, '<b>raw &amp;</b>');
  assert.equal(items[1].link, null);
});

test('parseRss caps the number of items and survives garbage', () => {
  const many = '<item><title>x</title></item>'.repeat(600);
  assert.equal(src.parseRss(many).length, 500);
  assert.deepEqual(src.parseRss('<item><title>unclosed'), []);
  assert.deepEqual(src.parseRss(null), []);
});

/* ---------- WID ---------- */

test('parseWidTitle handles the optional UNGEPATCHT tag', () => {
  assert.deepEqual(src.parseWidTitle('[NEU] [hoch] Composer: Mehrere Schwachstellen'), {
    status: 'NEU',
    unpatched: false,
    severity: 'hoch',
    text: 'Composer: Mehrere Schwachstellen',
  });
  assert.deepEqual(src.parseWidTitle('[UPDATE] [UNGEPATCHT] [hoch] Siemens SIMATIC: X'), {
    status: 'UPDATE',
    unpatched: true,
    severity: 'hoch',
    text: 'Siemens SIMATIC: X',
  });
  for (const bad of [
    '[NEW] [hoch] X',
    '[NEU] [HOCH] X',
    '[NEU] [hoch]',
    '[NEU][hoch] X',
    '[NEU] [UNGEPATCHT] [UNGEPATCHT] [hoch] X',
    '[NEU] [unbekannt] X',
    ' [NEU] [hoch] X',
  ]) {
    assert.equal(src.parseWidTitle(bad), null, bad);
  }
});

test('widRelevant: kritisch always, hoch only when new or unpatched', () => {
  const t = (status, unpatched, severity) => src.widRelevant({ status, unpatched, severity, text: 'x' });
  assert.equal(t('NEU', false, 'kritisch'), true);
  assert.equal(t('UPDATE', false, 'kritisch'), true);
  assert.equal(t('NEU', false, 'hoch'), true);
  assert.equal(t('UPDATE', true, 'hoch'), true);
  assert.equal(t('UPDATE', false, 'hoch'), false);
  assert.equal(t('NEU', true, 'mittel'), false);
  assert.equal(t('NEU', false, 'niedrig'), false);
  assert.equal(src.widRelevant(null), false);
});

test('fixture wid.xml: 12 relevant advisories, all titles parsed', () => {
  const { items, stats } = src.parseWid(fixture('wid.xml'));
  assert.deepEqual(stats, { received: 250, unparsedTitle: 0, invalid: 0, duplicate: 0, kept: 12 });
  assert.equal(items.filter((i) => i.severity === 'kritisch').length, 4);
  assert.equal(items.filter((i) => i.status === 'NEU' && i.severity === 'hoch').length, 6);
  assert.equal(items.filter((i) => i.unpatched).length, 2);
  for (const i of items) {
    assert.match(i.id, /^WID-SEC-\d{4}-\d{4,}$/);
    assert.equal(i.link, `https://wid.cert-bund.de/portal/wid/securityadvisory?name=${i.id}`);
    assert.ok(!i.title.startsWith('['), i.title);
    assert.ok(Number.isFinite(i.date));
  }
  const dates = items.map((i) => i.date);
  assert.deepEqual(dates, [...dates].sort((a, b) => b - a));
});

test('parseWid rejects foreign links and keeps the newest duplicate', () => {
  const item = (link, date) =>
    `<item><title>[NEU] [kritisch] X: Y</title><link>${link}</link><pubDate>${date}</pubDate></item>`;
  const ok = 'https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0001';
  const xml = [
    item(ok, 'Mon, 09 Nov 2026 10:00:00 GMT'),
    item(ok, 'Tue, 10 Nov 2026 10:00:00 GMT'),
    item('https://evil.example/?name=WID-SEC-2026-0002', 'Tue, 10 Nov 2026 10:00:00 GMT'),
    item(`${ok}&x=1`, 'Tue, 10 Nov 2026 10:00:00 GMT'),
    item(ok.replace('0001', '0003'), 'not a date'),
  ].join('');
  const { items, stats } = src.parseWid(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].date, Date.UTC(2026, 10, 10, 10));
  assert.equal(stats.duplicate, 1);
  assert.equal(stats.invalid, 3);
});

/* ---------- Buerger-CERT and BSI ---------- */

test('fixture buergercert.xml: latest 5, links rebuilt from UUIDs', () => {
  const { items, stats } = src.parseBuergercert(fixture('buergercert.xml'));
  assert.deepEqual(stats, { received: 100, invalid: 0, kept: 5 });
  assert.equal(src.parseBuergercert(fixture('buergercert.xml'), 1000).stats.kept, 100);
  for (const i of items) {
    assert.equal(i.link, `https://wid.cert-bund.de/portal/wid/buergercert/details?uuid=${i.id}`);
    assert.ok(!/[\r\n]/.test(i.description));
  }
  const dates = items.map((i) => i.date);
  assert.deepEqual(dates, [...dates].sort((a, b) => b - a));
});

test('fixture bits.xml and presse.xml: every item survives safeBsiUrl, newest 10 kept', () => {
  for (const [file, source, count] of [
    ['bits.xml', 'bits', 50],
    ['presse.xml', 'presse', 40],
  ]) {
    // limit above the feed size: every item is checked end to end
    const all = src.parseBsiFeed(fixture(file), source, 1000);
    assert.deepEqual(all.stats, { received: count, invalid: 0, kept: count });
    const { items, stats } = src.parseBsiFeed(fixture(file), source);
    assert.deepEqual(stats, { received: count, invalid: 0, kept: 10 });
    const dates = items.map((i) => i.date);
    assert.deepEqual(dates, [...dates].sort((a, b) => b - a));
    assert.ok(dates[9] >= Math.max(...all.items.slice(10).map((i) => i.date)));
    for (const i of items) {
      assert.equal(i.source, source);
      assert.ok(i.link.startsWith('https://www.bsi.bund.de/'));
      assert.ok(!i.title.includes('&#'), i.title);
    }
  }
});

test('parseBsiFeed drops items with unsafe links', () => {
  const xml =
    '<item><title>T</title><link>https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/%2e%2e/x.html</link><pubDate>Fri, 6 Nov 2026 13:00:00 +0100</pubDate></item>' +
    '<item><title>T</title><link>javascript:alert(1)</link><pubDate>Fri, 6 Nov 2026 13:00:00 +0100</pubDate></item>';
  assert.deepEqual(src.parseBsiFeed(xml, 'bits').stats, { received: 2, invalid: 2, kept: 0 });
});

/* ---------- NVD ---------- */

test('fixture nvd-kev.json: 12 KEV entries in the window', () => {
  const { items, stats } = src.parseNvd(fixture('nvd-kev.json'), NOW);
  assert.deepEqual(stats, {
    received: 12,
    total: 12,
    invalid: 0,
    outOfWindow: 0,
    truncated: false,
    kept: 12,
  });
  for (const i of items) {
    assert.equal(i.link, `https://nvd.nist.gov/vuln/detail/${i.id}`);
    assert.ok(i.kevAdded >= WINDOW_START);
    assert.ok(i.title.length > 0 && i.title.length <= 160);
    assert.ok(i.cvss === null || (i.cvss.score >= 0 && i.cvss.score <= 10));
  }
  assert.equal(items.filter((i) => i.cvss?.version === '4.0').length, 2);
});

test('bestCvss prefers newer versions and Primary scores', () => {
  const m = (score, type = 'Primary', version = '3.1') => ({ type, cvssData: { baseScore: score, version } });
  assert.deepEqual(src.bestCvss({ cvssMetricV31: [m(5)], cvssMetricV40: [m(9, 'Primary', '4.0')] }), {
    score: 9,
    version: '4.0',
  });
  assert.deepEqual(src.bestCvss({ cvssMetricV31: [m(7, 'Secondary'), m(5)] }), { score: 5, version: '3.1' });
  assert.deepEqual(src.bestCvss({ cvssMetricV40: [m(11, 'Primary', '4.0')], cvssMetricV31: [m(6)] }), {
    score: 6,
    version: '3.1',
  });
  assert.equal(src.bestCvss({ cvssMetricV2: [m(10, 'Primary', '2.0')] }), null);
  assert.equal(src.bestCvss(null), null);
});

test('parseNvd drops invalid and out-of-window entries and flags truncation', () => {
  const v = (id, add) => ({ cve: { id, cisaExploitAdd: add, cisaVulnerabilityName: 'N' } });
  const json = JSON.stringify({
    totalResults: 5,
    vulnerabilities: [v('CVE-2026-1234', '2026-11-10'), v('CVE-2026-1235', '2026-11-03'), v('../x', '2026-11-10'), v('CVE-2026-1236', '2026-02-30')],
  });
  const { items, stats } = src.parseNvd(json, NOW);
  assert.equal(items.length, 1);
  assert.equal(stats.outOfWindow, 1);
  assert.equal(stats.invalid, 2);
  assert.equal(stats.truncated, true);
  assert.throws(() => src.parseNvd('<html>', NOW));
});

/* ---------- EUVD ---------- */

test('fixture euvd-exploited.json: 12 of 33 exploited in the window', () => {
  const { items, stats } = src.parseEuvd(fixture('euvd-exploited.json'), NOW);
  assert.deepEqual(stats, {
    received: 33,
    total: 33,
    invalid: 0,
    outOfWindow: 21,
    needsMore: false,
    kept: 12,
  });
  for (const i of items) {
    assert.ok(i.exploitedSince >= WINDOW_START);
    assert.ok(i.cves.length >= 1);
    assert.ok(i.epss === null || (i.epss >= 0 && i.epss <= 100));
    assert.ok(i.title.length > 0 && i.title.length <= 160);
  }
});

test('euvdThreat names vendor and product without repeating the vendor', () => {
  const prod = (vendor, name) => ({ product: { name, vendor: { name: vendor } } });
  assert.equal(src.euvdThreat({ enisaIdProduct: [prod('Google', 'Chrome')] }), 'Google: Chrome');
  assert.equal(src.euvdThreat({ enisaIdProduct: [prod('Cisco', 'Cisco BroadWorks')] }), 'Cisco BroadWorks');
  assert.equal(
    src.euvdThreat({ enisaIdProduct: [prod('Apple', 'macOS'), prod('Apple', 'iOS'), prod('Apple', 'macOS')] }),
    'Apple: macOS (+1)',
  );
  assert.equal(src.euvdThreat({ enisaIdVendor: [{ vendor: { name: 'Acme' } }] }), 'Acme');
  assert.equal(src.euvdThreat({ description: 'Only a description' }), 'Only a description');
  const long = src.euvdThreat({ enisaIdProduct: [prod('V', 'x'.repeat(400)), prod('V', 'y')] });
  assert.equal(Array.from(long).length, 160);
  assert.ok(long.endsWith('… (+1)'));
});

test('parseEuvd signals when a second page is needed', () => {
  const items = Array.from({ length: 100 }, (_, n) => ({
    id: `EUVD-2026-${10000 + n}`,
    exploitedSince: 'Nov 10, 2026, 12:00:00 AM',
    aliases: `CVE-2026-${20000 + n}\n`,
    description: 'd',
  }));
  assert.equal(src.parseEuvd(JSON.stringify({ items, total: 150 }), NOW).stats.needsMore, true);
  assert.equal(src.parseEuvd(JSON.stringify({ items, total: 100 }), NOW).stats.needsMore, false);
});

/* ---------- Merge ---------- */

test('fixture: every EUVD entry in the window matches a KEV entry and is merged', () => {
  const nvd = src.parseNvd(fixture('nvd-kev.json'), NOW).items;
  const euvd = src.parseEuvd(fixture('euvd-exploited.json'), NOW).items;
  const m = src.mergeEuvdIntoNvd(nvd, euvd);
  assert.equal(m.merged, 12);
  assert.equal(m.euvd.length, 0);
  assert.equal(m.nvd.length, 12);
  for (const i of m.nvd) {
    assert.match(i.euvd.id, /^EUVD-\d{4}-\d{4,}$/);
    assert.equal(i.euvd.link, `https://euvd.enisa.europa.eu/vulnerability/${i.euvd.id}`);
  }
  // inputs are not mutated
  assert.ok(nvd.every((i) => !('euvd' in i)));
});

test('mergeEuvdIntoNvd matches any alias, not only the first', () => {
  const nvd = [{ id: 'CVE-2026-0002' }];
  const euvd = [
    { id: 'EUVD-2026-1', link: 'l1', epss: 1, cves: ['CVE-2026-0001', 'CVE-2026-0002'] },
    { id: 'EUVD-2026-2', link: 'l2', epss: 2, cves: ['CVE-2026-0009'] },
  ];
  const m = src.mergeEuvdIntoNvd(nvd, euvd);
  assert.deepEqual(m.nvd[0].euvd, { id: 'EUVD-2026-1', link: 'l1', epss: 1 });
  assert.deepEqual(m.euvd.map((e) => e.id), ['EUVD-2026-2']);
});

/* ---------- Network ---------- */

const respond = (body, status = 200, headers = {}) => async () => new Response(body, { status, headers });

test('fetchText sends no-store, manual redirects, a signal and a user agent', async () => {
  let seen;
  const r = await src.fetchText('https://example.test/', {
    accept: 'application/json',
    fetchImpl: async (url, init) => {
      seen = init;
      return new Response('{"a":1}');
    },
  });
  assert.equal(r.ok, true);
  assert.equal(r.text, '{"a":1}');
  assert.equal(r.bytes, 7);
  assert.equal(seen.cache, 'no-store');
  assert.equal(seen.redirect, 'manual');
  assert.ok(seen.signal instanceof AbortSignal);
  assert.equal(seen.headers.accept, 'application/json');
  assert.match(seen.headers['user-agent'], /^cyberuser\.de\//);
});

test('fetchText treats every non-200 status as a failure, redirects included', async () => {
  for (const status of [204, 301, 302, 404, 429, 500, 503]) {
    const r = await src.fetchText('https://example.test/', { fetchImpl: respond(null, status) });
    assert.equal(r.ok, false);
    assert.equal(r.error, `http_${status}`);
    assert.equal(r.text, null);
  }
});

test('fetchText enforces the byte limit, declared or streamed', async () => {
  const declared = await src.fetchText('https://example.test/', {
    maxBytes: 10,
    fetchImpl: respond('x', 200, { 'content-length': '99' }),
  });
  assert.equal(declared.error, 'too_large');

  const streamed = await src.fetchText('https://example.test/', {
    maxBytes: 10,
    fetchImpl: respond('x'.repeat(11)),
  });
  assert.equal(streamed.error, 'too_large');

  const exact = await src.fetchText('https://example.test/', { maxBytes: 10, fetchImpl: respond('x'.repeat(10)) });
  assert.equal(exact.ok, true);
});

test('fetchText rejects invalid UTF-8', async () => {
  const r = await src.fetchText('https://example.test/', { fetchImpl: respond(new Uint8Array([0x41, 0xff, 0x42])) });
  assert.equal(r.error, 'invalid_utf8');
});

test('fetchText times out on a hanging request and on a stalled body', async () => {
  const hang = (url, init) =>
    new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('a', 'AbortError'))));
  const r1 = await src.fetchText('https://example.test/', { timeoutMs: 30, fetchImpl: hang });
  assert.equal(r1.error, 'timeout');

  const stalled = async (url, init) => {
    const body = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode('partial'));
        init.signal.addEventListener('abort', () => c.error(new DOMException('a', 'AbortError')));
      },
    });
    return new Response(body);
  };
  const r2 = await src.fetchText('https://example.test/', { timeoutMs: 30, fetchImpl: stalled });
  assert.equal(r2.error, 'timeout');
});

test('fetchText reports network errors without throwing', async () => {
  const r = await src.fetchText('https://example.test/', {
    fetchImpl: async () => {
      throw new TypeError('fetch failed');
    },
  });
  assert.equal(r.ok, false);
  assert.equal(r.error, 'network');
});

/* ---------- Orchestration ---------- */

function fixtureFetch(overrides = {}) {
  const calls = [];
  const fake = async (url) => {
    calls.push(url);
    if (overrides[url]) return overrides[url]();
    if (url.startsWith('https://services.nvd.nist.gov/')) return new Response(fixture('nvd-kev.json'));
    if (url.startsWith('https://euvdservices.enisa.europa.eu/')) return new Response(fixture('euvd-exploited.json'));
    const file = { wid: 'wid.xml', buergercert: 'buergercert.xml', bits: 'bits.xml', presse: 'presse.xml' };
    for (const [k, f] of Object.entries(file)) if (url === src.FEEDS[k]) return new Response(fixture(f));
    return new Response(null, { status: 404 });
  };
  return { fake, calls };
}

test('collectAll on fixtures: six requests, all sources ok, nothing merged here', async () => {
  const { fake, calls } = fixtureFetch();
  const logs = [];
  const r = await src.collectAll(NOW, { fetchImpl: fake, log: (l) => logs.push(JSON.parse(l)) });
  assert.equal(calls.length, 6);
  for (const k of ['nvd', 'euvd', 'wid', 'buergercert', 'bits', 'presse']) assert.equal(r[k].ok, true, k);
  assert.equal(r.nvd.items.length, 12);
  // The EUVD merge happens in worker.js after source resolution, not here
  assert.ok(r.nvd.items.every((i) => !i.euvd));
  assert.equal(r.euvd.items.length, 12);
  assert.equal(r.wid.items.length, 12);
  assert.equal(r.buergercert.items.length, 5);
  // one log line per source, with metrics only
  assert.equal(logs.length, 6);
  for (const l of logs.filter((x) => x.source !== 'merge')) {
    assert.deepEqual(Object.keys(l).slice(0, 5), ['source', 'ok', 'status', 'bytes', 'ms']);
  }
});

test('collectAll isolates a failing source', async () => {
  const { fake } = fixtureFetch({ [src.nvdKevUrl(NOW)]: () => new Response(null, { status: 503 }) });
  const r = await src.collectAll(NOW, { fetchImpl: fake, log: () => {} });
  assert.equal(r.nvd.ok, false);
  assert.equal(r.nvd.error, 'http_503');
  assert.equal(r.euvd.ok, true);
  assert.equal(r.euvd.items.length, 12);
  assert.equal(r.wid.ok, true);
});

test('collectAll reports a parse error for a broken body', async () => {
  const { fake } = fixtureFetch({ [src.FEEDS.wid]: () => new Response('<html>maintenance</html>') });
  const r = await src.collectAll(NOW, { fetchImpl: fake, log: () => {} });
  assert.equal(r.wid.ok, true);
  assert.equal(r.wid.items.length, 0);
  const { fake: fake2 } = fixtureFetch({ [src.nvdKevUrl(NOW)]: () => new Response('<html>') });
  const r2 = await src.collectAll(NOW, { fetchImpl: fake2, log: () => {} });
  assert.equal(r2.nvd.error, 'parse');
});

test('collectAll fetches only the requested sources', async () => {
  const { fake, calls } = fixtureFetch();
  const r = await src.collectAll(NOW, { fetchImpl: fake, log: () => {}, only: new Set(['wid', 'bits']) });
  assert.deepEqual(Object.keys(r), ['wid', 'bits']);
  assert.deepEqual([...calls].sort(), [src.FEEDS.wid, src.FEEDS.bits].sort());
  const none = await src.collectAll(NOW, { fetchImpl: fake, log: () => {}, only: [] });
  assert.deepEqual(none, {});
});

test('collectAll fetches at most one extra EUVD page', async () => {
  const page = (offset, total) =>
    JSON.stringify({
      total,
      items: Array.from({ length: 100 }, (_, n) => ({
        id: `EUVD-2026-${offset + n}`,
        exploitedSince: 'Nov 10, 2026, 12:00:00 AM',
        aliases: `CVE-2026-${offset + n}`,
        description: 'd',
      })),
    });
  const { fake, calls } = fixtureFetch({
    [src.euvdSearchUrl(NOW, 0)]: () => new Response(page(10000, 300)),
    [src.euvdSearchUrl(NOW, 1)]: () => new Response(page(20000, 300)),
  });
  const r = await src.collectAll(NOW, { fetchImpl: fake, log: () => {} });
  assert.equal(calls.length, 7);
  assert.ok(!calls.includes(src.euvdSearchUrl(NOW, 2)));
  assert.equal(r.euvd.items.length, 200);
  assert.equal(r.euvd.partial, true);
});
