// Unit tests for src/sanitize.js: constructed edge/attack cases plus
// every relevant value from the saved real-world fixtures in test/fixtures/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as s from '../src/sanitize.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const rssItems = (xml) => xml.match(/<item>[\s\S]*?<\/item>/g) ?? [];
const tag = (item, name) => {
  const m = new RegExp(`<${name}>([^<]*)</${name}>`).exec(item);
  return m ? s.decodeXmlEntities(m[1]) : null;
};

/* ---------- Text ---------- */

test('decodeXmlEntities decodes once and never twice', () => {
  assert.equal(s.decodeXmlEntities('&amp;lt;script&amp;gt;'), '&lt;script&gt;');
  assert.equal(s.decodeXmlEntities('&lt;b&gt; &quot;x&quot; &apos;y&apos;'), '<b> "x" \'y\'');
});

test('decodeXmlEntities handles decimal and hex references', () => {
  assert.equal(s.decodeXmlEntities('&#8222;Test&#8220;'), '\u201ETest\u201C');
  assert.equal(s.decodeXmlEntities('a&#xD;b'), 'a\rb');
  assert.equal(s.decodeXmlEntities('&#x1F600;'), '\u{1F600}');
});

test('decodeXmlEntities replaces invalid code points and keeps unknown entities', () => {
  assert.equal(s.decodeXmlEntities('&#0;'), '\uFFFD');
  assert.equal(s.decodeXmlEntities('&#xD800;'), '\uFFFD');
  assert.equal(s.decodeXmlEntities('&#x110000;'), '\uFFFD');
  assert.equal(s.decodeXmlEntities('&nbsp;'), '&nbsp;');
  assert.equal(s.decodeXmlEntities(undefined), '');
});

test('cleanText normalizes whitespace and strips control and bidi characters', () => {
  assert.equal(s.cleanText('a\r\nb\tc'), 'a b c');
  assert.equal(s.cleanText('a\u0000b\u007Fc\u0085d'), 'abcd');
  assert.equal(s.cleanText('abc\u202Edef\u2066g'), 'abcdefg');
  assert.equal(s.cleanText('   x    y  '), 'x y');
  assert.equal(s.cleanText(42), '');
});

test('cleanText truncates by code point with an ellipsis', () => {
  assert.equal(s.cleanText('abcdef', 4), 'abc\u2026');
  assert.equal(s.cleanText('ab', 2), 'ab');
  assert.equal(s.cleanText('\u{1F600}\u{1F600}\u{1F600}', 2), '\u{1F600}\u2026');
  assert.equal(s.cleanText('abc def', 5), 'abc\u2026');
});

test('escapeHtml escapes the five significant characters', () => {
  assert.equal(
    s.escapeHtml(`<a href="x" onclick='y'>&`),
    '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;',
  );
  assert.equal(s.escapeHtml(7.5), '7.5');
  assert.equal(s.escapeHtml(null), '');
  assert.equal(s.escapeHtml({ toString: () => '<x>' }), '');
});

/* ---------- Identifiers and links ---------- */

test('ID validators accept exact formats only', () => {
  assert.equal(s.cveId('CVE-2026-12345'), 'CVE-2026-12345');
  assert.equal(s.cveId('CVE-2026-123'), null);
  assert.equal(s.cveId(' CVE-2026-12345'), null);
  assert.equal(s.cveId('CVE-2026-12345\n'), null);
  assert.equal(s.widId('WID-SEC-2026-1234'), 'WID-SEC-2026-1234');
  assert.equal(s.widId('WID-SEC-2026-12a4'), null);
  assert.equal(s.euvdId('EUVD-2026-121390'), 'EUVD-2026-121390');
  assert.equal(s.euvdId('EUVD-26-1'), null);
  assert.equal(s.uuid('0f8fad5b-d9cb-469f-a165-70867728950e'), '0f8fad5b-d9cb-469f-a165-70867728950e');
  assert.equal(s.uuid('0f8fad5b-d9cb-469f-a165-70867728950e&x=1'), null);
});

test('cveIdsFromAliases finds every CVE, not only the first alias', () => {
  assert.deepEqual(
    s.cveIdsFromAliases('GHSA-9w8j-fg77-whw7\nCVE-2026-1234\nCVE-2026-1234\nCVE-2026-99999'),
    ['CVE-2026-1234', 'CVE-2026-99999'],
  );
  assert.deepEqual(s.cveIdsFromAliases(null), []);
});

test('link builders only accept validated IDs', () => {
  assert.equal(s.nvdUrl('CVE-2026-1234'), 'https://nvd.nist.gov/vuln/detail/CVE-2026-1234');
  assert.equal(s.nvdUrl('CVE-2026-1234"><script>'), null);
  assert.equal(s.euvdUrl('EUVD-2026-1234'), 'https://euvd.enisa.europa.eu/vulnerability/EUVD-2026-1234');
  assert.equal(s.widUrl('WID-SEC-2026-1234'), 'https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1234');
  assert.equal(s.buergercertUrl('not-a-uuid'), null);
});

test('safeBsiUrl accepts the two allowed path prefixes', () => {
  const warn = 'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2026/2026-123.html';
  const press = 'https://www.bsi.bund.de/DE/Service-Navi/Presse/Pressemitteilungen/Presse2026/x_261111.html';
  assert.equal(s.safeBsiUrl(warn), warn);
  assert.equal(s.safeBsiUrl(press), press);
});

test('safeBsiUrl rejects everything else', () => {
  const bad = [
    'http://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.html',
    'https://bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.html',
    'https://www.bsi.bund.de.evil.example/SharedDocs/Cybersicherheitswarnungen/DE/a.html',
    'https://user@www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.html',
    'https://www.bsi.bund.de:443/SharedDocs/Cybersicherheitswarnungen/DE/a.html',
    'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.html?nn=1',
    'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.html#x',
    'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/../../DE/evil.html',
    'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/%2e%2e/a.html',
    'https://www.bsi.bund.de/DE/Themen/a.html',
    'https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/a.pdf',
    'javascript:alert(1)',
    null,
  ];
  for (const u of bad) assert.equal(s.safeBsiUrl(u), null, `accepted: ${u}`);
});

test('boundedNumber accepts finite numbers in range only', () => {
  assert.equal(s.boundedNumber(9.8, 0, 10), 9.8);
  assert.equal(s.boundedNumber(0, 0, 1), 0);
  assert.equal(s.boundedNumber(10.1, 0, 10), null);
  assert.equal(s.boundedNumber('9.8', 0, 10), null);
  assert.equal(s.boundedNumber(Number.NaN, 0, 10), null);
});

/* ---------- Dates ---------- */

test('parseIsoDay', () => {
  assert.equal(s.parseIsoDay('2026-11-10'), Date.UTC(2026, 10, 10));
  assert.equal(s.parseIsoDay('2026-02-30'), null);
  assert.equal(s.parseIsoDay('2026-11-10T00:00'), null);
});

test('parseNvdTimestamp treats zone-less timestamps as UTC', () => {
  assert.equal(s.parseNvdTimestamp('2026-11-10T17:15:42.123'), Date.UTC(2026, 10, 10, 17, 15, 42, 123));
  assert.equal(s.parseNvdTimestamp('2026-11-10T17:15:42.1'), Date.UTC(2026, 10, 10, 17, 15, 42, 100));
  assert.equal(s.parseNvdTimestamp('2026-11-10T17:15:42'), Date.UTC(2026, 10, 10, 17, 15, 42));
  assert.equal(s.parseNvdTimestamp('2026-11-10T24:00:00'), null);
  assert.equal(s.parseNvdTimestamp('2026-11-10T17:15:42Z'), null);
});

test('parseEuvdDate keeps only the day and accepts U+202F before AM/PM', () => {
  assert.equal(s.parseEuvdDate('Nov 10, 2026, 12:00:00 AM'), Date.UTC(2026, 10, 10));
  assert.equal(s.parseEuvdDate('Nov 10, 2026, 6:22:22\u202FPM'), Date.UTC(2026, 10, 10));
  assert.equal(s.parseEuvdDate('Feb 30, 2026, 1:00:00 PM'), null);
  assert.equal(s.parseEuvdDate('Nov 10, 2026, 13:00:00 PM'), null);
  assert.equal(s.parseEuvdDate('Nov 10, 2026'), null);
});

test('parseRfc822 converts offsets to UTC', () => {
  assert.equal(s.parseRfc822('Tue, 11 Nov 2026 10:34:00 GMT'), Date.UTC(2026, 10, 11, 10, 34));
  assert.equal(s.parseRfc822('Tue, 11 Nov 2026 10:34:00 +0100'), Date.UTC(2026, 10, 11, 9, 34));
  assert.equal(s.parseRfc822('Tue, 11 Nov 2026 10:34:00 -0500'), Date.UTC(2026, 10, 11, 15, 34));
  assert.equal(s.parseRfc822('1 Nov 2026 01:00:00 +0200'), Date.UTC(2026, 9, 31, 23, 0));
  assert.equal(s.parseRfc822('11 Nov 2026 10:34:00 +2500'), null);
  assert.equal(s.parseRfc822('31 Nov 2026 10:34:00 GMT'), null);
});

/* ---------- Real fixtures ---------- */

test('fixture nvd-kev.json: every ID and date validates', () => {
  const data = JSON.parse(fixture('nvd-kev.json'));
  assert.ok(data.vulnerabilities.length > 0);
  for (const { cve } of data.vulnerabilities) {
    assert.ok(s.cveId(cve.id), `id: ${cve.id}`);
    assert.ok(s.parseNvdTimestamp(cve.published) !== null, `published: ${cve.published}`);
    assert.ok(s.parseIsoDay(cve.cisaExploitAdd) !== null, `cisaExploitAdd: ${cve.cisaExploitAdd}`);
    assert.ok(s.parseIsoDay(cve.cisaActionDue) !== null, `cisaActionDue: ${cve.cisaActionDue}`);
  }
});

test('fixture euvd-exploited.json: every ID and date validates', () => {
  const data = JSON.parse(fixture('euvd-exploited.json'));
  assert.ok(data.items.length > 0);
  for (const v of data.items) {
    assert.ok(s.euvdId(v.id), `id: ${v.id}`);
    assert.ok(s.parseEuvdDate(v.exploitedSince) !== null, `exploitedSince: ${v.exploitedSince}`);
    assert.ok(s.parseEuvdDate(v.datePublished) !== null, `datePublished: ${v.datePublished}`);
  }
});

for (const file of ['wid.xml', 'buergercert.xml', 'bits.xml', 'presse.xml']) {
  test(`fixture ${file}: every pubDate parses`, () => {
    const items = rssItems(fixture(file));
    assert.ok(items.length > 0);
    for (const item of items) {
      const d = tag(item, 'pubDate');
      assert.ok(s.parseRfc822(d) !== null, `pubDate: ${d}`);
    }
  });
}

test('fixture wid.xml: every link yields a valid WID ID', () => {
  for (const item of rssItems(fixture('wid.xml'))) {
    const link = tag(item, 'link');
    const id = /[?&]name=([^&]+)$/.exec(link ?? '')?.[1];
    assert.ok(s.widId(id), `link: ${link}`);
  }
});

test('fixture buergercert.xml: every link yields a valid UUID', () => {
  for (const item of rssItems(fixture('buergercert.xml'))) {
    const link = tag(item, 'link');
    const id = /[?&]uuid=([^&]+)$/.exec(link ?? '')?.[1];
    assert.ok(s.uuid(id), `link: ${link}`);
  }
});

for (const file of ['bits.xml', 'presse.xml']) {
  test(`fixture ${file}: every item link passes safeBsiUrl`, () => {
    for (const item of rssItems(fixture(file))) {
      const link = tag(item, 'link');
      assert.ok(s.safeBsiUrl(link), `link: ${link}`);
    }
  });
}

test('safeBsiUrl accepts UTF-8 percent-encoding and rejects encoded ASCII', () => {
  const base = 'https://www.bsi.bund.de/DE/Service-Navi/Presse/Pressemitteilungen/Presse2026/';
  const ok = `${base}261020_CRA-Durchf%C3%BChrungsgesetz.html`;
  assert.equal(s.safeBsiUrl(ok), ok);
  const bad = [
    `${base}a%2Fb.html`,
    `${base}a%5Cb.html`,
    `${base}a%00b.html`,
    `${base}a%C3.html`,
    `${base}a%c3%bcb.html`,
    `${base}a%E2%80%AEb.html`,
  ];
  for (const u of bad) assert.equal(s.safeBsiUrl(u), null, `accepted: ${u}`);
});
