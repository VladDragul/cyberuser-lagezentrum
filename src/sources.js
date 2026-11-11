// Fetching and parsing of the six official sources shown on the homepage.
// Parsers are pure (string in, normalized items out) and run identically in
// node --test and in the Worker. Network access goes through an injectable
// fetch implementation so tests never touch the network.
//
// Every value that leaves this module was validated or cleaned by sanitize.js.
// Links are rebuilt from validated IDs, except BSI links, which pass safeBsiUrl.

import {
  LIMITS,
  decodeXmlEntities,
  cleanText,
  cveId,
  widId,
  euvdId,
  uuid,
  cveIdsFromAliases,
  nvdUrl,
  euvdUrl,
  widUrl,
  buergercertUrl,
  safeBsiUrl,
  boundedNumber,
  parseIsoDay,
  parseNvdTimestamp,
  parseEuvdDate,
  parseRfc822,
} from './sanitize.js';

/* ---------- Configuration ---------- */

export const FETCH_DEFAULTS = Object.freeze({
  timeoutMs: 10_000,
  maxBytes: 512 * 1024,
});

const DAY_MS = 86_400_000;
export const WINDOW_DAYS = 7;
export const EUVD_PAGE_SIZE = 100;
export const BUERGERCERT_LATEST = 5;
export const BSI_LATEST = 10;

// Upper bounds on how much of a (possibly hostile or broken) response is parsed
const MAX_RSS_ITEMS = 500;
const MAX_JSON_ITEMS = 500;

const USER_AGENT = 'cyberuser.de/0.1 (+https://cyberuser.de/)';
const ACCEPT_JSON = 'application/json';
const ACCEPT_RSS = 'application/rss+xml, application/xml;q=0.9, text/xml;q=0.8';

export const FEEDS = Object.freeze({
  wid: 'https://wid.cert-bund.de/content/public/securityAdvisory/rss',
  buergercert: 'https://wid.cert-bund.de/content/public/buergercert/rss',
  bits: 'https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_CSW.xml',
  presse:
    'https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse_Veranstaltungen.xml',
});

/* ---------- Time window ---------- */

// Midnight UTC of the day that lies WINDOW_DAYS before nowMs
export function windowStartMs(nowMs) {
  const today = Math.floor(nowMs / DAY_MS) * DAY_MS;
  return today - WINDOW_DAYS * DAY_MS;
}

const isoDay = (ms) => new Date(ms).toISOString().slice(0, 10);

export function nvdKevUrl(nowMs) {
  const from = isoDay(windowStartMs(nowMs));
  const to = isoDay(nowMs);
  return (
    'https://services.nvd.nist.gov/rest/json/cves/2.0' +
    `?kevStartDate=${from}T00:00:00.000&kevEndDate=${to}T23:59:59.999`
  );
}

export function euvdSearchUrl(nowMs, page = 0) {
  const from = isoDay(windowStartMs(nowMs));
  const to = isoDay(nowMs);
  return (
    'https://euvdservices.enisa.europa.eu/api/search' +
    `?exploited=true&fromUpdatedDate=${from}&toUpdatedDate=${to}&size=${EUVD_PAGE_SIZE}&page=${page}`
  );
}

/* ---------- Network ---------- */

// GET with no edge cache, no redirects, a hard timeout that also covers the
// body read, and a byte limit. Never throws: always returns a result object.
export async function fetchText(url, options = {}) {
  const {
    timeoutMs = FETCH_DEFAULTS.timeoutMs,
    maxBytes = FETCH_DEFAULTS.maxBytes,
    accept = '*/*',
    fetchImpl = globalThis.fetch,
  } = options;

  const started = Date.now();
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  const result = (fields) => ({ ok: false, status: 0, bytes: 0, text: null, error: null, ...fields, ms: Date.now() - started });

  try {
    const res = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      cache: 'no-store',
      signal: controller.signal,
      headers: { accept, 'user-agent': USER_AGENT },
    });

    if (res.status !== 200) {
      await res.body?.cancel().catch(() => {});
      return result({ status: res.status, error: `http_${res.status}` });
    }

    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
      await res.body?.cancel().catch(() => {});
      return result({ status: 200, error: 'too_large' });
    }

    if (!res.body) return result({ status: 200, error: 'empty_body' });

    const reader = res.body.getReader();
    const chunks = [];
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel().catch(() => {});
        return result({ status: 200, bytes, error: 'too_large' });
      }
      chunks.push(value);
    }

    const buf = new Uint8Array(bytes);
    let offset = 0;
    for (const c of chunks) {
      buf.set(c, offset);
      offset += c.byteLength;
    }

    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buf);
    } catch {
      return result({ status: 200, bytes, error: 'invalid_utf8' });
    }
    return { ok: true, status: 200, bytes, text, error: null, ms: Date.now() - started };
  } catch (err) {
    return result({ error: timedOut ? 'timeout' : err?.name === 'AbortError' ? 'aborted' : 'network' });
  } finally {
    clearTimeout(timer);
  }
}

/* ---------- RSS ---------- */

// Text content of one element: CDATA sections are taken literally, everything
// else gets one pass of entity decoding. Leftover markup is not interpreted;
// it ends up as plain text and is escaped at render time.
const CDATA_RE = /<!\[CDATA\[([\s\S]*?)\]\]>/g;

function elementText(inner) {
  if (!inner.includes('<![CDATA[')) return decodeXmlEntities(inner);
  let out = '';
  let last = 0;
  CDATA_RE.lastIndex = 0;
  let m;
  while ((m = CDATA_RE.exec(inner)) !== null) {
    out += decodeXmlEntities(inner.slice(last, m.index)) + m[1];
    last = CDATA_RE.lastIndex;
  }
  return out + decodeXmlEntities(inner.slice(last));
}

// Compiled once per tag name: the cron runs on a cold isolate with a 10 ms CPU budget
const CHILD_RE = new Map(
  ['title', 'link', 'description', 'pubDate'].map((n) => [n, new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`)]),
);

function childText(itemXml, name) {
  const m = CHILD_RE.get(name).exec(itemXml);
  return m ? elementText(m[1]) : null;
}

// Raw <item> bodies only, so the two channel-level <link> elements in the BSI
// feeds are never confused with item links.
const ITEM_RE = /<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/g;

function itemBodies(xml) {
  if (typeof xml !== 'string') return [];
  const out = [];
  ITEM_RE.lastIndex = 0;
  let m;
  while ((m = ITEM_RE.exec(xml)) !== null && out.length < MAX_RSS_ITEMS) out.push(m[1]);
  return out;
}

export function parseRss(xml) {
  return itemBodies(xml).map((body) => ({
    title: childText(body, 'title'),
    link: childText(body, 'link'),
    description: childText(body, 'description'),
    pubDate: childText(body, 'pubDate'),
  }));
}

/* ---------- WID (CERT-Bund security advisories) ---------- */

// "[NEU] [hoch] Produkt: Text" or "[UPDATE] [UNGEPATCHT] [kritisch] Produkt: Text"
const WID_TITLE_RE = /^\[(NEU|UPDATE)\]( \[UNGEPATCHT\])? \[(niedrig|mittel|hoch|kritisch)\] (.+)$/;
const WID_LINK_RE = /^https:\/\/wid\.cert-bund\.de\/portal\/wid\/securityadvisory\?name=(WID-SEC-\d{4}-\d{4,})$/;

export function parseWidTitle(title) {
  if (typeof title !== 'string') return null;
  const m = WID_TITLE_RE.exec(title);
  if (!m) return null;
  return { status: m[1], unpatched: m[2] !== undefined, severity: m[3], text: m[4] };
}

// kritisch: always. hoch: only when new or still unpatched.
export function widRelevant(t) {
  if (!t) return false;
  if (t.severity === 'kritisch') return true;
  return t.severity === 'hoch' && (t.status === 'NEU' || t.unpatched);
}

export function parseWid(xml) {
  const stats = { received: 0, unparsedTitle: 0, invalid: 0, duplicate: 0 };
  const byId = new Map();
  for (const body of itemBodies(xml)) {
    stats.received++;
    // Title first: most advisories are filtered out before any other field is read
    const t = parseWidTitle(cleanText(childText(body, 'title') ?? ''));
    if (!t) {
      stats.unparsedTitle++;
      continue;
    }
    if (!widRelevant(t)) continue;
    const linkMatch = WID_LINK_RE.exec((childText(body, 'link') ?? '').trim());
    const id = linkMatch ? widId(linkMatch[1]) : null;
    const date = parseRfc822(childText(body, 'pubDate') ?? '');
    if (!id || date === null) {
      stats.invalid++;
      continue;
    }
    const prev = byId.get(id);
    if (prev) {
      stats.duplicate++;
      if (prev.date >= date) continue;
    }
    byId.set(id, {
      source: 'wid',
      id,
      title: cleanText(t.text, LIMITS.title),
      description: cleanText(childText(body, 'description') ?? '', LIMITS.description),
      status: t.status,
      unpatched: t.unpatched,
      severity: t.severity,
      date,
      link: widUrl(id),
    });
  }
  const items = [...byId.values()].sort((a, b) => b.date - a.date);
  return { items, stats: { ...stats, kept: items.length } };
}

/* ---------- Shared: newest N items of a feed ---------- */

// Pass 1 reads only link and date for every item; pass 2 reads title and
// description for the newest `limit` valid items, which are all that is shown.
function newestItems(xml, limit, keyOf, build) {
  const stats = { received: 0, invalid: 0 };
  const candidates = [];
  for (const body of itemBodies(xml)) {
    stats.received++;
    const key = keyOf(childText(body, 'link') ?? '');
    const date = parseRfc822(childText(body, 'pubDate') ?? '');
    if (key === null || date === null) {
      stats.invalid++;
      continue;
    }
    candidates.push({ body, key, date });
  }
  candidates.sort((a, b) => b.date - a.date);
  const items = [];
  for (const c of candidates) {
    if (items.length >= limit) break;
    const title = cleanText(childText(c.body, 'title') ?? '', LIMITS.title);
    if (title === '') {
      stats.invalid++;
      continue;
    }
    const description = cleanText(childText(c.body, 'description') ?? '', LIMITS.description);
    items.push(build(c.key, c.date, title, description));
  }
  return { items, stats: { ...stats, kept: items.length } };
}

/* ---------- Buerger-CERT ---------- */

const BUERGERCERT_LINK_RE =
  /^https:\/\/wid\.cert-bund\.de\/portal\/wid\/buergercert\/details\?uuid=([0-9a-fA-F-]{36})$/;

export function parseBuergercert(xml, limit = BUERGERCERT_LATEST) {
  return newestItems(
    xml,
    limit,
    (link) => {
      const m = BUERGERCERT_LINK_RE.exec(link.trim());
      return m ? uuid(m[1]) : null;
    },
    (id, date, title, description) => ({ source: 'buergercert', id, title, description, date, link: buergercertUrl(id) }),
  );
}

/* ---------- BSI websites (BITS warnings, press) ---------- */

export function parseBsiFeed(xml, source, limit = BSI_LATEST) {
  return newestItems(xml, limit, safeBsiUrl, (link, date, title, description) => ({
    source,
    title,
    description,
    date,
    link,
  }));
}

/* ---------- NVD (CISA KEV entries) ---------- */

const CVSS_ORDER = Object.freeze(['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']);

// Newest CVSS version first; within a version the NVD "Primary" score wins
export function bestCvss(metrics) {
  if (!metrics || typeof metrics !== 'object') return null;
  for (const key of CVSS_ORDER) {
    const list = Array.isArray(metrics[key]) ? metrics[key] : [];
    const entry = list.find((x) => x?.type === 'Primary') ?? list[0];
    const score = boundedNumber(entry?.cvssData?.baseScore, 0, 10);
    if (score !== null) {
      const version = String(entry.cvssData.version ?? '');
      return { score, version: /^\d\.\d$/.test(version) ? version : null };
    }
  }
  return null;
}

function englishDescription(descriptions) {
  if (!Array.isArray(descriptions)) return '';
  const en = descriptions.find((d) => d?.lang === 'en') ?? descriptions[0];
  return typeof en?.value === 'string' ? en.value : '';
}

export function parseNvd(jsonText, nowMs) {
  const data = JSON.parse(jsonText);
  const list = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities.slice(0, MAX_JSON_ITEMS) : [];
  const from = windowStartMs(nowMs);
  const stats = {
    received: list.length,
    total: Number.isSafeInteger(data?.totalResults) ? data.totalResults : null,
    invalid: 0,
    outOfWindow: 0,
  };
  const items = [];
  for (const v of list) {
    const c = v?.cve;
    const id = cveId(c?.id);
    const added = parseIsoDay(c?.cisaExploitAdd);
    const name = cleanText(c?.cisaVulnerabilityName ?? '', LIMITS.vulnName);
    if (!id || added === null || name === '') {
      stats.invalid++;
      continue;
    }
    if (added < from) {
      stats.outOfWindow++;
      continue;
    }
    items.push({
      source: 'nvd',
      id,
      title: name,
      description: cleanText(englishDescription(c.descriptions), LIMITS.description),
      kevAdded: added,
      kevDue: parseIsoDay(c.cisaActionDue),
      published: parseNvdTimestamp(c.published),
      cvss: bestCvss(c.metrics),
      date: added,
      link: nvdUrl(id),
    });
  }
  items.sort((a, b) => b.date - a.date || (a.id < b.id ? 1 : -1));
  stats.truncated = stats.total !== null && stats.total > list.length;
  return { items, stats: { ...stats, kept: items.length } };
}

/* ---------- EUVD (ENISA, exploited) ---------- */

function names(list, pick) {
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const x of list.slice(0, 50)) {
    const n = cleanText(pick(x) ?? '');
    if (n !== '' && !out.includes(n)) out.push(n);
  }
  return out;
}

// "Vendor: Product (+N)", without repeating the vendor when the product name
// already starts with it. Falls back to the description when nothing is named.
export function euvdThreat(item) {
  const products = names(item?.enisaIdProduct, (p) => p?.product?.name);
  const vendors = names(item?.enisaIdVendor, (v) => v?.vendor?.name);
  const firstProduct = Array.isArray(item?.enisaIdProduct) ? item.enisaIdProduct[0] : null;
  const vendor = cleanText(firstProduct?.product?.vendor?.name ?? '') || vendors[0] || '';

  let base;
  let suffix = '';
  if (products.length > 0) {
    const p = products[0];
    base = vendor && !p.toLowerCase().startsWith(vendor.toLowerCase()) ? `${vendor}: ${p}` : p;
    if (products.length > 1) suffix = ` (+${products.length - 1})`;
  } else if (vendor) {
    base = vendor;
  } else {
    base = item?.description ?? '';
  }
  return cleanText(base, LIMITS.vulnName - suffix.length) + suffix;
}

export function parseEuvd(jsonText, nowMs) {
  const data = JSON.parse(jsonText);
  const list = Array.isArray(data?.items) ? data.items.slice(0, MAX_JSON_ITEMS) : [];
  const from = windowStartMs(nowMs);
  const stats = {
    received: list.length,
    total: Number.isSafeInteger(data?.total) ? data.total : null,
    invalid: 0,
    outOfWindow: 0,
  };
  const items = [];
  for (const x of list) {
    const id = euvdId(x?.id);
    const exploited = parseEuvdDate(x?.exploitedSince);
    const title = euvdThreat(x);
    if (!id || exploited === null || title === '') {
      stats.invalid++;
      continue;
    }
    if (exploited < from) {
      stats.outOfWindow++;
      continue;
    }
    items.push({
      source: 'euvd',
      id,
      title,
      description: cleanText(x.description ?? '', LIMITS.description),
      cves: cveIdsFromAliases(x.aliases),
      baseScore: boundedNumber(x.baseScore, 0, 10),
      epss: boundedNumber(x.epss, 0, 100),
      exploitedSince: exploited,
      date: exploited,
      link: euvdUrl(id),
    });
  }
  items.sort((a, b) => b.date - a.date || (a.id < b.id ? 1 : -1));
  stats.needsMore = stats.total !== null && stats.total > list.length && list.length >= EUVD_PAGE_SIZE;
  return { items, stats: { ...stats, kept: items.length } };
}

// EUVD entries whose CVE aliases are already in the KEV list are not shown twice.
// Instead, what EUVD adds (European ID, link, EPSS) is attached to the KEV item.
// Returns new arrays and never mutates its inputs.
export function mergeEuvdIntoNvd(nvdItems, euvdItems) {
  const byCve = new Map(nvdItems.map((i) => [i.id, { ...i, euvd: null }]));
  const remaining = [];
  let merged = 0;
  for (const e of euvdItems) {
    const hit = e.cves.find((c) => byCve.has(c));
    if (hit === undefined) {
      remaining.push(e);
      continue;
    }
    merged++;
    const target = byCve.get(hit);
    if (target.euvd === null) target.euvd = { id: e.id, link: e.link, epss: e.epss };
  }
  return { nvd: [...byCve.values()], euvd: remaining, merged };
}

/* ---------- Orchestration ---------- */

async function runSource(name, url, accept, parse, ctx) {
  const res = await fetchText(url, { ...ctx.fetchOptions, accept, fetchImpl: ctx.fetchImpl });
  const entry = { source: name, ok: false, status: res.status, bytes: res.bytes, ms: res.ms };
  if (!res.ok) {
    ctx.log(JSON.stringify({ ...entry, error: res.error }));
    return { ok: false, error: res.error, items: [], stats: null };
  }
  let parsed;
  try {
    parsed = parse(res.text);
  } catch {
    ctx.log(JSON.stringify({ ...entry, error: 'parse' }));
    return { ok: false, error: 'parse', items: [], stats: null };
  }
  ctx.log(JSON.stringify({ ...entry, ok: true, items: parsed.items.length, ...parsed.stats }));
  return { ok: true, error: null, items: parsed.items, stats: parsed.stats };
}

async function collectEuvd(nowMs, ctx) {
  const first = await runSource('euvd', euvdSearchUrl(nowMs, 0), ACCEPT_JSON, (t) => parseEuvd(t, nowMs), ctx);
  if (!first.ok || !first.stats.needsMore) return first;
  // At most one extra page; anything beyond that is logged and left out
  const second = await runSource('euvd_p1', euvdSearchUrl(nowMs, 1), ACCEPT_JSON, (t) => parseEuvd(t, nowMs), ctx);
  if (!second.ok) return { ...first, partial: true };
  const seen = new Set(first.items.map((i) => i.id));
  const merged = [...first.items, ...second.items.filter((i) => !seen.has(i.id))];
  merged.sort((a, b) => b.date - a.date || (a.id < b.id ? 1 : -1));
  return { ...first, items: merged, partial: second.stats.needsMore };
}

// Fetches the requested sources in parallel, all six when 'only' is not given.
// A failed source yields { ok: false } and never affects the others; sources
// that were not requested are absent from the result. worker.js decides which
// sources are due, keeps the last good version of each and merges EUVD into KEV.
export async function collectAll(nowMs, options = {}) {
  const ctx = {
    fetchImpl: options.fetchImpl ?? globalThis.fetch,
    fetchOptions: options.fetchOptions ?? {},
    log: options.log ?? ((line) => console.log(line)),
  };

  const tasks = {
    nvd: () => runSource('nvd', nvdKevUrl(nowMs), ACCEPT_JSON, (t) => parseNvd(t, nowMs), ctx),
    euvd: () => collectEuvd(nowMs, ctx),
    wid: () => runSource('wid', FEEDS.wid, ACCEPT_RSS, parseWid, ctx),
    buergercert: () => runSource('buergercert', FEEDS.buergercert, ACCEPT_RSS, (t) => parseBuergercert(t), ctx),
    bits: () => runSource('bits', FEEDS.bits, ACCEPT_RSS, (t) => parseBsiFeed(t, 'bits'), ctx),
    presse: () => runSource('presse', FEEDS.presse, ACCEPT_RSS, (t) => parseBsiFeed(t, 'presse'), ctx),
  };

  const wanted = options.only === undefined ? null : new Set(options.only);
  const keys = Object.keys(tasks).filter((key) => wanted === null || wanted.has(key));
  const values = await Promise.all(keys.map((key) => tasks[key]()));
  return Object.fromEntries(keys.map((key, i) => [key, values[i]]));
}
