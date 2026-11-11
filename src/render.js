// Homepage brief renderer: the "Sicherheitslage" cards on cyberuser.de.
//
// Pure: no I/O, no clock, no globals. The same input always gives the same
// output, which keeps the cron CPU budget predictable and the tests exact.
//
// The output is an HTML fragment. worker.js stores it in KV and places it
// between the markers of the homepage that nginx serves. It only uses classes
// that style.css on the static site already defines:
//   .lage, .lage-col        the two columns
//   .lage-list, .lage-item  one small card per entry
//   .slip-head, .slip-time  source and date line of a card
//   .lage-title, .lage-id   title (linked to the source) and the ID line
//   .status                 "Stand" line and outage notices
//   .print                  NEU mark (fingerprint) on entries first seen in the last 24 h
//
// Safety model:
//   - Every interpolated value goes through the html tag and escapeHtml.
//     Only fragments produced by the tag itself are inserted unescaped.
//   - Links are never taken from stored items. They are rebuilt here from
//     validated IDs (NVD, EUVD, WID, Buerger-CERT) or re-checked with
//     safeBsiUrl, so a corrupted KV entry cannot inject markup or URLs.
//   - Text is cleaned and length-limited again, for the same reason.

import {
  LIMITS,
  cleanText,
  escapeHtml,
  boundedNumber,
  cveId,
  widId,
  euvdId,
  uuid,
  nvdUrl,
  euvdUrl,
  widUrl,
  buergercertUrl,
  safeBsiUrl,
} from './sanitize.js';
import { FINGERPRINT_VIEWBOX, FINGERPRINT_RIDGES } from './fingerprint.js';

/* ---------- Configuration ---------- */

// Cards shown per source, newest first
export const MAX_ITEMS_PER_SECTION = 50;
// An item counts as new for this long after the cron first saw it
export const NEW_WINDOW_MS = 86_400_000;
export const SOURCE_KEYS = Object.freeze(['nvd', 'euvd', 'wid', 'buergercert', 'bits', 'presse']);

// Upper bound on stored items looked at per source before sorting
const MAX_ITEMS_READ = 500;
const MAX_CVES_READ = 50;
const MAX_CVES_SHOWN = 5;
const SOURCE_STATES = new Set(['ok', 'stale', 'missing']);
// widRelevant in sources.js only ever keeps these
const WID_SEVERITIES = new Set(['hoch', 'kritisch']);
const WID_STATUSES = new Set(['NEU', 'UPDATE']);

/* ---------- Escaping template tag ---------- */

// Not exported: the only way to obtain trusted markup is through the html tag.
class SafeHtml {
  constructor(value) {
    this.value = value;
  }
}

function fragment(value) {
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) {
    let out = '';
    for (const v of value) out += fragment(v);
    return out;
  }
  // Strings and numbers are escaped; null, undefined, booleans and objects render as ''
  return escapeHtml(value);
}

export function html(strings, ...values) {
  let out = strings[0];
  for (let i = 0; i < values.length; i++) out += fragment(values[i]) + strings[i + 1];
  return new SafeHtml(out);
}

/* ---------- Formatting ---------- */

const pad2 = (n) => (n < 10 ? '0' : '') + n;

function validDate(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d;
}

// Calendar dates without a time of day (KEV added, EUVD exploited since) stay in UTC
export function formatDay(ms) {
  const d = validDate(ms);
  return d ? `${pad2(d.getUTCDate())}.${pad2(d.getUTCMonth() + 1)}.${d.getUTCFullYear()}` : null;
}

// Created once: constructing the formatter is the expensive part. Only the
// numeric parts are used, so the result does not depend on the locale data of
// the runtime, only on its time zone data.
const BERLIN = new Intl.DateTimeFormat('en-US', {
  timeZone: 'Europe/Berlin',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  hourCycle: 'h23',
});

// Date and time as read in Germany (Europe/Berlin, daylight saving included)
export function formatDateTime(ms) {
  const d = validDate(ms);
  if (!d) return null;
  const p = {};
  for (const part of BERLIN.formatToParts(d)) p[part.type] = part.value;
  return `${p.day}.${p.month}.${p.year} ${p.hour}:${p.minute} Uhr`;
}

// German decimal comma; with trim, trailing zeros after the comma are dropped
export function formatDecimal(n, digits, trim = false) {
  let s = n.toFixed(digits);
  if (trim && s.includes('.')) s = s.replace(/0+$/, '').replace(/\.$/, '');
  return s.replace('.', ',');
}

// The datetime attribute is always ISO in UTC; only the visible text is local
function timeTag(ms, withTime) {
  const d = validDate(ms);
  if (!d) return 'unbekannt';
  const iso = d.toISOString();
  return withTime
    ? html`<time datetime="${iso}">${formatDateTime(ms)}</time>`
    : html`<time datetime="${iso.slice(0, 10)}">${formatDay(ms)}</time>`;
}

function cvssText(score, version) {
  const s = boundedNumber(score, 0, 10);
  if (s === null) return '';
  const v = typeof version === 'string' && /^\d\.\d$/.test(version) ? ` (v${version})` : '';
  return `CVSS ${formatDecimal(s, 1)}${v}`;
}

// Joins the non-empty parts with a separator
function joinParts(parts, sep) {
  const out = [];
  for (const p of parts) {
    if (p === '') continue;
    if (out.length > 0) out.push(sep);
    out.push(p);
  }
  return out;
}

/* ---------- NEU mark ---------- */

// The ridge data lives in this repository, but it is still checked and escaped
// here: markup reaches the page only through the html tag.
const RIDGE_PATH = /^M[0-9. ]{1,4000}$/;
const inRange = (n, min, max, fallback) => (typeof n === 'number' && n >= min && n <= max ? n : fallback);
const ridges = FINGERPRINT_RIDGES.filter((r) => Array.isArray(r) && typeof r[0] === 'string' && RIDGE_PATH.test(r[0]));

// Defined once per fragment, and only when at least one card carries the mark
const FINGERPRINT_DEFS = html`<svg class="print-defs" width="0" height="0" aria-hidden="true" focusable="false"><symbol id="fp" viewBox="${FINGERPRINT_VIEWBOX}"><g fill="none" stroke="currentColor" stroke-linecap="round">${ridges.map(
  (r) => html`<path d="${r[0]}" stroke-opacity="${inRange(r[1], 0, 1, 1)}" stroke-width="${inRange(r[2], 0.5, 2, 1)}"/>`,
)}</g></symbol></svg>`;

const NEW_MARK = html`<span class="print" title="Seit weniger als 24 Stunden auf dieser Seite"><svg class="print-fp" viewBox="${FINGERPRINT_VIEWBOX}" aria-hidden="true" focusable="false"><use href="#fp"/></svg><span class="print-label">NEU</span></span>`;

/* ---------- Item identity (shared with worker.js) ---------- */

// The key under which worker.js remembers when an item was first seen. The
// validators are the same as for the cards, so a key exists exactly when the
// item can be shown.
export function itemKey(sourceKey, item) {
  let k = null;
  switch (sourceKey) {
    case 'nvd':
      k = cveId(item?.id);
      break;
    case 'euvd':
      k = euvdId(item?.id);
      break;
    case 'wid':
      k = widId(item?.id);
      break;
    case 'buergercert':
      k = uuid(item?.id);
      break;
    case 'bits':
    case 'presse':
      k = safeBsiUrl(item?.link);
      break;
    default:
      k = null;
  }
  return typeof k === 'string' && k !== '' && k !== '__proto__' ? k : null;
}

// New = first seen by the cron less than NEW_WINDOW_MS ago. The value 0 marks
// items that were already there when a source got its first map (never new).
export function isFresh(seen, sourceKey, item, nowMs) {
  const map = seen?.[sourceKey];
  if (map === null || typeof map !== 'object' || Array.isArray(map)) return false;
  const k = itemKey(sourceKey, item);
  if (k === null || !Object.hasOwn(map, k)) return false;
  const t = map[k];
  return typeof t === 'number' && Number.isFinite(t) && t > 0 && t <= nowMs && nowMs - t < NEW_WINDOW_MS;
}

/* ---------- Ordering ---------- */

// Sort newest first without trusting the feed order; invalid dates go last,
// ties keep their original order
function newestFirst(items, dateOf) {
  return items
    .map((item, index) => {
      const ms = dateOf(item);
      return { item, index, t: validDate(ms) ? ms : -Infinity };
    })
    .sort((a, b) => b.t - a.t || a.index - b.index)
    .map((e) => e.item);
}

// Take the newest `count` items that pass validation (toEntry returns null otherwise)
function pickNewest(items, dateOf, toEntry, count) {
  const out = [];
  for (const item of newestFirst(items, dateOf)) {
    if (out.length >= count) break;
    const entry = toEntry(item);
    if (entry !== null) out.push(entry);
  }
  return out;
}

/* ---------- Cards (null = invalid, not rendered) ---------- */

// One card for every source: source and date, title linked to the original
// publication, and a last line that is never empty
function briefItem({ head, time, title, id, href, fresh }) {
  return html`<li class="lage-item">
<div class="slip-head"><span>${head}</span><span class="slip-time">${time}</span></div>
<p class="lage-title">${href ? html`<a class="slip-link" href="${href}" rel="noopener noreferrer">${title}</a>` : title}</p>
<p class="lage-id">${id}</p>${fresh ? NEW_MARK : ''}
</li>`;
}

function kevBrief(item, fresh) {
  const id = cveId(item?.id);
  if (!id || !validDate(item.kevAdded)) return null;
  return briefItem({
    head: 'CISA KEV',
    time: timeTag(item.kevAdded, false),
    title: cleanText(item.title, LIMITS.vulnName) || id,
    id: joinParts([id, cvssText(item.cvss?.score, item.cvss?.version)], ', '),
    href: nvdUrl(id),
    fresh,
  });
}

function euvdBrief(item, kevIds, fresh) {
  const id = euvdId(item?.id);
  if (!id || !validDate(item.exploitedSince)) return null;
  const cves = Array.isArray(item.cves)
    ? [...new Set(item.cves.slice(0, MAX_CVES_READ).filter((c) => cveId(c) !== null))]
    : [];
  // Already shown as a KEV card (also covers an EUVD copy that was never merged)
  if (cves.some((c) => kevIds.has(c))) return null;
  const shown = cves.slice(0, MAX_CVES_SHOWN).join(', ');
  const more = cves.length > MAX_CVES_SHOWN ? ` (+${cves.length - MAX_CVES_SHOWN})` : '';
  return briefItem({
    head: 'ENISA EUVD',
    time: timeTag(item.exploitedSince, false),
    title: cleanText(item.title, LIMITS.vulnName) || id,
    id: joinParts([cves.length > 0 ? shown + more : id, cvssText(item.baseScore, null)], ', '),
    href: euvdUrl(id),
    fresh,
  });
}

function widBrief(item, fresh) {
  const id = widId(item?.id);
  const severity = item?.severity;
  if (!id || !WID_SEVERITIES.has(severity) || !WID_STATUSES.has(item?.status) || !validDate(item.date)) return null;
  return briefItem({
    head: 'CERT-Bund WID',
    time: timeTag(item.date, true),
    title: cleanText(item.title, LIMITS.title) || id,
    // only a literal true counts as unpatched
    id: joinParts([id, `Schweregrad ${severity}`, item.unpatched === true ? html`<strong>UNGEPATCHT</strong>` : ''], ', '),
    href: widUrl(id),
    fresh,
  });
}

function buergercertBrief(item, fresh) {
  const id = uuid(item?.id);
  const title = cleanText(item?.title, LIMITS.title);
  if (!id || title === '' || !validDate(item.date)) return null;
  return briefItem({
    head: 'Bürger-CERT',
    time: timeTag(item.date, true),
    title,
    id: 'Warnung für Privatanwender',
    href: buergercertUrl(id),
    fresh,
  });
}

// Both BSI website feeds. The link is the only one taken from a feed; when
// safeBsiUrl rejects it, the title is shown without a link.
function bsiBrief(item, head, label, fresh) {
  const title = cleanText(item?.title, LIMITS.title);
  if (title === '' || !validDate(item.date)) return null;
  return briefItem({
    head,
    time: timeTag(item.date, true),
    title,
    id: label,
    href: safeBsiUrl(item.link),
    fresh,
  });
}

/* ---------- Groups ---------- */

function normalizeSource(input) {
  const state = SOURCE_STATES.has(input?.state) ? input.state : 'missing';
  const items = state !== 'missing' && Array.isArray(input.items) ? input.items.slice(0, MAX_ITEMS_READ) : [];
  return { state, asOf: input?.asOf ?? null, items };
}

function sourceNotice(src) {
  if (src.state === 'stale') {
    return html`<p class="status">QUELLE NICHT ERREICHBAR, STAND: ${formatDateTime(src.asOf) ?? 'UNBEKANNT'}</p>`;
  }
  if (src.state === 'missing') return html`<p class="status">QUELLE NICHT ERREICHBAR, KEINE DATEN</p>`;
  return '';
}

function briefGroup(title, src, entries) {
  let body = '';
  if (src.state !== 'missing') {
    body = entries.length > 0 ? html`<ul class="lage-list">${entries}</ul>` : html`<p>Derzeit keine Einträge.</p>`;
  }
  return html`<h3>${title}</h3>
${sourceNotice(src)}${body}
`;
}

/* ---------- Homepage brief ---------- */

// input: { nowMs, sources: { nvd, euvd, wid, buergercert, bits, presse } }
// each source: { state: 'ok' | 'stale' | 'missing', asOf: epoch ms, items: [...] }
// seen (optional): { [source]: { [itemKey]: firstSeenMs } } from worker.js, for NEU
// Fallback decisions (which copy is shown) are made by worker.js, not here.
//
// Returns a string without <html>/<body>, to be placed between the homepage
// markers. Left column: exploited vulnerabilities (KEV, then EUVD entries that
// are not in KEV). Right column: the German sources.
export function renderBrief({ nowMs, sources, seen } = {}) {
  const src = {};
  for (const key of SOURCE_KEYS) src[key] = normalizeSource(sources?.[key]);

  const fresh = (key, item) => isFresh(seen, key, item, nowMs);
  const newest = (key, dateOf, toEntry) => pickNewest(src[key].items, dateOf, toEntry, MAX_ITEMS_PER_SECTION);
  const byDate = (i) => i?.date;

  // Only CVEs that really got a KEV card hide their EUVD entry
  const kevIds = new Set();
  const kev = newest(
    'nvd',
    (i) => i?.kevAdded,
    (i) => {
      const entry = kevBrief(i, fresh('nvd', i));
      if (entry !== null) kevIds.add(i.id);
      return entry;
    },
  );
  const euvd = newest('euvd', (i) => i?.exploitedSince, (i) => euvdBrief(i, kevIds, fresh('euvd', i)));
  const wid = newest('wid', byDate, (i) => widBrief(i, fresh('wid', i)));
  const buergercert = newest('buergercert', byDate, (i) => buergercertBrief(i, fresh('buergercert', i)));
  const bits = newest('bits', byDate, (i) => bsiBrief(i, 'BSI', 'Cybersicherheitswarnung', fresh('bits', i)));
  const presse = newest('presse', byDate, (i) => bsiBrief(i, 'BSI Presse', 'Presse und Veranstaltungen', fresh('presse', i)));

  const left = [
    briefGroup('Aktiv ausgenutzte Schwachstellen', src.nvd, kev),
    briefGroup('Weitere ausgenutzte Schwachstellen (EUVD)', src.euvd, euvd),
  ];
  const right = [
    briefGroup('Hinweise des CERT-Bund', src.wid, wid),
    briefGroup('Warnungen für Privatanwender', src.buergercert, buergercert),
    briefGroup('Cybersicherheitswarnungen des BSI', src.bits, bits),
    briefGroup('Presse und Veranstaltungen des BSI', src.presse, presse),
  ];

  // Item text is escaped, so this marker can only come from NEW_MARK
  const marked = fragment([left, right]).includes('<span class="print"');

  return html`<aside class="lage" aria-labelledby="lage-title">
${marked ? FINGERPRINT_DEFS : ''}<div class="lage-col lage-col-kev">
<h2 id="lage-title">Sicherheitslage</h2>
<p class="status">Stand: ${timeTag(nowMs, true)}</p>
${left}</div>
<div class="lage-col lage-col-wid">
<p class="status">Stand: ${timeTag(nowMs, true)}</p>
${right}<p class="lage-sources">Quellen: CISA, NIST (NVD), ENISA (EUVD), CERT-Bund, BSI</p>
</div>
</aside>
`.value;
}
