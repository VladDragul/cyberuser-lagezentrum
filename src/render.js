// Lagezentrum page renderer (/news).
//
// Pure: no I/O, no clock, no globals. The same input always gives the same
// output, which keeps the cron CPU budget predictable and the tests exact.
//
// The page reuses existing site components; style.css only gains the NEU mark:
//   .hero/.lead/.status  page head and the "Stand" line
//   .fp-section          one section per source (as on fingerabdruck.html)
//   .signals + .slip     SITREP cards: frosted panel with shadow (home page slip)
//   .fields/.field       THREAT/TARGET/STATUS/ACTION/LINK grid inside a card
//   .rules               frosted panel holding the compact BSI news lists
//   .noscript            small muted paragraph, reused for item descriptions
//   .print               NEU mark (fingerprint) on cards first seen in the last 24 h
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
import { windowStartMs } from './sources.js';
import { FINGERPRINT_VIEWBOX, FINGERPRINT_RIDGES } from './fingerprint.js';

/* ---------- Configuration ---------- */

// Must match the version string used by the static pages, so the browser cache is shared
export const STYLE_HREF = '/style.css?v=20261111f';
export const MAX_ITEMS_PER_SECTION = 50;
// An item counts as new for this long after the cron first saw it
export const NEW_WINDOW_MS = 86_400_000;
export const SOURCE_KEYS = Object.freeze(['nvd', 'euvd', 'wid', 'buergercert', 'bits', 'presse']);

const MAX_CVES_SHOWN = 5;
const SOURCE_STATES = new Set(['ok', 'stale', 'missing']);
// widRelevant in sources.js only ever keeps these
const WID_SEVERITIES = new Set(['hoch', 'kritisch']);
const WID_STATUSES = new Set(['NEU', 'UPDATE']);

export const ACTIONS = Object.freeze({
  kev: 'Betroffene Systeme ermitteln und das Sicherheitsupdate des Herstellers vorrangig einspielen. Die Schwachstelle wird bereits aktiv ausgenutzt.',
  euvd: 'Betroffene Systeme ermitteln und die Hinweise des Herstellers umsetzen. Die Schwachstelle wird laut ENISA ausgenutzt.',
  widCritical: 'Betroffene Systeme ermitteln und verfügbare Updates umgehend einspielen.',
  widHigh: 'Betroffene Systeme ermitteln und verfügbare Updates zeitnah einspielen.',
  widUnpatched:
    'Noch kein Update verfügbar. Hinweise des Herstellers zu Gegenmaßnahmen prüfen und betroffene Systeme absichern oder vom Netz trennen.',
  buergercert: 'Warnung lesen und betroffene Geräte und Programme aktualisieren.',
});

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

/* ---------- Formatting (manual, UTC, no Intl) ---------- */

const pad2 = (n) => (n < 10 ? '0' : '') + n;

function validDate(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDay(ms) {
  const d = validDate(ms);
  return d ? `${pad2(d.getUTCDate())}.${pad2(d.getUTCMonth() + 1)}.${d.getUTCFullYear()}` : null;
}

export function formatDateTime(ms) {
  const d = validDate(ms);
  return d ? `${formatDay(ms)} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())} UTC` : null;
}

// German decimal comma; with trim, trailing zeros after the comma are dropped
export function formatDecimal(n, digits, trim = false) {
  let s = n.toFixed(digits);
  if (trim && s.includes('.')) s = s.replace(/0+$/, '').replace(/\.$/, '');
  return s.replace('.', ',');
}

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

const epssText = (epss) => (epss === null ? '' : `EPSS ${formatDecimal(epss, 2, true)} %`);

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

// Defined once per page, and only when at least one card carries the mark
const FINGERPRINT_DEFS = html`<svg class="print-defs" width="0" height="0" aria-hidden="true" focusable="false"><symbol id="fp" viewBox="${FINGERPRINT_VIEWBOX}"><g fill="none" stroke="currentColor" stroke-linecap="round">${ridges.map(
  (r) => html`<path d="${r[0]}" stroke-opacity="${inRange(r[1], 0, 1, 1)}" stroke-width="${inRange(r[2], 0.5, 2, 1)}"/>`,
)}</g></symbol></svg>`;

const NEW_MARK = html`<span class="print" title="Seit weniger als 24 Stunden auf dieser Seite"><svg class="print-fp" viewBox="${FINGERPRINT_VIEWBOX}" aria-hidden="true" focusable="false"><use href="#fp"/></svg><span class="print-label">NEU</span></span>`;

/* ---------- Building blocks ---------- */

const field = (label, value) => html`<div class="field"><dt>${label}</dt><dd>${value}</dd></div>`;
const link = (href, text) => (href ? html`<a href="${href}" rel="noreferrer">${text}</a>` : '');

function card({ head, time, threat, target, status, action, links, description, lang, fresh, href, anchor }) {
  // The threat text links to the primary source; CSS stretches this link over the whole card
  const threatCell = href ? html`<a class="slip-link" href="${href}" rel="noreferrer">${threat}</a>` : threat;
  let desc = '';
  if (description !== '') {
    desc = lang
      ? html`<p class="noscript" lang="${lang}">${description}</p>`
      : html`<p class="noscript">${description}</p>`;
  }
  // The anchor lets the homepage link to this exact card
  const open = anchor ? html`<li id="${anchor}">` : html`<li>`;
  return html`${open}<article class="slip">
<div class="slip-head"><span>${head}</span><span class="slip-time">${time}</span></div>
<dl class="fields">${field('THREAT', threatCell)}${field('TARGET', target)}${field('STATUS', status)}${field('ACTION', action)}${field('LINK', joinParts(links, ' · '))}</dl>
${desc}${fresh ? NEW_MARK : ''}
</article></li>`;
}

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

/* ---------- Per-source items (null = invalid, not rendered) ---------- */

function kevCard(item, fresh = false) {
  const id = cveId(item?.id);
  if (!id || !validDate(item.kevAdded)) return null;
  const due = validDate(item.kevDue) ? item.kevDue : null;
  const euvd = euvdId(item.euvd?.id);
  const epss = euvd ? boundedNumber(item.euvd.epss, 0, 100) : null;
  return {
    id,
    html: card({
      head: 'CISA KEV',
      time: timeTag(item.kevAdded, false),
      threat: cleanText(item.title, LIMITS.vulnName) || id,
      target: joinParts([id, cvssText(item.cvss?.score, item.cvss?.version)], ', '),
      status: joinParts(
        ['Aktiv ausgenutzt', due === null ? '' : html`CISA-Frist ${timeTag(due, false)}`, epssText(epss)],
        ', ',
      ),
      action: ACTIONS.kev,
      href: nvdUrl(id),
      anchor: newsAnchor('nvd', id),
      links: [link(nvdUrl(id), 'NVD'), link(euvdUrl(euvd), 'EUVD')],
      description: cleanText(item.description, LIMITS.description),
      lang: 'en',
      fresh,
    }),
  };
}

function euvdCard(item, kevIds, fresh = false) {
  const id = euvdId(item?.id);
  if (!id || !validDate(item.exploitedSince)) return null;
  const cves = Array.isArray(item.cves) ? [...new Set(item.cves.slice(0, 50).filter((c) => cveId(c) !== null))] : [];
  // Already shown in the KEV section (also covers a stale EUVD copy that was never merged)
  if (cves.some((c) => kevIds.has(c))) return null;
  const shown = cves.slice(0, MAX_CVES_SHOWN).join(', ');
  const more = cves.length > MAX_CVES_SHOWN ? ` (+${cves.length - MAX_CVES_SHOWN})` : '';
  return card({
    head: 'ENISA EUVD',
    time: timeTag(item.exploitedSince, false),
    threat: cleanText(item.title, LIMITS.vulnName) || id,
    target: joinParts([cves.length > 0 ? shown + more : id, cvssText(item.baseScore, null)], ', '),
    status: joinParts(['Laut ENISA ausgenutzt', epssText(boundedNumber(item.epss, 0, 100))], ', '),
    action: ACTIONS.euvd,
    href: euvdUrl(id),
    links: [link(euvdUrl(id), 'EUVD'), cves.length > 0 ? link(nvdUrl(cves[0]), 'NVD') : ''],
    description: cleanText(item.description, LIMITS.description),
    lang: 'en',
    fresh,
  });
}

function widCard(item, fresh = false) {
  const id = widId(item?.id);
  const severity = item?.severity;
  const status = item?.status;
  if (!id || !WID_SEVERITIES.has(severity) || !WID_STATUSES.has(status) || !validDate(item.date)) return null;
  const unpatched = item.unpatched === true;
  let action = ACTIONS.widHigh;
  if (unpatched) action = ACTIONS.widUnpatched;
  else if (severity === 'kritisch') action = ACTIONS.widCritical;
  return card({
    head: 'CERT-Bund WID',
    time: timeTag(item.date, true),
    threat: cleanText(item.title, LIMITS.title) || id,
    target: id,
    status: joinParts(
      [status === 'NEU' ? 'Erstmeldung' : 'Aktualisiert', `Schweregrad ${severity}`, unpatched ? html`<strong>UNGEPATCHT</strong>` : ''],
      ', ',
    ),
    action,
    href: widUrl(id),
    anchor: newsAnchor('wid', id),
    links: [link(widUrl(id), 'WID')],
    description: cleanText(item.description, LIMITS.description),
    lang: null,
    fresh,
  });
}

function buergercertCard(item, fresh = false) {
  const id = uuid(item?.id);
  const title = cleanText(item?.title, LIMITS.title);
  if (!id || title === '' || !validDate(item.date)) return null;
  return card({
    head: 'Bürger-CERT',
    time: timeTag(item.date, true),
    threat: title,
    target: 'Privatanwender',
    status: 'Aktuelle Warnung',
    action: ACTIONS.buergercert,
    href: buergercertUrl(id),
    links: [link(buergercertUrl(id), 'Bürger-CERT')],
    description: cleanText(item.description, LIMITS.description),
    lang: null,
    fresh,
  });
}

function newsItem(item, fresh = false) {
  const title = cleanText(item?.title, LIMITS.title);
  if (title === '' || !validDate(item.date)) return null;
  const href = safeBsiUrl(item.link);
  return html`<li>${fresh ? html`<strong>NEU</strong> ` : ''}${timeTag(item.date, true)}: ${href ? link(href, title) : title}</li>`;
}

/* ---------- Sections ---------- */

function normalizeSource(input) {
  const state = SOURCE_STATES.has(input?.state) ? input.state : 'missing';
  const items = state !== 'missing' && Array.isArray(input.items) ? input.items.slice(0, MAX_ITEMS_PER_SECTION) : [];
  return { state, asOf: input?.asOf ?? null, items };
}

function mapValid(items, fn) {
  const out = [];
  for (const item of items) {
    const r = fn(item);
    if (r !== null) out.push(r);
  }
  return out;
}

function sourceNotice(src) {
  if (src.state === 'stale') {
    return html`<p class="status">QUELLE NICHT ERREICHBAR, STAND: ${formatDateTime(src.asOf) ?? 'UNBEKANNT'}</p>`;
  }
  if (src.state === 'missing') return html`<p class="status">QUELLE NICHT ERREICHBAR, KEINE DATEN</p>`;
  return '';
}

const cardList = (entries) => html`<ul class="signals">${entries}</ul>`;
const newsList = (entries) => html`<div class="rules"><ul>${entries}</ul></div>`;

function section(key, meta, src, entries, wrap) {
  let body = '';
  if (src.state !== 'missing') body = entries.length > 0 ? wrap(entries) : html`<p>${meta.empty}</p>`;
  return html`<section class="fp-section" id="${key}" aria-labelledby="${key}-title">
<h2 id="${key}-title">${meta.title}</h2>
<p>${meta.intro}</p>
${sourceNotice(src)}${body}
</section>
`;
}

function sectionTexts(nowMs) {
  const since = formatDay(validDate(nowMs) ? windowStartMs(nowMs) : NaN);
  const window = since ? ` Zeitraum: seit dem ${since}.` : '';
  return {
    nvd: {
      title: 'Aktiv ausgenutzte Schwachstellen',
      intro: `Neu im Katalog „Known Exploited Vulnerabilities“ der US-Behörde CISA, mit Daten aus der NVD und, wo vorhanden, aus der europäischen Schwachstellendatenbank EUVD.${window}`,
      empty: 'Im Zeitraum wurden keine neuen Einträge aufgenommen.',
    },
    euvd: {
      title: 'Weitere ausgenutzte Schwachstellen (EUVD)',
      intro: `Von der ENISA als ausgenutzt markiert und nicht bereits oben im KEV-Katalog aufgeführt.${window}`,
      empty: 'Keine weiteren Einträge. Was auch im KEV-Katalog steht, ist oben aufgeführt.',
    },
    wid: {
      title: 'Sicherheitshinweise des CERT-Bund',
      intro:
        'Aus dem Warn- und Informationsdienst (WID) des BSI: alle kritischen Hinweise sowie hohe, wenn sie neu sind oder noch kein Update existiert.',
      empty: 'Im aktuellen Feed stehen keine Hinweise dieser Stufen.',
    },
    buergercert: {
      title: 'Warnungen für Privatanwender',
      intro: 'Die neuesten Warnungen des Bürger-CERT im BSI.',
      empty: 'Der Feed enthält derzeit keine Warnungen.',
    },
    bits: {
      title: 'Cybersicherheitswarnungen des BSI',
      intro: 'Die neuesten Warnungen von der Website des BSI.',
      empty: 'Der Feed enthält derzeit keine Meldungen.',
    },
    presse: {
      title: 'Presse und Veranstaltungen des BSI',
      intro: 'Die neuesten Pressemitteilungen und Veranstaltungshinweise des BSI.',
      empty: 'Der Feed enthält derzeit keine Meldungen.',
    },
  };
}

/* ---------- Page ---------- */

// input: { nowMs, sources: { nvd, euvd, wid, buergercert, bits, presse } }
// each source: { state: 'ok' | 'stale' | 'missing', asOf: epoch ms, items: [...] }
// seen (optional): { [source]: { [itemKey]: firstSeenMs } } from worker.js, for NEU
// Fallback decisions (which copy is shown) are made by worker.js, not here.
export function renderPage({ nowMs, sources, seen } = {}) {
  const src = {};
  for (const key of SOURCE_KEYS) src[key] = normalizeSource(sources?.[key]);
  const t = sectionTexts(nowMs);

  const kevIds = new Set();
  const kevCards = [];
  for (const item of src.nvd.items) {
    const c = kevCard(item, isFresh(seen, 'nvd', item, nowMs));
    if (c === null) continue;
    kevIds.add(c.id);
    kevCards.push(c.html);
  }

  const sections = [
    section('nvd', t.nvd, src.nvd, kevCards, cardList),
    section('euvd', t.euvd, src.euvd, mapValid(src.euvd.items, (i) => euvdCard(i, kevIds, isFresh(seen, 'euvd', i, nowMs))), cardList),
    section('wid', t.wid, src.wid, mapValid(src.wid.items, (i) => widCard(i, isFresh(seen, 'wid', i, nowMs))), cardList),
    section('buergercert', t.buergercert, src.buergercert, mapValid(src.buergercert.items, (i) => buergercertCard(i, isFresh(seen, 'buergercert', i, nowMs))), cardList),
    section('bits', t.bits, src.bits, mapValid(src.bits.items, (i) => newsItem(i, isFresh(seen, 'bits', i, nowMs))), newsList),
    section('presse', t.presse, src.presse, mapValid(src.presse.items, (i) => newsItem(i, isFresh(seen, 'presse', i, nowMs))), newsList),
  ];

  // Item text is escaped, so this marker can only come from NEW_MARK
  const marked = fragment(sections).includes('<span class="print"');

  const page = html`<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyberuser | Lagezentrum</title>
<link rel="icon" href="/favicon.ico?v=2">
<meta name="description" content="Aktuelle Warnungen und aktiv ausgenutzte Schwachstellen aus offiziellen Quellen: CISA, NIST, ENISA, CERT-Bund und BSI. Automatisch zusammengestellt, ohne KI.">
<meta name="color-scheme" content="dark">
<link rel="canonical" href="https://cyberuser.de/news">
<link rel="stylesheet" href="${STYLE_HREF}">
</head>
<body class="page-news">
${marked ? FINGERPRINT_DEFS : ''}
<header class="site">
  <a class="brand" href="/">cyberuser.de</a>
</header>

<main>
<section class="hero" aria-labelledby="hero-title">
  <h1 id="hero-title">Lagezentrum</h1>
  <p class="lead">Aktuelle Warnungen und aktiv ausgenutzte Schwachstellen, direkt aus offiziellen Quellen: CISA und NIST (USA), ENISA (EU), CERT-Bund und BSI. Die Seite wird stündlich automatisch erstellt (NVD-Daten alle zwei Stunden), ohne KI und ohne eigene Bewertung. Maßgeblich ist immer die verlinkte Originalmeldung.</p>
  <p class="status">Stand: ${timeTag(nowMs, true)}</p>
</section>

${sections}</main>

<footer class="site">
  <a href="/">Startseite</a>
  <a href="/impressum.html">Impressum</a>
  <a href="/datenschutz.html">Datenschutz</a>
  <a href="/kontakt.html">Kontakt</a>
  <span class="badges"><a href="https://internet.nl/"><img src="/badge-internetnl-web.svg" alt="Internet.nl: 100 % im Website-Test" width="204" height="38"></a><a href="https://internet.nl/"><img src="/badge-internetnl-mail.svg" alt="Internet.nl: 100 % im E-Mail-Test" width="204" height="39"></a></span>
</footer>

</body>
</html>
`;
  return '<!doctype html>\n' + page.value;
}

/* ---------- Homepage brief ---------- */

// Newest entries per source in the homepage brief
export const BRIEF_COUNTS = Object.freeze({ nvd: 5, wid: 5 });

// Anchor of a card on /news: section key plus the validated item id
export const newsAnchor = (key, id) => `${key}-${id}`;

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

function briefItem({ head, time, title, id, href, fresh }) {
  return html`<li class="lage-item">
<div class="slip-head"><span>${head}</span><span class="slip-time">${time}</span></div>
<p class="lage-title">${href ? html`<a class="slip-link" href="${href}">${title}</a>` : title}</p>
<p class="lage-id">${id}</p>${fresh ? NEW_MARK : ''}
</li>`;
}

// Same validation as kevCard, so an item shows here only if /news shows it too
function kevBrief(item, fresh) {
  const id = cveId(item?.id);
  if (!id || !validDate(item.kevAdded)) return null;
  return briefItem({
    head: 'CISA KEV',
    time: timeTag(item.kevAdded, false),
    title: cleanText(item.title, LIMITS.vulnName) || id,
    id: joinParts([id, cvssText(item.cvss?.score, item.cvss?.version)], ', '),
    // Homepage cards open the matching card on /news, which links to the source
    href: `/news#${newsAnchor('nvd', id)}`,
    fresh,
  });
}

// Same validation as widCard
function widBrief(item, fresh) {
  const id = widId(item?.id);
  const severity = item?.severity;
  if (!id || !WID_SEVERITIES.has(severity) || !WID_STATUSES.has(item?.status) || !validDate(item.date)) return null;
  return briefItem({
    head: 'CERT-Bund WID',
    time: timeTag(item.date, true),
    title: cleanText(item.title, LIMITS.title) || id,
    id: joinParts([id, `Schweregrad ${severity}`, item.unpatched === true ? html`<strong>UNGEPATCHT</strong>` : ''], ', '),
    href: `/news#${newsAnchor('wid', id)}`,
    fresh,
  });
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

// Short HTML fragment for the homepage. Same input as renderPage; returns a
// string without <html>/<body>, to be placed between the homepage markers.
export function renderBrief({ nowMs, sources, seen } = {}) {
  const nvd = normalizeSource(sources?.nvd);
  const wid = normalizeSource(sources?.wid);

  const kev = pickNewest(nvd.items, (i) => i?.kevAdded, (i) => kevBrief(i, isFresh(seen, 'nvd', i, nowMs)), BRIEF_COUNTS.nvd);
  const bsi = pickNewest(wid.items, (i) => i?.date, (i) => widBrief(i, isFresh(seen, 'wid', i, nowMs)), BRIEF_COUNTS.wid);

  const groups = [
    briefGroup('Aktiv ausgenutzte Schwachstellen', nvd, kev),
    briefGroup('Hinweise des CERT-Bund', wid, bsi),
  ];

  // Item text is escaped, so this marker can only come from NEW_MARK
  const marked = fragment(groups).includes('<span class="print"');

  return html`<aside class="lage" aria-labelledby="lage-title">
${marked ? FINGERPRINT_DEFS : ''}<div class="lage-col lage-col-kev">
<h2 id="lage-title">Sicherheitslage</h2>
<p class="status">Stand: ${timeTag(nowMs, true)}</p>
${groups[0]}</div>
<div class="lage-col lage-col-wid">
<p class="status">Stand: ${timeTag(nowMs, true)}</p>
${groups[1]}${kev.length + bsi.length === 0 ? html`<p class="lage-more"><a href="/news">Gesamte Lage ansehen</a></p>` : ''}
<p class="lage-sources">Quellen: CISA, NIST (NVD), CERT-Bund (BSI)</p>
</div>
</aside>
`.value;
}
