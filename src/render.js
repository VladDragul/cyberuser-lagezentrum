// Lagezentrum page renderer (/news).
//
// Pure: no I/O, no clock, no globals. The same input always gives the same
// output, which keeps the cron CPU budget predictable and the tests exact.
//
// The page reuses existing site components only; style.css is not changed:
//   .hero/.lead/.status  page head and the "Stand" line
//   .fp-section          one section per source (as on fingerabdruck.html)
//   .signals + .slip     SITREP cards: frosted panel with shadow (home page slip)
//   .fields/.field       THREAT/TARGET/STATUS/ACTION/LINK grid inside a card
//   .rules               frosted panel holding the compact BSI news lists
//   .noscript            small muted paragraph, reused for item descriptions
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

/* ---------- Configuration ---------- */

// Must match the version string used by the static pages, so the browser cache is shared
export const STYLE_HREF = '/style.css?v=20261109m';
export const MAX_ITEMS_PER_SECTION = 50;
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

/* ---------- Building blocks ---------- */

const field = (label, value) => html`<div class="field"><dt>${label}</dt><dd>${value}</dd></div>`;
const link = (href, text) => (href ? html`<a href="${href}" rel="noreferrer">${text}</a>` : '');

function card({ head, time, threat, target, status, action, links, description, lang }) {
  let desc = '';
  if (description !== '') {
    desc = lang
      ? html`<p class="noscript" lang="${lang}">${description}</p>`
      : html`<p class="noscript">${description}</p>`;
  }
  return html`<li><article class="slip">
<div class="slip-head"><span>${head}</span><span class="slip-time">${time}</span></div>
<dl class="fields">${field('THREAT', threat)}${field('TARGET', target)}${field('STATUS', status)}${field('ACTION', action)}${field('LINK', joinParts(links, ' · '))}</dl>
${desc}
</article></li>`;
}

/* ---------- Per-source items (null = invalid, not rendered) ---------- */

function kevCard(item) {
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
      links: [link(nvdUrl(id), 'NVD'), link(euvdUrl(euvd), 'EUVD')],
      description: cleanText(item.description, LIMITS.description),
      lang: 'en',
    }),
  };
}

function euvdCard(item, kevIds) {
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
    links: [link(euvdUrl(id), 'EUVD'), cves.length > 0 ? link(nvdUrl(cves[0]), 'NVD') : ''],
    description: cleanText(item.description, LIMITS.description),
    lang: 'en',
  });
}

function widCard(item) {
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
      [status === 'NEU' ? 'Neu' : 'Aktualisiert', `Schweregrad ${severity}`, unpatched ? html`<strong>UNGEPATCHT</strong>` : ''],
      ', ',
    ),
    action,
    links: [link(widUrl(id), 'WID')],
    description: cleanText(item.description, LIMITS.description),
    lang: null,
  });
}

function buergercertCard(item) {
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
    links: [link(buergercertUrl(id), 'Bürger-CERT')],
    description: cleanText(item.description, LIMITS.description),
    lang: null,
  });
}

function newsItem(item) {
  const title = cleanText(item?.title, LIMITS.title);
  if (title === '' || !validDate(item.date)) return null;
  const href = safeBsiUrl(item.link);
  return html`<li>${timeTag(item.date, true)}: ${href ? link(href, title) : title}</li>`;
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
// Fallback decisions (which copy is shown) are made by index.js, not here.
export function renderPage({ nowMs, sources } = {}) {
  const src = {};
  for (const key of SOURCE_KEYS) src[key] = normalizeSource(sources?.[key]);
  const t = sectionTexts(nowMs);

  const kevIds = new Set();
  const kevCards = [];
  for (const item of src.nvd.items) {
    const c = kevCard(item);
    if (c === null) continue;
    kevIds.add(c.id);
    kevCards.push(c.html);
  }

  const sections = [
    section('nvd', t.nvd, src.nvd, kevCards, cardList),
    section('euvd', t.euvd, src.euvd, mapValid(src.euvd.items, (i) => euvdCard(i, kevIds)), cardList),
    section('wid', t.wid, src.wid, mapValid(src.wid.items, widCard), cardList),
    section('buergercert', t.buergercert, src.buergercert, mapValid(src.buergercert.items, buergercertCard), cardList),
    section('bits', t.bits, src.bits, mapValid(src.bits.items, newsItem), newsList),
    section('presse', t.presse, src.presse, mapValid(src.presse.items, newsItem), newsList),
  ];

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
<body>

<header class="site">
  <a class="brand" href="/">cyberuser.de</a>
</header>

<main>
<section class="hero" aria-labelledby="hero-title">
  <h1 id="hero-title">Lagezentrum</h1>
  <p class="lead">Aktuelle Warnungen und aktiv ausgenutzte Schwachstellen, direkt aus offiziellen Quellen: CISA und NIST (USA), ENISA (EU), CERT-Bund und BSI. Die Seite wird alle sechs Stunden automatisch erstellt, ohne KI und ohne eigene Bewertung. Maßgeblich ist immer die verlinkte Originalmeldung.</p>
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
