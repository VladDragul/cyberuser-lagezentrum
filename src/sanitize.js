// Pure helpers for validating and normalizing data from external sources.
// Every value that reaches the rendered page passes through this module.
// No I/O and no shared state: everything here is unit tested with node --test.

export const LIMITS = Object.freeze({ title: 200, description: 400, vulnName: 160 });

/* ---------- Text ---------- */

const XML_NAMED = Object.freeze({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" });
const REPLACEMENT_CHAR = '\uFFFD';

function codePointToString(cp) {
  // NUL, UTF-16 surrogates and values beyond Unicode are never valid XML characters
  if (!Number.isSafeInteger(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
    return REPLACEMENT_CHAR;
  }
  return String.fromCodePoint(cp);
}

// Single pass: "&amp;lt;" becomes "&lt;" and stays literal text (no double decoding).
// Unknown entities such as "&nbsp;" do not match and remain plain text.
export function decodeXmlEntities(input) {
  if (typeof input !== 'string') return '';
  return input.replace(
    /&(?:#x([0-9A-Fa-f]{1,8})|#([0-9]{1,10})|(amp|lt|gt|quot|apos));/g,
    (_, hex, dec, name) => {
      if (name) return XML_NAMED[name];
      return codePointToString(hex !== undefined ? parseInt(hex, 16) : parseInt(dec, 10));
    },
  );
}

// C0/C1 control characters (tab, LF and CR are handled separately), DEL,
// and bidirectional marks/overrides/isolates that can visually reorder text.
const STRIP_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

export function cleanText(input, max) {
  if (typeof input !== 'string') return '';
  const s = input
    .replace(/[\r\n\t]/g, ' ')
    .replace(STRIP_RE, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!Number.isInteger(max) || max < 1) return s;
  // Count code points so a surrogate pair (emoji) is never cut in half
  const chars = Array.from(s);
  if (chars.length <= max) return s;
  return chars.slice(0, max - 1).join('').trimEnd() + '\u2026';
}

const HTML_ESCAPES = Object.freeze({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' });

export function escapeHtml(input) {
  if (typeof input !== 'string' && typeof input !== 'number') return '';
  return String(input).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/* ---------- Identifiers ---------- */

function matchId(re, input) {
  return typeof input === 'string' && input.length <= 64 && re.test(input) ? input : null;
}

export const cveId = (s) => matchId(/^CVE-\d{4}-\d{4,}$/, s);
export const widId = (s) => matchId(/^WID-SEC-\d{4}-\d{4,}$/, s);
export const euvdId = (s) => matchId(/^EUVD-\d{4}-\d{4,}$/, s);
export const uuid = (s) =>
  matchId(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, s);

// EUVD "aliases" is one string with one alias per line (CVE, GHSA, ...)
export function cveIdsFromAliases(aliases) {
  if (typeof aliases !== 'string') return [];
  const found = aliases.split(/\s+/).filter((a) => cveId(a) !== null);
  return [...new Set(found)];
}

/* ---------- Links (built from validated IDs, never taken from feeds) ---------- */

export const nvdUrl = (id) => (cveId(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : null);
export const euvdUrl = (id) => (euvdId(id) ? `https://euvd.enisa.europa.eu/vulnerability/${id}` : null);
export const widUrl = (id) =>
  widId(id) ? `https://wid.cert-bund.de/portal/wid/securityadvisory?name=${id}` : null;
export const buergercertUrl = (u) =>
  uuid(u) ? `https://wid.cert-bund.de/portal/wid/buergercert/details?uuid=${u}` : null;

const BSI_PATH_PREFIXES = Object.freeze(['/SharedDocs/Cybersicherheitswarnungen/', '/DE/Service-Navi/Presse/']);

// The only link taken from a feed, so it gets the strictest check:
// raw pattern, URL parse, and the parsed form must equal the input exactly
// (anything the parser would normalize, such as "..", is rejected).
// Percent-encoding is allowed only for bytes 0x80-0xFF, i.e. UTF-8 sequences
// for non-ASCII characters such as umlauts ("%C3%BC"). Encoded ASCII such as
// "%2e" (dot), "%2F" (slash), "%5C" (backslash) or "%00" never matches.
// The decoded path must be valid UTF-8 and free of control and bidi characters.
const BSI_URL_RE = /^https:\/\/www\.bsi\.bund\.de\/(?:[A-Za-z0-9/_.-]|%[89A-F][0-9A-F])+\.html$/;

export function safeBsiUrl(input) {
  if (typeof input !== 'string' || input.length > 512) return null;
  const raw = input.trim();
  if (!BSI_URL_RE.test(raw)) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (
    url.protocol !== 'https:' ||
    url.hostname !== 'www.bsi.bund.de' ||
    url.port !== '' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.href !== raw
  ) {
    return null;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(url.pathname);
  } catch {
    return null;
  }
  if (decoded.replace(STRIP_RE, '') !== decoded) return null;
  return BSI_PATH_PREFIXES.some((p) => url.pathname.startsWith(p)) ? url.href : null;
}

/* ---------- Numbers ---------- */

export function boundedNumber(value, min, max) {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max ? value : null;
}

/* ---------- Dates (all results are UTC epoch milliseconds or null) ---------- */

const MONTHS = Object.freeze(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']);

function utcMs(y, mo, d, h = 0, mi = 0, s = 0, ms = 0) {
  if (h > 23 || mi > 59 || s > 59) return null;
  const t = Date.UTC(y, mo - 1, d, h, mi, s, ms);
  const dt = new Date(t);
  // Date.UTC silently rolls over (Feb 30 -> Mar 2); reject instead
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== mo - 1 || dt.getUTCDate() !== d) return null;
  return t;
}

// NVD cisaExploitAdd / cisaActionDue: "2026-11-10"
export function parseIsoDay(input) {
  if (typeof input !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(input.trim());
  return m ? utcMs(+m[1], +m[2], +m[3]) : null;
}

// NVD published / lastModified: "2026-11-10T17:15:42.123" (no zone, UTC by NVD convention)
export function parseNvdTimestamp(input) {
  if (typeof input !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/.exec(input.trim());
  if (!m) return null;
  const ms = m[7] ? Number(m[7].padEnd(3, '0')) : 0;
  return utcMs(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], ms);
}

// EUVD: "Nov 10, 2026, 12:00:00 AM" (en-US, no zone). Only the calendar day is kept.
// Newer Java versions put U+202F (narrow no-break space) before AM/PM.
export function parseEuvdDate(input) {
  if (typeof input !== 'string') return null;
  const m = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{1,2}), (\d{4}), (\d{1,2}):(\d{2}):(\d{2})[ \u00A0\u202F](AM|PM)$/.exec(
    input.trim(),
  );
  if (!m || +m[4] < 1 || +m[4] > 12 || +m[5] > 59 || +m[6] > 59) return null;
  return utcMs(+m[3], MONTHS.indexOf(m[1]) + 1, +m[2]);
}

// RSS pubDate (RFC 822/1123): "Tue, 11 Nov 2026 10:34:00 GMT" or "... +0100"
export function parseRfc822(input) {
  if (typeof input !== 'string') return null;
  const m = /^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), )?(\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) (\d{2}):(\d{2})(?::(\d{2}))? (GMT|UT|Z|[+-]\d{4})$/.exec(
    input.trim(),
  );
  if (!m) return null;
  const t = utcMs(+m[3], MONTHS.indexOf(m[2]) + 1, +m[1], +m[4], +m[5], m[6] ? +m[6] : 0);
  if (t === null) return null;
  const zone = m[7];
  if (zone === 'GMT' || zone === 'UT' || zone === 'Z') return t;
  const sign = zone[0] === '+' ? 1 : -1;
  const hh = Number(zone.slice(1, 3));
  const mm = Number(zone.slice(3, 5));
  if (hh > 14 || mm > 59) return null;
  // Local time minus a positive offset gives UTC
  return t - sign * (hh * 60 + mm) * 60000;
}
