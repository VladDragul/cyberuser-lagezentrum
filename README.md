# cyberuser-lagezentrum

Cloudflare Worker behind the "Sicherheitslage" cards on the homepage of cyberuser.de: a German-language overview of current vulnerabilities and security advisories from official sources. No cookies, no scripts from third parties, no visitor data stored.

cyberuser.de is a static site served from a home server (lab01) through Cloudflare Tunnel. For the exact homepage `/`, this Worker inserts the cards into the page that nginx on lab01 serves. The former page `/news` redirects to the homepage.

## Sources

| Key | Source | Publisher | Fetch interval |
|---|---|---|---|
| `nvd` | NVD CVE API, Known Exploited Vulnerabilities window | NIST | 2 hours |
| `euvd` | EUVD search API, exploited vulnerabilities | ENISA | 1 hour |
| `wid` | WID security advisories (RSS) | BSI (CERT-Bund) | 1 hour |
| `buergercert` | Buerger-CERT advisories (RSS) | BSI | 1 hour |
| `bits` | BSI news feed (RSS) | BSI | 1 hour |
| `presse` | BSI press and events feed (RSS) | BSI | 1 hour |

Exact URLs and the date the test fixtures were saved: `test/fixtures/SOURCES.md`. All content remains the property of the respective publishers.

NVD asks automated clients to check for updates no more than once every two hours: <https://nvd.nist.gov/developers/api-workflows>

## How it works

- **Schedule.** One Cron Trigger, `17 * * * *` (minute 17 of every hour, UTC). Each run fetches only the sources that are due according to `SOURCE_INTERVAL_MS` in `src/worker.js`, with a 5 minute tolerance for small shifts in run time. Failed attempts count too, so a broken source is not hammered.
- **Requests to sources.** HTTPS only, `cache: 'no-store'`, `redirect: 'manual'`. Every source is isolated: one failure does not stop the others. The look-back window is 7 days.
- **State in Workers KV** (binding `LAGE`):
  - `state` (version 3): `{ v, sources, attempts, seen }`. Sources are stored unmerged; EUVD entries are merged into the NVD KEV list only when the view is built. Older state versions are ignored.
  - `page`: see `KV_PAGE` in `src/worker.js`.
  - `brief`: short HTML fragment for the homepage (newest 6 KEV and 4 CERT-Bund WID entries), written by the same cron run with `generatedAt` metadata. The Worker puts it between `<!-- lage:start -->` and `<!-- lage:end -->` in the static `index.html`, only if it is at most 24 hours old. Otherwise, or on any error, the homepage is served unchanged (fail-open). See `KV_BRIEF`, `BRIEF_MAX_AGE_MS` and `insertBrief` in `src/worker.js`.
- **Stale data.** A failed source shows its last good copy for at most 7 days (`STALE_MAX_MS`), then "KEINE DATEN".
- **NEU mark.** `seen` records, per source, when each item was first seen (max 500 entries per source). Items first seen in the last 24 hours (`NEW_WINDOW_MS`) get a "NEU" mark with a fingerprint. The very first map of a source is a baseline: nothing in it is ever marked NEU, so a fresh deployment does not flag everything.
- **Rendering.** `src/render.js` builds the HTML with a tagged template (`html`) that escapes every value. Links are built only from validated IDs and URLs (`src/sanitize.js`).

## Security

- Response headers (same policy as the static site): CSP `default-src 'none'` with `'self'` only for scripts, styles, images and fonts, no inline styles; COEP, COOP, CORP, Permissions-Policy, `Referrer-Policy: no-referrer`, `nosniff`, `X-Frame-Options: DENY`. HSTS is added by Cloudflare at the edge.
- `Cache-Control: public, max-age=300, no-transform`. `no-transform` also stops Cloudflare from injecting its JavaScript Detections snippet.
- No `*.workers.dev` address and no preview URLs: the Worker is reachable only through the `cyberuser.de/news*` route and the exact homepage route `cyberuser.de/` (no wildcard, so `/index.html` and URLs with a query string go straight to the origin). `/news` and `/news/` answer with a 301 to the homepage; every other path it sees gets a 404.
- Automatic invocation logs are disabled, so no visitor metadata (IP, headers) is stored. Only explicit console logs from the cron run are kept.
- All input from sources is treated as untrusted: text is decoded, trimmed to fixed limits and escaped; IDs and URLs must match strict patterns before they are used.

## Project layout

```
src/index.js        Entry point. Default export only (see below)
src/worker.js       Request handling, cron run, KV state, seen map, headers
src/sources.js      Fetching and parsing of all six sources
src/render.js       HTML page, NEU mark, item keys, homepage brief
src/sanitize.js     Validation and escaping helpers
src/fingerprint.js  Generated data for the fingerprint (do not edit by hand)
test/               node:test suites and fixtures
tools/              fingerprint-gen.py
```

**Rule for `src/index.js`:** workerd treats every named export of the main module as an entrypoint and only accepts functions, classes or handler objects there. `index.js` therefore keeps a default export only; all logic and constants live in `worker.js`, where the tests import them from.

## Requirements

- Node.js 26.13.0 (pinned in `engines`)
- npm 11
- Wrangler 4.160.0 (exact, installed as a dev dependency)

Install scripts are allowed only for `esbuild` and `workerd` (`allowScripts` in `package.json`).

## Local development

```bash
npm ci
npm test                 # node --test test/*.test.js
```

Failing tests are marked with `✖`. Summary of failures only:

```bash
npm test 2>&1 | sed -n '/failing tests:/,$p'
```

Run the Worker locally with scheduled events enabled (session A):

```bash
rm -rf .wrangler/state && npx wrangler dev --test-scheduled
```

From a second session, trigger a cron run and load the page:

```bash
# /__scheduled ignores the time parameter; use this endpoint instead.
# time is the simulated scheduledTime in milliseconds since the epoch.
curl -s "http://localhost:8787/cdn-cgi/local/scheduled?cron=17+*+*+*+*&time=$(date +%s000)"
npx wrangler kv key get brief --binding LAGE --local | head
```

Inspect or change the simulated KV state (local only, never the deployed namespace):

```bash
npx wrangler kv key get state --binding LAGE --local
npx wrangler kv key put state '<json>' --binding LAGE --local
```

## Fingerprint

`src/fingerprint.js` is generated, not drawn by hand and not traced from any real fingerprint or image. The ridges are contour lines of a synthetic whorl-shaped field, cut into segments with random gaps and uneven ink.

```bash
python3 tools/fingerprint-gen.py > src/fingerprint.js
```

Deterministic for a given numpy and matplotlib version (seeds 3 and 11). Last generated with numpy 2.5.3 and matplotlib 3.11.2.

## Cloudflare Free plan limits

Relevant limits this design stays within (check the current values in the official docs):

- Workers: 5 Cron Triggers per account, 10 ms CPU per invocation (cron included), 50 subrequests per invocation, 100,000 requests per day. <https://developers.cloudflare.com/workers/platform/limits/>
- KV: 100,000 reads and 1,000 writes per day. An hourly cron writes 48 times a day (state, brief). Every homepage view costs one Worker request, one KV read and one request to the origin; a redirect from `/news` costs one Worker request and no KV read. <https://developers.cloudflare.com/kv/platform/limits/>

If traffic grows, the next step is the Cache API inside the Worker.

## Deployment

Deployment runs only from GitHub Actions (in progress): Node 26.13.0, `npm ci`, `npm test`, `wrangler deploy`, behind a GitHub Environment with manual approval. The Cloudflare API token is scoped to this Worker and stored as a GitHub secret. Nothing is deployed from a developer machine.

After the first deployment, the first cron run builds the baseline, so no item is marked NEU.

## Commit signing

All commits are signed with SSH keys (ed25519):

| Machine | Key | Fingerprint |
|---|---|---|
| Mac | `~/.ssh/id_ed25519` | `SHA256:Witenk8g/VHG0PRcJfiNJWBGXiNuDbvw1KhBng92A34` |
| lab01 | `~/.ssh/git_signing_lab01` | `SHA256:dySvVOjDQkqetJe0kVYrEHu6ErhsdTxdsammspaAJbA` |

The lab01 key is used for signing only. The Mac key is also registered on GitHub as an authentication key.

Verify locally with an allowed signers file that maps the principal `105380245+VladDragul@users.noreply.github.com` to both keys (`namespaces="git"`):

```bash
git log --format='%h %G? %s'
```

`G` means a good signature from an allowed key.

## License

No license has been chosen for the code yet. Content fetched from the sources remains the property of the respective publishers.
