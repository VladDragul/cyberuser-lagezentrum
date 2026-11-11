# Test fixtures

Raw responses saved on 2026-11-11 (UTC) with `curl --fail --proto '=https'`.
They are used only by local tests and are never served by the Worker.

| File | Source | Publisher |
|---|---|---|
| nvd-kev.json | https://services.nvd.nist.gov/rest/json/cves/2.0?kevStartDate=2026-11-04T00:00:00.000&kevEndDate=2026-11-11T23:59:59.999 | NIST NVD |
| euvd-exploited.json | https://euvdservices.enisa.europa.eu/api/search?exploited=true&fromUpdatedDate=2026-11-04&toUpdatedDate=2026-11-11&size=100&page=0 | ENISA EUVD |
| wid.xml | https://wid.cert-bund.de/content/public/securityAdvisory/rss | BSI (CERT-Bund WID) |
| buergercert.xml | https://wid.cert-bund.de/content/public/buergercert/rss | BSI (Buerger-CERT) |
| bits.xml | https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_CSW.xml | BSI |
| presse.xml | https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Presse_Veranstaltungen.xml | BSI |

All content remains the property of the respective publishers.
