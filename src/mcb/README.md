# mcb

Scrapes OEM security data and enriches CVEs into static JSON. Runs inside the Cybref pipeline as the
`mobile_cve` source (output: `vulnerabilities/mobile/index.json` + `vulnerabilities/mobile/cves/<year>.json`), or standalone:

```bash
uv run mcb --output data/vulnerabilities/mobile --nvd-dir data/vulnerabilities/nvd   # incremental; --from-scratch to rebuild
```

## Sources

| OEM / module | URL | Kind | Used for |
|---|---|---|---|
| Samsung | `https://security.samsungmobile.com/securityUpdate.smsb` | HTML (`POST` `year=YYYY`) | Monthly SMR bulletins + CVEs |
| Samsung | `https://security.samsungmobile.com/workScope.smsb` | HTML | Patch frequency per model |
| Samsung | `https://www.samsungknox.com/en/api/supported-devices` | JSON API (`limit=5000`) | Device catalog, support dates |
| Samsung | `https://doc.samsungmobile.com/{model}/{csc}/doc.html` | HTML (+ linked doc page) | Per-CSC FOTA / current SPL |
| Google | `https://source.android.com/docs/security/bulletin/pixel` | HTML | Pixel bulletin index + assumed SPL for supported devices |
| Google | `https://source.android.com/docs/security/bulletin/{year}/{slug}` (and legacy `/security/bulletin/...` paths) | HTML | Android + Pixel monthly CVE pages |
| Apple | `https://support.apple.com/en-us/100100` | HTML | Apple security updates index |
| Apple | `https://support.apple.com/...` (archive indexes + HT pages linked from the index) | HTML | Historical / per-release CVE pages |
| Apple | `https://api.appledb.dev/device/main.json.gz` | JSON API | Device catalog |
| Apple | `https://api.appledb.dev/ios/iOS/main.json.gz` | JSON API | iOS version history / support |
| Enrichment | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON API (`cveId=…`, optional `NVD_API_KEY`) | CVE details (CVSS, description) |
| Enrichment | `https://cveawg.mitre.org/api/cve/{id}` | JSON API | Fallback when NVD misses a CVE |
| Enrichment | Local `nvdcve-2.0-{year,recent,modified}.json.gz` in `--nvd-dir` (published by the `nvd_cve` source) | NVD bulk feed files | Prefer local feed before hitting the APIs |

### Bundled local data (not fetched)

| File | Used for |
|---|---|
| `scrapers/pixel_devices.json` | Pixel model catalog (name, codename, launch, support years) |
| `csc/samsung-csc.csv` | CSC → region / carrier labels |

