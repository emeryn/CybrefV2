# 🛡️ Cybref - tooling (`download` branch)

> **Looking for the data? → [`main` branch](https://github.com/emeryn/CybrefV2/tree/main)**
> (datasets, `catalog.json` index and per-dataset README).

This branch (the default one) holds the **code** that builds Cybref, an automated mirror of
cybersecurity reference datasets. The data lives on `main`, which contains nothing else.

```
download  <- this branch (default): engine, catalog, mobile CVE scraper, workflows
main      <- datasets only: single orphan commit replaced at each run, no history, no code
```

[`.github/workflows/refsets.yml`](.github/workflows/refsets.yml) runs on a schedule from this branch,
checks `main` out, fetches the sources and force-pushes the result to `main` as one commit.

## Layout

| Path | Role |
| :--- | :--- |
| [`sources.yaml`](sources.yaml) | **The catalog** - every dataset, its URL, schedule, validation rules and docs. |
| [`src/cybref/`](src/cybref) | Engine: concurrent downloads, validation, atomic publication, state, docs. |
| [`src/cybref/processors/`](src/cybref/processors) | Custom steps for sources that are not a plain download (scrapers, merges, NVD, ...). |
| [`src/mcb/`](src/mcb) | Mobile CVE scraper (Samsung / Pixel / Apple), run as the `mobile_cve` source. |
| [`.github/workflows/refsets.yml`](.github/workflows/refsets.yml) | Scheduled pipeline (daily / weekly + mobile), publishes to `main`. |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | CI for this branch: catalog check, README sync, smoke fetch. |

## How a run works

1. Sources of the selected group (`daily`, `weekly`, then `mobile`) run concurrently (6 at a time, 2 per host).
2. Each download is retried with exponential backoff (honours `Retry-After`), resumes interrupted transfers
   with HTTP Range, and checks `Content-Length`. Unchanged sources answer `304` via ETag / Last-Modified.
3. Every file is **validated before publication**: size limits, JSON/XML/CSV structure, "is this an HTML
   error page?", GitHub's 100 MB cap, and a shrink guard (refuses a file suddenly much smaller than the
   previous one). A source is published all-or-nothing; on failure the previous version is kept.
4. Failed sources get a second, sequential pass after a 60 s cool-down (flaky hosts like IEEE).
5. NVD feeds are only re-downloaded when their `.meta` sha256 changes, and are verified against it. A failing
   year does not block the others (status `partial`).
6. Gzip outputs are deterministic (`mtime=0`): identical content gives identical bytes, so git uploads nothing.
7. `catalog.json` (public index), `README.md` and `.cybref/state.json` (internal state: ETags, hashes) are
   regenerated, files no source produces anymore are pruned, and `main` is replaced by one orphan commit.
8. The job fails (notification) if any source failed - after publishing everything that succeeded.

## Local use

```bash
uv sync
uv run cybref list                                   # catalog
uv run cybref fetch --out data --only cisa_kev,first_epss  # some sources
uv run cybref fetch --out data --group daily         # a group
uv run cybref docs                                   # refresh the catalog section below
uv run cybref prune --out data --dry-run             # files no source produces anymore
uv run mcb --output data/vulnerabilities/mobile --nvd-dir data/vulnerabilities/nvd       # mobile scraper alone
```

Optional environment: `NVD_API_KEY` (faster NVD enrichment for mcb), `ABUSECH_AUTH_KEY` (abuse.ch feeds,
sent only if set). In GitHub: repository secrets with the same names.

## Adding a dataset

Add an entry to [`sources.yaml`](sources.yaml) (the header documents every field), run `uv run cybref docs`,
and test it with `uv run cybref fetch --out /tmp/data --only <id>`. If it needs more than download / unzip /
gunzip / gzip, write a processor in `src/cybref/processors/` and register it in `PROCESSORS`.

## Naming convention

Enforced when the catalog loads (a bad name fails CI):

```
<category>/<provider>_<dataset>[_<variant>].<ext>[.gz]      e.g. threat_intel/abusech_urlhaus_online.csv
```

- **category** = top-level folder: `threat_intel`, `lol`, `vulnerabilities`, `frameworks`, `network`,
  `domains`, `registries`, `detection`;
- **provider first** (`abusech_`, `mitre_`, `ieee_`, `mthcht_`...), then the dataset, then the variant
  (`_ipv4`, `_recent`, `_lite`...); projects that are their own provider keep their name (`lolbas`, `gtfobins`);
- **lowercase snake_case**, and the file stem **is** the source id in `sources.yaml`;
- the **extension is the real format**: `json`, `jsonl` (one JSON object per line), `csv`, `tsv`,
  `txt` (one entry per line, `#` comments), `xml`, `yaml`, `pem`, plus `.gz` when compressed;
- multi-file datasets get a folder and keep upstream names (`vulnerabilities/nvd/nvdcve-2.0-2024.json.gz`).

## Catalog

Files are published at `https://raw.githubusercontent.com/emeryn/CybrefV2/main/<category>/<file>`.

<!-- catalog:start -->
### Threat Intelligence & IOCs - `threat_intel/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`abusech_threatfox_recent.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_threatfox_recent.json) | Daily | **ThreatFox**. IOCs of the last 48h (IP:port, domains, URLs, hashes) tagged by malware family. | [threatfox.abuse.ch](https://threatfox.abuse.ch/) |
| [`abusech_feodotracker_c2_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_feodotracker_c2_ips.json) | Daily | **Feodo Tracker**. Botnet C2 servers (Dridex, Emotet, QakBot, Pikabot...). | [feodotracker.abuse.ch](https://feodotracker.abuse.ch/) |
| [`abusech_urlhaus_online.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_urlhaus_online.csv) | Daily | **URLhaus**. Malware distribution URLs currently online. | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) |
| [`abusech_malwarebazaar_recent.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_malwarebazaar_recent.csv) | Daily | **MalwareBazaar**. Malware samples of the last 48h (hashes, signature, file type, tags). | [bazaar.abuse.ch](https://bazaar.abuse.ch/) |
| [`abusech_sslbl_certificates.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_sslbl_certificates.csv) | Daily | **SSL Blacklist**. SHA1 fingerprints of TLS certificates used by botnet C2 servers. | [sslbl.abuse.ch](https://sslbl.abuse.ch/) |
| [`openphish_urls.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/openphish_urls.txt) | Daily | **OpenPhish**. Community feed of currently active phishing URLs. | [openphish.com](https://openphish.com/) |
| [`malwarefilter_phishing_domains.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/malwarefilter_phishing_domains.txt) | Daily | **Phishing Filter**. Phishing domains aggregated from OpenPhish, PhishTank and others, with false positives (top sites) removed. | [gitlab.com](https://gitlab.com/malware-filter/phishing-filter) |
| [`proofpoint_et_compromised_ips.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/proofpoint_et_compromised_ips.txt) | Daily | **ET Compromised IPs**. Proofpoint Emerging Threats list of known compromised hosts. | [rules.emergingthreats.net](https://rules.emergingthreats.net/) |
| [`spamhaus_drop_ipv4.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_drop_ipv4.jsonl) | Daily | **Spamhaus DROP (IPv4)**. Do Not Route Or Peer - hijacked or criminal netblocks. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`spamhaus_drop_ipv6.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_drop_ipv6.jsonl) | Daily | **Spamhaus DROP (IPv6)**. IPv6 counterpart of the DROP list. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`spamhaus_asndrop.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_asndrop.jsonl) | Daily | **Spamhaus ASN-DROP**. Autonomous systems operated by cybercriminals. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`firehol_level1.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/firehol_level1.txt) | Daily | **FireHOL Level 1**. Aggregated "safe to block" networks (fullbogons, DROP, Feodo, DShield...). | [iplists.firehol.org](https://iplists.firehol.org/) |
| [`stamparm_ipsum.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/stamparm_ipsum.txt) | Daily | **IPsum**. Malicious IPs aggregated from 30+ blocklists, with the number of lists each IP appears on (filter on >= 3 for a reliable set). | [github.com](https://github.com/stamparm/ipsum) |
| [`dshield_block.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/dshield_block.txt) | Daily | **DShield block list**. SANS ISC top 20 attacking /24 subnets of the last 3 days. | [isc.sans.edu](https://isc.sans.edu/block.html) |
| [`cinsscore_badguys.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/cinsscore_badguys.txt) | Daily | **CINS Army**. IPs with poor reputation seen by the Sentinel IPS network. | [cinsscore.com](https://cinsscore.com/) |
| [`blocklistde_all.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/blocklistde_all.txt) | Daily | **blocklist.de**. IPs reported for attacks (SSH, mail, web, FTP brute force) in the last 48h. | [blocklist.de](https://www.blocklist.de/) |
| [`ransomwarelive_groups.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/ransomwarelive_groups.json) | Daily | **Ransomware.live groups**. Ransomware groups with their leak sites, aliases and activity. | [ransomware.live](https://www.ransomware.live/) |
| [`ransomwarelive_victims_recent.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/ransomwarelive_victims_recent.json) | Daily | **Ransomware.live victims**. Latest victims claimed on ransomware leak sites (group, sector, country, dates). | [ransomware.live](https://www.ransomware.live/) |

### Living Off The Land - `lol/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`lolbas.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolbas.json) | Weekly | **LOLBAS**. Windows Living Off The Land binaries, scripts and libraries. | [lolbas-project.github.io](https://lolbas-project.github.io/) |
| [`gtfobins.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/gtfobins.json) | Weekly | **GTFOBins**. Unix binaries usable to bypass local security restrictions. | [gtfobins.github.io](https://gtfobins.github.io/) |
| [`loobins.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/loobins.json) | Weekly | **LOOBins**. macOS Living Off the Orchard binaries. | [loobins.io](https://www.loobins.io/) |
| [`loldrivers.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/loldrivers.json) | Weekly | **LOLDrivers**. Vulnerable and malicious Windows drivers (hashes, metadata). | [loldrivers.io](https://www.loldrivers.io/) |
| [`lolrmm.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolrmm.json) | Weekly | **LOLRMM**. Remote Monitoring & Management tools abused by attackers (artifacts, domains). | [lolrmm.io](https://lolrmm.io/) |
| [`lolesxi.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolesxi.json) | Weekly | **LOLESXi**. VMware ESXi native binaries used by adversaries. | [lolesxi-project.github.io](https://lolesxi-project.github.io/LOLESXi/) |
| [`lofl.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lofl.json) | Weekly | **LOFL**. Living Off the Foreign Land cmdlets and binaries. | [lofl-project.github.io](https://lofl-project.github.io/) |
| [`lolapps.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolapps.json) | Weekly | **LOLApps**. Legitimate applications (Greenshot, Notepad++, Teams...) abusable for persistence or execution. | [lolapps-project.github.io](https://lolapps-project.github.io/) |
| [`lolc2.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolc2.json) | Weekly | **LOLC2**. C2 frameworks hiding in legitimate services. | [lolc2.github.io](https://lolc2.github.io/) |
| [`bootloaders.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/bootloaders.json) | Weekly | **Bootloaders.io**. Known vulnerable or malicious bootloaders. | [bootloaders.io](https://www.bootloaders.io/) |
| [`hijacklibs.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/hijacklibs.json) | Weekly | **HijackLibs**. DLL hijacking candidates (DLL, vulnerable executables, expected paths). | [hijacklibs.net](https://hijacklibs.net/) |
| [`lottunnels_binaries.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lottunnels_binaries.json) | Weekly | **LoTtunnels**. Tunneling binaries usable for proxying or exfiltration. | [lottunnels.github.io](https://lottunnels.github.io/) |
| [`lottunnels_domains.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lottunnels_domains.csv) | Weekly | **LoTtunnels domains**. Domains used by tunneling services. | [lottunnels.github.io](https://lottunnels.github.io/) |
| [`lots.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lots.csv) | Weekly | **LOTS Project**. Legitimate trusted sites abused for C2, phishing or exfiltration. | [lots-project.com](https://lots-project.com/) |
| [`filesec_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/filesec_extensions.csv) | Weekly | **FileSec**. File extensions abused by attackers. | [filesec.io](https://filesec.io/) |
| [`malapi_winapi.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/malapi_winapi.csv) | Weekly | **MalAPI.io**. Windows APIs abused by malware, by technique. | [malapi.io](https://malapi.io/) |
| [`lothardware.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lothardware.json) | Weekly | **LOTHardware**. Hardware implants and malicious devices (USB, network, RF...). | [github.com](https://github.com/enesilhaydin/lothardware) |

### Vulnerabilities & Exploits - `vulnerabilities/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`cisa_kev.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/cisa_kev.json) | Daily | **CISA KEV**. Known Exploited Vulnerabilities catalog (US). | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| [`enisa_euvd_exploited.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/enisa_euvd_exploited.json) | Daily | **EUVD exploited**. European Vulnerability Database entries flagged as exploited (ENISA) - the EU counterpart of KEV. | [euvd.enisa.europa.eu](https://euvd.enisa.europa.eu/) |
| [`first_epss.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/first_epss.csv) | Daily | **EPSS**. Exploit Prediction Scoring System - daily probability of exploitation for every CVE. | [first.org](https://www.first.org/epss/) |
| [`certfr_alertes.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/certfr_alertes.xml) | Daily | **CERT-FR alertes**. ANSSI CERT-FR security alerts (RSS, latest entries). | [cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr/alerte/) |
| [`certfr_avis.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/certfr_avis.xml) | Daily | **CERT-FR avis**. ANSSI CERT-FR security advisories (RSS, latest entries). | [cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr/avis/) |
| [`exploitdb_exploits.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/exploitdb_exploits.csv) | Weekly | **Exploit-DB**. Exploit index with CVE mapping. | [exploit-db.com](https://www.exploit-db.com/) |
| [`metasploit_modules.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/metasploit_modules.json) | Weekly | **Metasploit modules**. Metadata of every Metasploit module (CVE / references, targets, rank) - "is there a weaponized exploit?". | [github.com](https://github.com/rapid7/metasploit-framework) |
| [`nuclei_cve_templates.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/nuclei_cve_templates.jsonl) | Weekly | **Nuclei CVE templates**. CVEs with a Nuclei detection template (severity, CVSS, EPSS, template path). | [github.com](https://github.com/projectdiscovery/nuclei-templates) |
| [`github_advisories.json.gz`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/github_advisories.json.gz) | Weekly | **GitHub Advisories**. All GitHub-reviewed security advisories (OSV format) in one JSON array. | [github.com](https://github.com/advisories) |
| `nvd/nvdcve-2.0-*.json.gz` | Weekly | **NVD CVE**. Full NVD CVE JSON 2.0 feeds per year + recent + modified (original gzip, re-downloaded only when NVD's sha256 changes). | [nvd.nist.gov](https://nvd.nist.gov/vuln/data-feeds) |
| `nvd/cpe/*.json.gz` | Weekly | **NVD CPE dictionary**. CPE 2.0 dictionary split by vendor initial (a.json.gz ... z, 0-9, other) - a single file would exceed GitHub's 100 MB limit. | [nvd.nist.gov](https://nvd.nist.gov/products/cpe) |
| [`mobile/index.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/mobile/index.json)<br>`mobile/cves/*.json` | Weekly | **Mobile CVE**. Samsung / Pixel / iPhone devices with their patch level, and the CVEs of every mobile bulletin (NVD-enriched). Index + per-year CVE details. | [github.com](https://github.com/emeryn/CybrefV2/tree/download/src/mcb) |

### Frameworks & Knowledge Bases - `frameworks/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`mitre_attack_enterprise.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_enterprise.json) | Weekly | **MITRE ATT&CK Enterprise**. ATT&CK Enterprise matrix (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/) |
| [`mitre_attack_mobile.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_mobile.json) | Weekly | **MITRE ATT&CK Mobile**. ATT&CK Mobile matrix (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/matrices/mobile/) |
| [`mitre_attack_ics.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_ics.json) | Weekly | **MITRE ATT&CK ICS**. ATT&CK for Industrial Control Systems (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/matrices/ics/) |
| [`mitre_d3fend.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_d3fend.json) | Weekly | **MITRE D3FEND**. Defensive countermeasures knowledge graph, mapped to ATT&CK (JSON-LD). | [d3fend.mitre.org](https://d3fend.mitre.org/) |
| [`mitre_atlas.yaml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_atlas.yaml) | Weekly | **MITRE ATLAS**. Adversarial Threat Landscape for AI Systems - tactics, techniques and case studies against ML/AI. | [atlas.mitre.org](https://atlas.mitre.org/) |
| [`mitre_cwe.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_cwe.xml) | Weekly | **MITRE CWE**. Common Weakness Enumeration catalog. | [cwe.mitre.org](https://cwe.mitre.org/) |
| [`mitre_capec.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_capec.xml) | Weekly | **MITRE CAPEC**. Common Attack Pattern Enumeration and Classification. | [capec.mitre.org](https://capec.mitre.org/) |
| [`redcanary_atomic_tests.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/redcanary_atomic_tests.csv) | Weekly | **Atomic Red Team**. Index of Atomic Red Team tests (ATT&CK technique, test name, GUID, platform) to validate detections. | [atomicredteam.io](https://atomicredteam.io/) |

### Network: Cloud, ASN, Geo, Anonymizers, Crawlers - `network/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`aws_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/aws_ip_ranges.json) | Weekly | **AWS IP ranges**. Amazon Web Services public IP ranges by service and region. | [docs.aws.amazon.com](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) |
| [`azure_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/azure_ip_ranges.json) | Weekly | **Azure IP ranges**. Microsoft Azure service tags and IP ranges (stable URL mirror). | [github.com](https://github.com/enzo-g/azureIPranges) |
| [`gcp_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/gcp_ip_ranges.json) | Weekly | **Google Cloud IP ranges**. Google Cloud customer IP ranges. | [cloud.google.com](https://cloud.google.com/compute/docs/faq#find_ip_range) |
| [`google_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_ip_ranges.json) | Weekly | **Google IP ranges**. IP ranges of Google services (Gmail, APIs...) outside Google Cloud. | [support.google.com](https://support.google.com/a/answer/10026322) |
| [`oracle_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/oracle_ip_ranges.json) | Weekly | **Oracle Cloud IP ranges**. Oracle Cloud Infrastructure public IP ranges. | [docs.oracle.com](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm) |
| [`digitalocean_ip_ranges.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/digitalocean_ip_ranges.csv) | Weekly | **DigitalOcean IP ranges**. DigitalOcean IP ranges with location (geofeed CSV). | [docs.digitalocean.com](https://docs.digitalocean.com/platform/) |
| [`cloudflare_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/cloudflare_ip_ranges.json) | Weekly | **Cloudflare IP ranges**. Cloudflare edge IPv4/IPv6 ranges. | [cloudflare.com](https://www.cloudflare.com/ips/) |
| [`fastly_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/fastly_ip_ranges.json) | Weekly | **Fastly IP ranges**. Fastly CDN public IP ranges. | [fastly.com](https://www.fastly.com/documentation/reference/api/utils/public-ip-list/) |
| [`github_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/github_ip_ranges.json) | Weekly | **GitHub IP ranges**. GitHub service IP ranges (actions, hooks, git, pages...). | [docs.github.com](https://docs.github.com/en/rest/meta/meta) |
| [`microsoft365_endpoints.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/microsoft365_endpoints.json) | Weekly | **Microsoft 365 endpoints**. URLs and IP ranges used by Microsoft 365 (worldwide instance). | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) |
| [`tor_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_relays.json) | Daily | **Tor relays**. Details of every running Tor relay (Onionoo). | [metrics.torproject.org](https://metrics.torproject.org/onionoo.html) |
| [`tor_exit_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_exit_relays.json) | Daily | **Tor exit relays**. Details of Tor exit relays (Onionoo). | [metrics.torproject.org](https://metrics.torproject.org/onionoo.html) |
| [`tor_exit_ips.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_exit_ips.txt) | Daily | **Tor exit IPs**. Plain list of Tor exit IPs (TorDNSEL), ideal for quick matching. | [check.torproject.org](https://check.torproject.org/) |
| [`apple_private_relay_ranges.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/apple_private_relay_ranges.csv) | Weekly | **iCloud Private Relay**. Egress IP ranges of iCloud Private Relay with their geolocation. | [developer.apple.com](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/) |
| [`mullvad_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/mullvad_relays.json) | Weekly | **Mullvad relays**. Mullvad VPN servers with their IPv4/IPv6 addresses. | [mullvad.net](https://mullvad.net/en/servers) |
| [`x4bnet_vpn_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/x4bnet_vpn_ipv4.txt) | Weekly | **X4BNet VPN ranges**. Commercial VPN provider IPv4 ranges. | [github.com](https://github.com/X4BNet/lists_vpn) |
| [`x4bnet_datacenter_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/x4bnet_datacenter_ipv4.txt) | Weekly | **X4BNet datacenter ranges**. Datacenter and hosting IPv4 ranges. | [github.com](https://github.com/X4BNet/lists_vpn) |
| [`google_googlebot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_googlebot_ips.json) | Weekly | **Googlebot IPs**. IP ranges of Googlebot (verify that a "Googlebot" user agent is genuine). | [developers.google.com](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot) |
| [`google_special_crawlers_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_special_crawlers_ips.json) | Weekly | **Google special crawlers IPs**. IP ranges of Google special-case crawlers (AdsBot...). | [developers.google.com](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot) |
| [`bing_bingbot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/bing_bingbot_ips.json) | Weekly | **Bingbot IPs**. IP ranges of Bingbot. | [bing.com](https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26) |
| [`apple_applebot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/apple_applebot_ips.json) | Weekly | **Applebot IPs**. IP ranges of Applebot. | [support.apple.com](https://support.apple.com/en-us/119829) |
| [`openai_gptbot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/openai_gptbot_ips.json) | Weekly | **OpenAI GPTBot IPs**. IP ranges of OpenAI's training crawler. | [platform.openai.com](https://platform.openai.com/docs/bots) |
| [`openai_chatgpt_user_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/openai_chatgpt_user_ips.json) | Weekly | **OpenAI ChatGPT-User IPs**. IP ranges used when ChatGPT browses on behalf of a user. | [platform.openai.com](https://platform.openai.com/docs/bots) |
| [`iptoasn_ipv4.tsv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/iptoasn_ipv4.tsv) | Weekly | **IPtoASN (IPv4)**. IPv4 range -> ASN, country, AS name. | [iptoasn.com](https://iptoasn.com/) |
| [`iptoasn_ipv6.tsv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/iptoasn_ipv6.tsv) | Weekly | **IPtoASN (IPv6)**. IPv6 range -> ASN, country, AS name. | [iptoasn.com](https://iptoasn.com/) |
| [`dbip_country_lite.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/dbip_country_lite.csv) | Weekly | **DB-IP Country Lite**. IP range -> country (IPv4 + IPv6). CC BY 4.0, attribution to DB-IP.com required. | [db-ip.com](https://db-ip.com/db/download/ip-to-country-lite) |
| [`dbip_asn_lite.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/dbip_asn_lite.csv) | Weekly | **DB-IP ASN Lite**. IP range -> ASN and organisation (IPv4 + IPv6). CC BY 4.0, attribution to DB-IP.com required. | [db-ip.com](https://db-ip.com/db/download/ip-to-asn-lite) |
| [`teamcymru_fullbogons_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/teamcymru_fullbogons_ipv4.txt) | Weekly | **Team Cymru fullbogons (IPv4)**. Unallocated and reserved IPv4 space - traffic from there is spoofed or hijacked. | [team-cymru.com](https://www.team-cymru.com/bogon-networks) |
| [`teamcymru_fullbogons_ipv6.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/teamcymru_fullbogons_ipv6.txt) | Weekly | **Team Cymru fullbogons (IPv6)**. Unallocated and reserved IPv6 space. | [team-cymru.com](https://www.team-cymru.com/bogon-networks) |

### Domains & Email - `domains/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`tranco_top1m.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/tranco_top1m.csv) | Weekly | **Tranco Top 1M**. Research-grade ranking of the top 1M domains (rank,domain). | [tranco-list.eu](https://tranco-list.eu/) |
| [`publicsuffix_list.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/publicsuffix_list.txt) | Weekly | **Public Suffix List**. Effective TLDs, needed to compute registrable domains. | [publicsuffix.org](https://publicsuffix.org/) |
| [`iana_tlds.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/iana_tlds.txt) | Weekly | **IANA TLDs**. Official list of top-level domains in the root zone. | [iana.org](https://www.iana.org/domains/root/db) |
| [`disposable_email_domains.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/disposable_email_domains.txt) | Weekly | **Disposable email domains**. Throw-away email providers. | [github.com](https://github.com/disposable-email-domains/disposable-email-domains) |
| [`free_email_domains.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/free_email_domains.json) | Weekly | **Free email domains**. Free webmail providers (gmail.com, gmx.fr...) - not corporate addresses. | [github.com](https://github.com/Kikobeats/free-email-domains) |
| [`url_shorteners.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/url_shorteners.txt) | Weekly | **URL shorteners**. URL shortener domains (often used to hide phishing or malware links). | [github.com](https://github.com/PeterDaveHello/url-shorteners) |

### Standards & Hardware Registries - `registries/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`ieee_oui.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_oui.csv) | Weekly | **IEEE MA-L (OUI)**. MAC address large-block assignments. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_oui36.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_oui36.csv) | Weekly | **IEEE MA-S (OUI-36)**. MAC address small-block assignments. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_iab.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_iab.csv) | Weekly | **IEEE IAB**. Individual Address Blocks (legacy). | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_cid.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_cid.csv) | Weekly | **IEEE CID**. Company IDs. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_manid.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_manid.csv) | Weekly | **IEEE MANID**. Manufacturer IDs. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`wireshark_manuf.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/wireshark_manuf.txt) | Weekly | **Wireshark manuf**. All IEEE MAC registries merged with short vendor names - the easiest MAC vendor lookup. | [wireshark.org](https://www.wireshark.org/tools/oui-lookup.html) |
| [`usb_ids.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/usb_ids.json) | Weekly | **USB IDs**. USB vendors and products as JSON ({vendor_id - name, products}). | [linux-usb.org](http://www.linux-usb.org/usb-ids.html) |
| [`pci_ids.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/pci_ids.txt) | Weekly | **PCI IDs**. PCI vendors and devices (raw pci.ids format). | [pci-ids.ucw.cz](https://pci-ids.ucw.cz/) |
| [`bluetooth_company_ids.yaml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/bluetooth_company_ids.yaml) | Weekly | **Bluetooth company IDs**. Bluetooth SIG company identifiers (BLE manufacturer data -> vendor). | [bluetooth.com](https://www.bluetooth.com/specifications/assigned-numbers/) |
| [`google_play_devices.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/google_play_devices.csv) | Weekly | **Android devices (Google Play)**. Every Google Play certified Android device - brand, marketing name, device and model codes (re-encoded to UTF-8). | [support.google.com](https://support.google.com/googleplay/answer/1727131) |
| [`iana_service_ports.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/iana_service_ports.csv) | Weekly | **IANA ports**. Service name and transport protocol port number registry. | [iana.org](https://www.iana.org/assignments/service-names-port-numbers/) |
| [`curl_ca_bundle.pem`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/curl_ca_bundle.pem) | Weekly | **CA certificates (Mozilla)**. Root CAs trusted by Mozilla, as a PEM bundle (extracted by curl). | [curl.se](https://curl.se/docs/caextract.html) |

### Detection Lists & Allowlists - `detection/`

| File | Freq | Description | Source |
| :--- | :--- | :--- | :--- |
| [`mthcht_suspicious_user_agents.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_user_agents.csv) | Weekly | **Suspicious User-Agents**. HTTP User-Agents of offensive tools, scanners and malware. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_named_pipes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_named_pipes.csv) | Weekly | **Suspicious named pipes**. Named pipes used by C2 frameworks and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_mutexes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_mutexes.csv) | Weekly | **Suspicious mutexes**. Mutex names created by malware families. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_services.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_services.csv) | Weekly | **Suspicious Windows services**. Windows service names created by malware and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_scheduled_tasks.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_scheduled_tasks.csv) | Weekly | **Suspicious scheduled tasks**. Scheduled task names used by malware for persistence. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_firewall_rules.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_firewall_rules.csv) | Weekly | **Suspicious firewall rules**. Windows firewall rule names added by malware and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_hostnames.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_hostnames.csv) | Weekly | **Suspicious hostnames**. Default hostnames of attacker machines (Kali, VPS images...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_ports.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_ports.csv) | Weekly | **Suspicious ports**. Network ports associated with malware and offensive tooling. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_tlds.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_tlds.csv) | Weekly | **Suspicious TLDs**. Top-level domains over-represented in malicious activity. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_double_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_double_extensions.csv) | Weekly | **Suspicious double extensions**. Deceptive double file extensions (invoice.pdf.exe...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_mac_addresses.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_mac_addresses.csv) | Weekly | **Suspicious MAC addresses**. MAC prefixes of attack hardware, VMs and spoofed devices. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_usb_ids.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_usb_ids.csv) | Weekly | **Suspicious USB IDs**. USB IDs of attack devices (Rubber Ducky, O.MG, Flipper...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_ransomware_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_ransomware_extensions.csv) | Weekly | **Ransomware extensions**. File extensions appended by ransomware families. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_ransomware_notes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_ransomware_notes.csv) | Weekly | **Ransomware notes**. Ransom note file names by ransomware family. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_doh_servers.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_doh_servers.csv) | Weekly | **DNS-over-HTTPS servers**. Public DoH resolvers (DNS bypass and covert channel detection). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_blockchain_rpc.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_blockchain_rpc.csv) | Weekly | **Blockchain RPC endpoints**. Public blockchain RPC endpoints (abused for C2 resolution, e.g. EtherHiding). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_windows_asr_rules.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_windows_asr_rules.csv) | Weekly | **Windows ASR rules**. Microsoft Defender Attack Surface Reduction rule names and GUIDs. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`ihebski_default_credentials.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/ihebski_default_credentials.csv) | Weekly | **Default credentials cheat sheet**. 3,500+ vendor default credentials (product, username, password). | [github.com](https://github.com/ihebski/DefaultCreds-cheat-sheet) |
| [`seclists_default_passwords.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_default_passwords.csv) | Weekly | **SecLists default credentials**. Vendor default usernames and passwords. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`seclists_secret_keywords.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_secret_keywords.txt) | Weekly | **SecLists secret keywords**. Variable names that usually hold secrets. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`seclists_webshells.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_webshells.txt) | Weekly | **SecLists web shells**. Known web shell and backdoor file names. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`badbot_user_agents.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_user_agents.txt) | Weekly | **Bad Bot Blocker - user agents**. Bad bots and scrapers User-Agents. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`badbot_referrers.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_referrers.txt) | Weekly | **Bad Bot Blocker - referrers**. Spam referrer domains. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`badbot_fake_googlebots.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_fake_googlebots.txt) | Weekly | **Bad Bot Blocker - fake Googlebots**. IPs pretending to be Googlebot. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`misp_warninglists.json.gz`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/misp_warninglists.json.gz) | Weekly | **MISP warninglists**. Known-benign indicators (public DNS, CDNs, cloud ranges, known-good Windows hashes...) to cut false positives. One object per list (popularity rankings excluded). | [github.com](https://github.com/MISP/misp-warninglists) |
<!-- catalog:end -->
