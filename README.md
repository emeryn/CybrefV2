# 🛡️ Cybref - Cybersecurity Reference Sets

Automated mirror of cybersecurity reference datasets: threat-intel feeds, Living Off The Land
projects, vulnerability databases, network ranges and hardware registries - downloaded,
validated and normalized on a schedule.

## Usage

Single file: `https://raw.githubusercontent.com/emeryn/CybrefV2/main/<file>`

Everything:

```bash
git clone --depth 1 https://github.com/emeryn/CybrefV2.git cybref
# update later (history is not kept: the branch is a single commit replaced at each update)
git -C cybref fetch --depth 1 origin main && git -C cybref reset --hard origin/main
```

[`catalog.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/catalog.json) is the machine-readable index of
everything here: per dataset its description, source, frequency, health and last run, and per
file its URL, size, record count, sha256 and last update.

Last generated 2026-10-10 07:04 UTC.
⚠️ = last update failed or is overdue - the previous version of the file is kept.

The tooling lives on the [`download`](https://github.com/emeryn/CybrefV2/tree/download) branch.

## Catalog

### Threat Intelligence & IOCs - `threat_intel/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`abusech_threatfox_recent.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_threatfox_recent.json) | Daily | 4.3 MB | 2026-10-10 | **ThreatFox**. IOCs of the last 48h (IP:port, domains, URLs, hashes) tagged by malware family. | [threatfox.abuse.ch](https://threatfox.abuse.ch/) |
| [`abusech_feodotracker_c2_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_feodotracker_c2_ips.json) | Daily | 1.7 KB | 2026-10-04 | **Feodo Tracker**. Botnet C2 servers (Dridex, Emotet, QakBot, Pikabot...). | [feodotracker.abuse.ch](https://feodotracker.abuse.ch/) |
| [`abusech_urlhaus_online.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_urlhaus_online.csv) | Daily | 7.2 MB | 2026-10-10 | **URLhaus**. Malware distribution URLs currently online. | [urlhaus.abuse.ch](https://urlhaus.abuse.ch/) |
| [`abusech_malwarebazaar_recent.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_malwarebazaar_recent.csv) | Daily | 431.8 KB | 2026-10-10 | **MalwareBazaar**. Malware samples of the last 48h (hashes, signature, file type, tags). | [bazaar.abuse.ch](https://bazaar.abuse.ch/) |
| [`abusech_sslbl_certificates.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/abusech_sslbl_certificates.csv) | Daily | 804.8 KB | 2026-10-10 | **SSL Blacklist**. SHA1 fingerprints of TLS certificates used by botnet C2 servers. | [sslbl.abuse.ch](https://sslbl.abuse.ch/) |
| [`openphish_urls.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/openphish_urls.txt) | Daily | 14.5 KB | 2026-10-10 | **OpenPhish**. Community feed of currently active phishing URLs. | [openphish.com](https://openphish.com/) |
| [`malwarefilter_phishing_domains.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/malwarefilter_phishing_domains.txt) | Daily | 972.8 KB | 2026-10-10 | **Phishing Filter**. Phishing domains aggregated from OpenPhish, PhishTank and others, with false positives (top sites) removed. | [gitlab.com](https://gitlab.com/malware-filter/phishing-filter) |
| [`proofpoint_et_compromised_ips.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/proofpoint_et_compromised_ips.txt) | Daily | 8.3 KB | 2026-10-10 | **ET Compromised IPs**. Proofpoint Emerging Threats list of known compromised hosts. | [rules.emergingthreats.net](https://rules.emergingthreats.net/) |
| [`spamhaus_drop_ipv4.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_drop_ipv4.jsonl) | Daily | 100.5 KB | 2026-10-10 | **Spamhaus DROP (IPv4)**. Do Not Route Or Peer - hijacked or criminal netblocks. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`spamhaus_drop_ipv6.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_drop_ipv6.jsonl) | Daily | 5.8 KB | 2026-10-04 | **Spamhaus DROP (IPv6)**. IPv6 counterpart of the DROP list. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`spamhaus_asndrop.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/spamhaus_asndrop.jsonl) | Daily | 37.6 KB | 2026-10-10 | **Spamhaus ASN-DROP**. Autonomous systems operated by cybercriminals. | [spamhaus.org](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) |
| [`firehol_level1.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/firehol_level1.txt) | Daily | 72.1 KB | 2026-10-10 | **FireHOL Level 1**. Aggregated "safe to block" networks (fullbogons, DROP, Feodo, DShield...). | [iplists.firehol.org](https://iplists.firehol.org/) |
| [`stamparm_ipsum.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/stamparm_ipsum.txt) | Daily | 1.8 MB | 2026-10-10 | **IPsum**. Malicious IPs aggregated from 30+ blocklists, with the number of lists each IP appears on (filter on >= 3 for a reliable set). | [github.com](https://github.com/stamparm/ipsum) |
| [`dshield_block.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/dshield_block.txt) | Daily | 2.0 KB | 2026-10-10 | **DShield block list**. SANS ISC top 20 attacking /24 subnets of the last 3 days. | [isc.sans.edu](https://isc.sans.edu/block.html) |
| [`cinsscore_badguys.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/cinsscore_badguys.txt) | Daily | 206.5 KB | 2026-10-10 | **CINS Army**. IPs with poor reputation seen by the Sentinel IPS network. | [cinsscore.com](https://cinsscore.com/) |
| [`blocklistde_all.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/blocklistde_all.txt) | Daily | 337.4 KB | 2026-10-10 | **blocklist.de**. IPs reported for attacks (SSH, mail, web, FTP brute force) in the last 48h. | [blocklist.de](https://www.blocklist.de/) |
| [`ransomwarelive_groups.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/ransomwarelive_groups.json) | Daily | 766.8 KB | 2026-10-10 | **Ransomware.live groups**. Ransomware groups with their leak sites, aliases and activity. | [ransomware.live](https://www.ransomware.live/) |
| [`ransomwarelive_victims_recent.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/threat_intel/ransomwarelive_victims_recent.json) | Daily | 90.9 KB | 2026-10-10 | **Ransomware.live victims**. Latest victims claimed on ransomware leak sites (group, sector, country, dates). | [ransomware.live](https://www.ransomware.live/) |

### Living Off The Land - `lol/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`lolbas.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolbas.json) | Weekly | 430.8 KB | 2026-10-04 | **LOLBAS**. Windows Living Off The Land binaries, scripts and libraries. | [lolbas-project.github.io](https://lolbas-project.github.io/) |
| [`gtfobins.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/gtfobins.json) | Weekly | 188.1 KB | 2026-10-04 | **GTFOBins**. Unix binaries usable to bypass local security restrictions. | [gtfobins.github.io](https://gtfobins.github.io/) |
| [`loobins.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/loobins.json) | Weekly | 153.6 KB | 2026-10-04 | **LOOBins**. macOS Living Off the Orchard binaries. | [loobins.io](https://www.loobins.io/) |
| [`loldrivers.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/loldrivers.json) | Weekly | 31.7 MB | 2026-10-04 | **LOLDrivers**. Vulnerable and malicious Windows drivers (hashes, metadata). | [loldrivers.io](https://www.loldrivers.io/) |
| [`lolrmm.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolrmm.json) | Weekly | 2.1 MB | 2026-10-04 | **LOLRMM**. Remote Monitoring & Management tools abused by attackers (artifacts, domains). | [lolrmm.io](https://lolrmm.io/) |
| [`lolesxi.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolesxi.json) | Weekly | 42.2 KB | 2026-10-04 | **LOLESXi**. VMware ESXi native binaries used by adversaries. | [lolesxi-project.github.io](https://lolesxi-project.github.io/LOLESXi/) |
| [`lofl.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lofl.json) | Weekly | 273.7 KB | 2026-10-04 | **LOFL**. Living Off the Foreign Land cmdlets and binaries. | [lofl-project.github.io](https://lofl-project.github.io/) |
| [`lolapps.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolapps.json) | Weekly | 7.3 KB | 2026-10-04 | **LOLApps**. Legitimate applications (Greenshot, Notepad++, Teams...) abusable for persistence or execution. | [lolapps-project.github.io](https://lolapps-project.github.io/) |
| [`lolc2.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lolc2.json) | Weekly | 87.4 KB | 2026-10-04 | **LOLC2**. C2 frameworks hiding in legitimate services. | [lolc2.github.io](https://lolc2.github.io/) |
| [`bootloaders.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/bootloaders.json) | Weekly | 2.0 MB | 2026-10-04 | **Bootloaders.io**. Known vulnerable or malicious bootloaders. | [bootloaders.io](https://www.bootloaders.io/) |
| [`hijacklibs.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/hijacklibs.json) | Weekly | 946.2 KB | 2026-10-04 | **HijackLibs**. DLL hijacking candidates (DLL, vulnerable executables, expected paths). | [hijacklibs.net](https://hijacklibs.net/) |
| [`lottunnels_binaries.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lottunnels_binaries.json) | Weekly | 133.4 KB | 2026-10-04 | **LoTtunnels**. Tunneling binaries usable for proxying or exfiltration. | [lottunnels.github.io](https://lottunnels.github.io/) |
| [`lottunnels_domains.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lottunnels_domains.csv) | Weekly | 2.5 KB | 2026-10-04 | **LoTtunnels domains**. Domains used by tunneling services. | [lottunnels.github.io](https://lottunnels.github.io/) |
| [`lots.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lots.csv) | Weekly | 7.3 KB | 2026-10-04 | **LOTS Project**. Legitimate trusted sites abused for C2, phishing or exfiltration. | [lots-project.com](https://lots-project.com/) |
| [`filesec_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/filesec_extensions.csv) | Weekly | 4.8 KB | 2026-10-04 | **FileSec**. File extensions abused by attackers. | [filesec.io](https://filesec.io/) |
| [`malapi_winapi.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/malapi_winapi.csv) | Weekly | 28.5 KB | 2026-10-04 | **MalAPI.io**. Windows APIs abused by malware, by technique. | [malapi.io](https://malapi.io/) |
| [`lothardware.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/lol/lothardware.json) | Weekly | 4.4 KB | 2026-10-04 | **LOTHardware**. Hardware implants and malicious devices (USB, network, RF...). | [github.com](https://github.com/enesilhaydin/lothardware) |

### Vulnerabilities & Exploits - `vulnerabilities/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`cisa_kev.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/cisa_kev.json) | Daily | 1.7 MB | 2026-10-09 | **CISA KEV**. Known Exploited Vulnerabilities catalog (US). | [cisa.gov](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| [`enisa_euvd_exploited.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/enisa_euvd_exploited.json) | Daily | 6.7 MB | 2026-10-10 | **EUVD exploited**. European Vulnerability Database entries flagged as exploited (ENISA) - the EU counterpart of KEV. | [euvd.enisa.europa.eu](https://euvd.enisa.europa.eu/) |
| [`first_epss.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/first_epss.csv) | Daily | 11.2 MB | 2026-10-10 | **EPSS**. Exploit Prediction Scoring System - daily probability of exploitation for every CVE. | [first.org](https://www.first.org/epss/) |
| [`certfr_alertes.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/certfr_alertes.xml) | Daily | 25.3 KB | 2026-10-10 | **CERT-FR alertes**. ANSSI CERT-FR security alerts (RSS, latest entries). | [cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr/alerte/) |
| [`certfr_avis.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/certfr_avis.xml) | Daily | 22.5 KB | 2026-10-10 | **CERT-FR avis**. ANSSI CERT-FR security advisories (RSS, latest entries). | [cert.ssi.gouv.fr](https://www.cert.ssi.gouv.fr/avis/) |
| [`exploitdb_exploits.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/exploitdb_exploits.csv) | Weekly | 9.7 MB | 2026-10-04 | **Exploit-DB**. Exploit index with CVE mapping. | [exploit-db.com](https://www.exploit-db.com/) |
| [`metasploit_modules.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/metasploit_modules.json) | Weekly | 10.8 MB | 2026-10-04 | **Metasploit modules**. Metadata of every Metasploit module (CVE / references, targets, rank) - "is there a weaponized exploit?". | [github.com](https://github.com/rapid7/metasploit-framework) |
| [`nuclei_cve_templates.jsonl`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/nuclei_cve_templates.jsonl) | Weekly | 2.1 MB | 2026-10-04 | **Nuclei CVE templates**. CVEs with a Nuclei detection template (severity, CVSS, EPSS, template path). | [github.com](https://github.com/projectdiscovery/nuclei-templates) |
| [`github_advisories.json.gz`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/github_advisories.json.gz) | Weekly | 24.5 MB | 2026-10-04 | **GitHub Advisories**. All GitHub-reviewed security advisories (OSV format) in one JSON array. | [github.com](https://github.com/advisories) |
| `nvd/nvdcve-2.0-*.json.gz` | Weekly | 228.4 MB | 2026-10-04 | **NVD CVE**. Full NVD CVE JSON 2.0 feeds per year + recent + modified (original gzip, re-downloaded only when NVD's sha256 changes). | [nvd.nist.gov](https://nvd.nist.gov/vuln/data-feeds) |
| `nvd/cpe/*.json.gz` | Weekly | 79.8 MB | 2026-10-04 | **NVD CPE dictionary**. CPE 2.0 dictionary split by vendor initial (a.json.gz ... z, 0-9, other) - a single file would exceed GitHub's 100 MB limit. | [nvd.nist.gov](https://nvd.nist.gov/products/cpe) |
| [`mobile/index.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/vulnerabilities/mobile/index.json)<br>`mobile/cves/*.json` | Weekly | 18.1 MB | 2026-10-04 | **Mobile CVE**. Samsung / Pixel / iPhone devices with their patch level, and the CVEs of every mobile bulletin (NVD-enriched). Index + per-year CVE details. | [github.com](https://github.com/emeryn/CybrefV2/tree/download/src/mcb) |

### Frameworks & Knowledge Bases - `frameworks/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`mitre_attack_enterprise.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_enterprise.json) | Weekly | 45.7 MB | 2026-10-04 | **MITRE ATT&CK Enterprise**. ATT&CK Enterprise matrix (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/) |
| [`mitre_attack_mobile.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_mobile.json) | Weekly | 4.9 MB | 2026-10-04 | **MITRE ATT&CK Mobile**. ATT&CK Mobile matrix (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/matrices/mobile/) |
| [`mitre_attack_ics.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_attack_ics.json) | Weekly | 3.4 MB | 2026-10-04 | **MITRE ATT&CK ICS**. ATT&CK for Industrial Control Systems (STIX 2.1). | [attack.mitre.org](https://attack.mitre.org/matrices/ics/) |
| [`mitre_d3fend.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_d3fend.json) | Weekly | 4.6 MB | 2026-10-04 | **MITRE D3FEND**. Defensive countermeasures knowledge graph, mapped to ATT&CK (JSON-LD). | [d3fend.mitre.org](https://d3fend.mitre.org/) |
| [`mitre_atlas.yaml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_atlas.yaml) | Weekly | 821.8 KB | 2026-10-04 | **MITRE ATLAS**. Adversarial Threat Landscape for AI Systems - tactics, techniques and case studies against ML/AI. | [atlas.mitre.org](https://atlas.mitre.org/) |
| [`mitre_cwe.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_cwe.xml) | Weekly | 17.3 MB | 2026-10-04 | **MITRE CWE**. Common Weakness Enumeration catalog. | [cwe.mitre.org](https://cwe.mitre.org/) |
| [`mitre_capec.xml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/mitre_capec.xml) | Weekly | 3.7 MB | 2026-10-04 | **MITRE CAPEC**. Common Attack Pattern Enumeration and Classification. | [capec.mitre.org](https://capec.mitre.org/) |
| [`redcanary_atomic_tests.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/frameworks/redcanary_atomic_tests.csv) | Weekly | 345.7 KB | 2026-10-04 | **Atomic Red Team**. Index of Atomic Red Team tests (ATT&CK technique, test name, GUID, platform) to validate detections. | [atomicredteam.io](https://atomicredteam.io/) |

### Network: Cloud, ASN, Geo, Anonymizers, Crawlers - `network/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`aws_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/aws_ip_ranges.json) | Weekly | 2.6 MB | 2026-10-04 | **AWS IP ranges**. Amazon Web Services public IP ranges by service and region. | [docs.aws.amazon.com](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) |
| [`azure_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/azure_ip_ranges.json) | Weekly | 4.1 MB | 2026-10-04 | **Azure IP ranges**. Microsoft Azure service tags and IP ranges (stable URL mirror). | [github.com](https://github.com/enzo-g/azureIPranges) |
| [`gcp_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/gcp_ip_ranges.json) | Weekly | 110.5 KB | 2026-10-04 | **Google Cloud IP ranges**. Google Cloud customer IP ranges. | [cloud.google.com](https://cloud.google.com/compute/docs/faq#find_ip_range) |
| [`google_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_ip_ranges.json) | Weekly | 6.0 KB | 2026-10-04 | **Google IP ranges**. IP ranges of Google services (Gmail, APIs...) outside Google Cloud. | [support.google.com](https://support.google.com/a/answer/10026322) |
| [`oracle_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/oracle_ip_ranges.json) | Weekly | 228.6 KB | 2026-10-04 | **Oracle Cloud IP ranges**. Oracle Cloud Infrastructure public IP ranges. | [docs.oracle.com](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm) |
| [`digitalocean_ip_ranges.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/digitalocean_ip_ranges.csv) | Weekly | 51.7 KB | 2026-10-04 | **DigitalOcean IP ranges**. DigitalOcean IP ranges with location (geofeed CSV). | [docs.digitalocean.com](https://docs.digitalocean.com/platform/) |
| [`cloudflare_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/cloudflare_ip_ranges.json) | Weekly | 505 B | 2026-10-04 | **Cloudflare IP ranges**. Cloudflare edge IPv4/IPv6 ranges. | [cloudflare.com](https://www.cloudflare.com/ips/) |
| [`fastly_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/fastly_ip_ranges.json) | Weekly | 402 B | 2026-10-04 | **Fastly IP ranges**. Fastly CDN public IP ranges. | [fastly.com](https://www.fastly.com/documentation/reference/api/utils/public-ip-list/) |
| [`github_ip_ranges.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/github_ip_ranges.json) | Weekly | 151.0 KB | 2026-10-04 | **GitHub IP ranges**. GitHub service IP ranges (actions, hooks, git, pages...). | [docs.github.com](https://docs.github.com/en/rest/meta/meta) |
| [`microsoft365_endpoints.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/microsoft365_endpoints.json) | Weekly | 27.2 KB | 2026-10-04 | **Microsoft 365 endpoints**. URLs and IP ranges used by Microsoft 365 (worldwide instance). | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service) |
| [`tor_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_relays.json) | Daily | 71.3 MB | 2026-10-10 | **Tor relays**. Details of every running Tor relay (Onionoo). | [metrics.torproject.org](https://metrics.torproject.org/onionoo.html) |
| [`tor_exit_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_exit_relays.json) | Daily | 16.8 MB | 2026-10-10 | **Tor exit relays**. Details of Tor exit relays (Onionoo). | [metrics.torproject.org](https://metrics.torproject.org/onionoo.html) |
| [`tor_exit_ips.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/tor_exit_ips.txt) | Daily | 16.7 KB | 2026-10-10 | **Tor exit IPs**. Plain list of Tor exit IPs (TorDNSEL), ideal for quick matching. | [check.torproject.org](https://check.torproject.org/) |
| [`apple_private_relay_ranges.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/apple_private_relay_ranges.csv) | Weekly | 11.5 MB | 2026-10-04 | **iCloud Private Relay**. Egress IP ranges of iCloud Private Relay with their geolocation. | [developer.apple.com](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/) |
| [`mullvad_relays.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/mullvad_relays.json) | Weekly | 287.1 KB | 2026-10-04 | **Mullvad relays**. Mullvad VPN servers with their IPv4/IPv6 addresses. | [mullvad.net](https://mullvad.net/en/servers) |
| [`x4bnet_vpn_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/x4bnet_vpn_ipv4.txt) | Weekly | 176.1 KB | 2026-10-04 | **X4BNet VPN ranges**. Commercial VPN provider IPv4 ranges. | [github.com](https://github.com/X4BNet/lists_vpn) |
| [`x4bnet_datacenter_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/x4bnet_datacenter_ipv4.txt) | Weekly | 676.9 KB | 2026-10-04 | **X4BNet datacenter ranges**. Datacenter and hosting IPv4 ranges. | [github.com](https://github.com/X4BNet/lists_vpn) |
| [`google_googlebot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_googlebot_ips.json) | Weekly | 21.3 KB | 2026-10-04 | **Googlebot IPs**. IP ranges of Googlebot (verify that a "Googlebot" user agent is genuine). | [developers.google.com](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot) |
| [`google_special_crawlers_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/google_special_crawlers_ips.json) | Weekly | 18.7 KB | 2026-10-04 | **Google special crawlers IPs**. IP ranges of Google special-case crawlers (AdsBot...). | [developers.google.com](https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot) |
| [`bing_bingbot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/bing_bingbot_ips.json) | Weekly | 1.5 KB | 2026-10-04 | **Bingbot IPs**. IP ranges of Bingbot. | [bing.com](https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26) |
| [`apple_applebot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/apple_applebot_ips.json) | Weekly | 1.6 KB | 2026-10-04 | **Applebot IPs**. IP ranges of Applebot. | [support.apple.com](https://support.apple.com/en-us/119829) |
| [`openai_gptbot_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/openai_gptbot_ips.json) | Weekly | 977 B | 2026-10-04 | **OpenAI GPTBot IPs**. IP ranges of OpenAI's training crawler. | [platform.openai.com](https://platform.openai.com/docs/bots) |
| [`openai_chatgpt_user_ips.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/openai_chatgpt_user_ips.json) | Weekly | 8.1 KB | 2026-10-04 | **OpenAI ChatGPT-User IPs**. IP ranges used when ChatGPT browses on behalf of a user. | [platform.openai.com](https://platform.openai.com/docs/bots) |
| [`iptoasn_ipv4.tsv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/iptoasn_ipv4.tsv) | Weekly | 29.1 MB | 2026-10-04 | **IPtoASN (IPv4)**. IPv4 range -> ASN, country, AS name. | [iptoasn.com](https://iptoasn.com/) |
| [`iptoasn_ipv6.tsv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/iptoasn_ipv6.tsv) | Weekly | 14.5 MB | 2026-10-04 | **IPtoASN (IPv6)**. IPv6 range -> ASN, country, AS name. | [iptoasn.com](https://iptoasn.com/) |
| [`dbip_country_lite.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/dbip_country_lite.csv) | Weekly | 29.8 MB | 2026-10-04 | **DB-IP Country Lite**. IP range -> country (IPv4 + IPv6). CC BY 4.0, attribution to DB-IP.com required. | [db-ip.com](https://db-ip.com/db/download/ip-to-country-lite) |
| [`dbip_asn_lite.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/dbip_asn_lite.csv) | Weekly | 29.0 MB | 2026-10-04 | **DB-IP ASN Lite**. IP range -> ASN and organisation (IPv4 + IPv6). CC BY 4.0, attribution to DB-IP.com required. | [db-ip.com](https://db-ip.com/db/download/ip-to-asn-lite) |
| [`teamcymru_fullbogons_ipv4.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/teamcymru_fullbogons_ipv4.txt) | Weekly | 46.8 KB | 2026-10-04 | **Team Cymru fullbogons (IPv4)**. Unallocated and reserved IPv4 space - traffic from there is spoofed or hijacked. | [team-cymru.com](https://www.team-cymru.com/bogon-networks) |
| [`teamcymru_fullbogons_ipv6.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/network/teamcymru_fullbogons_ipv6.txt) | Weekly | 2.5 MB | 2026-10-04 | **Team Cymru fullbogons (IPv6)**. Unallocated and reserved IPv6 space. | [team-cymru.com](https://www.team-cymru.com/bogon-networks) |

### Domains & Email - `domains/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`tranco_top1m.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/tranco_top1m.csv) | Weekly | 21.6 MB | 2026-10-04 | **Tranco Top 1M**. Research-grade ranking of the top 1M domains (rank,domain). | [tranco-list.eu](https://tranco-list.eu/) |
| [`publicsuffix_list.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/publicsuffix_list.txt) | Weekly | 326.9 KB | 2026-10-04 | **Public Suffix List**. Effective TLDs, needed to compute registrable domains. | [publicsuffix.org](https://publicsuffix.org/) |
| [`iana_tlds.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/iana_tlds.txt) | Weekly | 9.3 KB | 2026-10-04 | **IANA TLDs**. Official list of top-level domains in the root zone. | [iana.org](https://www.iana.org/domains/root/db) |
| [`disposable_email_domains.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/disposable_email_domains.txt) | Weekly | 127.3 KB | 2026-10-04 | **Disposable email domains**. Throw-away email providers. | [github.com](https://github.com/disposable-email-domains/disposable-email-domains) |
| [`free_email_domains.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/free_email_domains.json) | Weekly | 268.2 KB | 2026-10-04 | **Free email domains**. Free webmail providers (gmail.com, gmx.fr...) - not corporate addresses. | [github.com](https://github.com/Kikobeats/free-email-domains) |
| [`url_shorteners.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/domains/url_shorteners.txt) | Weekly | 12.8 KB | 2026-10-04 | **URL shorteners**. URL shortener domains (often used to hide phishing or malware links). | [github.com](https://github.com/PeterDaveHello/url-shorteners) |

### Standards & Hardware Registries - `registries/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`ieee_oui.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_oui.csv) | Weekly | 3.7 MB | 2026-10-04 | **IEEE MA-L (OUI)**. MAC address large-block assignments. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_oui36.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_oui36.csv) | Weekly | 654.2 KB | 2026-10-04 | **IEEE MA-S (OUI-36)**. MAC address small-block assignments. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_iab.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_iab.csv) | Weekly | 372.2 KB | 2026-10-04 | **IEEE IAB**. Individual Address Blocks (legacy). | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_cid.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_cid.csv) | Weekly | 19.8 KB | 2026-10-04 | **IEEE CID**. Company IDs. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`ieee_manid.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/ieee_manid.csv) | Weekly | 12.7 KB | 2026-10-04 | **IEEE MANID**. Manufacturer IDs. | [standards.ieee.org](https://standards.ieee.org/products-programs/regauth/) |
| [`wireshark_manuf.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/wireshark_manuf.txt) | Weekly | 3.0 MB | 2026-10-04 | **Wireshark manuf**. All IEEE MAC registries merged with short vendor names - the easiest MAC vendor lookup. | [wireshark.org](https://www.wireshark.org/tools/oui-lookup.html) |
| [`usb_ids.json`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/usb_ids.json) | Weekly | 1.0 MB | 2026-10-04 | **USB IDs**. USB vendors and products as JSON ({vendor_id - name, products}). | [linux-usb.org](http://www.linux-usb.org/usb-ids.html) |
| [`pci_ids.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/pci_ids.txt) | Weekly | 1.6 MB | 2026-10-04 | **PCI IDs**. PCI vendors and devices (raw pci.ids format). | [pci-ids.ucw.cz](https://pci-ids.ucw.cz/) |
| [`bluetooth_company_ids.yaml`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/bluetooth_company_ids.yaml) | Weekly | 205.3 KB | 2026-10-04 | **Bluetooth company IDs**. Bluetooth SIG company identifiers (BLE manufacturer data -> vendor). | [bluetooth.com](https://www.bluetooth.com/specifications/assigned-numbers/) |
| [`google_play_devices.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/google_play_devices.csv) | Weekly | 2.3 MB | 2026-10-04 | **Android devices (Google Play)**. Every Google Play certified Android device - brand, marketing name, device and model codes (re-encoded to UTF-8). | [support.google.com](https://support.google.com/googleplay/answer/1727131) |
| [`iana_service_ports.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/iana_service_ports.csv) | Weekly | 1.1 MB | 2026-10-04 | **IANA ports**. Service name and transport protocol port number registry. | [iana.org](https://www.iana.org/assignments/service-names-port-numbers/) |
| [`curl_ca_bundle.pem`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/registries/curl_ca_bundle.pem) | Weekly | 184.5 KB | 2026-10-04 | **CA certificates (Mozilla)**. Root CAs trusted by Mozilla, as a PEM bundle (extracted by curl). | [curl.se](https://curl.se/docs/caextract.html) |

### Detection Lists & Allowlists - `detection/`

| File | Freq | Size | Updated | Description | Source |
| :--- | :--- | ---: | :--- | :--- | :--- |
| [`mthcht_suspicious_user_agents.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_user_agents.csv) | Weekly | 421.4 KB | 2026-10-04 | **Suspicious User-Agents**. HTTP User-Agents of offensive tools, scanners and malware. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_named_pipes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_named_pipes.csv) | Weekly | 104.9 KB | 2026-10-04 | **Suspicious named pipes**. Named pipes used by C2 frameworks and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_mutexes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_mutexes.csv) | Weekly | 60.2 KB | 2026-10-04 | **Suspicious mutexes**. Mutex names created by malware families. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_services.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_services.csv) | Weekly | 40.5 KB | 2026-10-04 | **Suspicious Windows services**. Windows service names created by malware and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_scheduled_tasks.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_scheduled_tasks.csv) | Weekly | 26.5 KB | 2026-10-04 | **Suspicious scheduled tasks**. Scheduled task names used by malware for persistence. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_firewall_rules.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_firewall_rules.csv) | Weekly | 9.0 KB | 2026-10-04 | **Suspicious firewall rules**. Windows firewall rule names added by malware and offensive tools. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_hostnames.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_hostnames.csv) | Weekly | 4.4 KB | 2026-10-04 | **Suspicious hostnames**. Default hostnames of attacker machines (Kali, VPS images...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_ports.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_ports.csv) | Weekly | 29.8 KB | 2026-10-04 | **Suspicious ports**. Network ports associated with malware and offensive tooling. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_tlds.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_tlds.csv) | Weekly | 15.4 KB | 2026-10-04 | **Suspicious TLDs**. Top-level domains over-represented in malicious activity. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_double_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_double_extensions.csv) | Weekly | 27.0 KB | 2026-10-04 | **Suspicious double extensions**. Deceptive double file extensions (invoice.pdf.exe...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_mac_addresses.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_mac_addresses.csv) | Weekly | 3.9 KB | 2026-10-04 | **Suspicious MAC addresses**. MAC prefixes of attack hardware, VMs and spoofed devices. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_suspicious_usb_ids.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_suspicious_usb_ids.csv) | Weekly | 5.5 KB | 2026-10-04 | **Suspicious USB IDs**. USB IDs of attack devices (Rubber Ducky, O.MG, Flipper...). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_ransomware_extensions.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_ransomware_extensions.csv) | Weekly | 19.4 KB | 2026-10-04 | **Ransomware extensions**. File extensions appended by ransomware families. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_ransomware_notes.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_ransomware_notes.csv) | Weekly | 26.8 KB | 2026-10-04 | **Ransomware notes**. Ransom note file names by ransomware family. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_doh_servers.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_doh_servers.csv) | Weekly | 237.5 KB | 2026-10-04 | **DNS-over-HTTPS servers**. Public DoH resolvers (DNS bypass and covert channel detection). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_blockchain_rpc.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_blockchain_rpc.csv) | Weekly | 28.8 KB | 2026-10-04 | **Blockchain RPC endpoints**. Public blockchain RPC endpoints (abused for C2 resolution, e.g. EtherHiding). | [github.com](https://github.com/mthcht/awesome-lists) |
| [`mthcht_windows_asr_rules.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/mthcht_windows_asr_rules.csv) | Weekly | 3.9 KB | 2026-10-04 | **Windows ASR rules**. Microsoft Defender Attack Surface Reduction rule names and GUIDs. | [github.com](https://github.com/mthcht/awesome-lists) |
| [`ihebski_default_credentials.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/ihebski_default_credentials.csv) | Weekly | 95.0 KB | 2026-10-04 | **Default credentials cheat sheet**. 3,500+ vendor default credentials (product, username, password). | [github.com](https://github.com/ihebski/DefaultCreds-cheat-sheet) |
| [`seclists_default_passwords.csv`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_default_passwords.csv) | Weekly | 88.7 KB | 2026-10-04 | **SecLists default credentials**. Vendor default usernames and passwords. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`seclists_secret_keywords.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_secret_keywords.txt) | Weekly | 825 B | 2026-10-04 | **SecLists secret keywords**. Variable names that usually hold secrets. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`seclists_webshells.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/seclists_webshells.txt) | Weekly | 14.4 KB | 2026-10-04 | **SecLists web shells**. Known web shell and backdoor file names. | [github.com](https://github.com/danielmiessler/SecLists) |
| [`badbot_user_agents.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_user_agents.txt) | Weekly | 7.5 KB | 2026-10-04 | **Bad Bot Blocker - user agents**. Bad bots and scrapers User-Agents. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`badbot_referrers.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_referrers.txt) | Weekly | 115.2 KB | 2026-10-04 | **Bad Bot Blocker - referrers**. Spam referrer domains. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`badbot_fake_googlebots.txt`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/badbot_fake_googlebots.txt) | Weekly | 3.0 KB | 2026-10-04 | **Bad Bot Blocker - fake Googlebots**. IPs pretending to be Googlebot. | [github.com](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) |
| [`misp_warninglists.json.gz`](https://raw.githubusercontent.com/emeryn/CybrefV2/main/detection/misp_warninglists.json.gz) | Weekly | 35.4 MB | 2026-10-04 | **MISP warninglists**. Known-benign indicators (public DNS, CDNs, cloud ranges, known-good Windows hashes...) to cut false positives. One object per list (popularity rankings excluded). | [github.com](https://github.com/MISP/misp-warninglists) |

## Disclaimer

Data belongs to its respective sources, which deserve all the credit. This repository only
mirrors it: check each source's license before any commercial or production use.
