import asyncio
import logging
import re
from datetime import date

import httpx
from bs4 import BeautifulSoup, NavigableString, Tag

from .base import CVEInfo, DeviceInfo, ManufacturerScraper, SecurityBulletin
from .csc_registry import CscMeta, candidate_cscs, load_csc_registry

logger = logging.getLogger("mcb.samsung")


_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

SEVERITY_KEYWORDS = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}

MONTH_MAP = {
    "jan": "01", "january": "01",
    "feb": "02", "february": "02",
    "mar": "03", "march": "03",
    "apr": "04", "april": "04",
    "may": "05",
    "jun": "06", "june": "06",
    "jul": "07", "july": "07",
    "aug": "08", "august": "08",
    "sep": "09", "september": "09",
    "oct": "10", "october": "10",
    "nov": "11", "november": "11",
    "dec": "12", "december": "12",
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
_SVE_HEADER = re.compile(r"SVE-\d{4}-\d+", re.IGNORECASE)
_SEVERITY_LINE = re.compile(r"^Severity:\s*([A-Za-z]+)", re.IGNORECASE)
_ZONE_ANDROID = re.compile(
    r"Google patches|Android Security Bulletin", re.IGNORECASE
)
_ZONE_SEMI = re.compile(r"Samsung Semiconductor", re.IGNORECASE)
_ZONE_SVE = re.compile(
    r"Samsung Vulnerabilities and Exposures|\bSVE items\b", re.IGNORECASE
)


class SamsungScraper(ManufacturerScraper):
    BULLETIN_URL = "https://security.samsungmobile.com"
    KNOX_URL = "https://www.samsungknox.com"
    FOTA_URL = "https://doc.samsungmobile.com"

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        self._csc_registry: dict[str, CscMeta] = load_csc_registry()

    @property
    def name(self) -> str:
        return "samsung"

    def infer_spl(
        self,
        model_code: str,
        confirmed: dict[str, date],
        siblings: list[tuple[str, date]],
    ) -> tuple[date, str] | None:
        """Strip regional suffixes before falling back to sibling models."""
        code = model_code
        for _ in range(2):
            if len(code) <= 3:
                break
            code = code[:-1]
            if code in confirmed:
                return confirmed[code], code
        return super().infer_spl(model_code, confirmed, siblings)

    def _client(self, base_url: str, headers: dict | None = None) -> httpx.AsyncClient:
        kwargs: dict = dict(
            base_url=base_url,
            timeout=self._timeout,
            follow_redirects=True,
        )
        if headers:
            kwargs["headers"] = headers
        return httpx.AsyncClient(**kwargs)

    async def fetch_bulletins(self, from_year: int | None = None) -> list[SecurityBulletin]:
        # Page shows current year only; older years need POST year=YYYY. SMR public from 2016.
        today = date.today()
        start = from_year if from_year is not None else 2016
        years = range(start, today.year + 1)
        bulletins_map: dict[str, list[CVEInfo]] = {}

        async with self._client(self.BULLETIN_URL, _BROWSER_HEADERS) as client:
            for year in years:
                try:
                    resp = await client.post("/securityUpdate.smsb", data={"year": str(year)})
                    resp.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.warning("Failed to fetch bulletins for %d: %s", year, exc)
                    continue
                self._parse_bulletin_page_into(resp.text, bulletins_map)
                logger.info("Fetched Samsung bulletins for %d (%d unique SPL dates so far)", year, len(bulletins_map))

        if not bulletins_map:
            logger.warning("No bulletins parsed — Samsung may have changed their HTML layout")

        return [
            SecurityBulletin(spl_date=d, manufacturer="samsung", cves=cves)
            for d, cves in sorted(bulletins_map.items())
            if cves
        ]

    def _parse_bulletin_page_into(self, html: str, bulletins_map: dict[str, list[CVEInfo]]) -> None:
        soup = BeautifulSoup(html, "lxml")
        local_map: dict[str, list[CVEInfo]] = {}

        # 2020+: wrap_acc -> acc_title (SMR date) + acc_sub (Google + SVE).
        for section in soup.select("div.wrap_acc"):
            title_el = section.select_one("div.acc_title")
            if not title_el:
                continue
            spl_date = self._extract_spl_date(title_el.get_text(strip=True))
            if not spl_date:
                continue
            sub = section.select_one("div.acc_sub")
            if not sub:
                continue
            cves: list[CVEInfo] = []
            self._parse_acc_sub(sub, cves)
            if cves:
                local_map[spl_date] = cves

        # Pre-2020 archives still use tables.
        if not local_map:
            for table in soup.find_all("table"):
                heading = table.find_previous(re.compile(r"h[1-6]|strong|b"))
                spl_date = (
                    self._extract_spl_date(heading.get_text(strip=True)) if heading else None
                )
                if not spl_date:
                    continue
                local_map.setdefault(spl_date, [])
                self._parse_table_cves(table, local_map[spl_date])

        for spl_date, cves in local_map.items():
            if spl_date not in bulletins_map:
                bulletins_map[spl_date] = cves
            else:
                existing_ids = {c.cve_id for c in bulletins_map[spl_date]}
                bulletins_map[spl_date].extend(c for c in cves if c.cve_id not in existing_ids)

    def _parse_acc_sub(self, sub: Tag, cves: list[CVEInfo]) -> None:
        """Walk acc_sub: 2026+ splits SVE into padding-left divs; <=2025 keeps all in <font>."""
        seen: set[str] = set()
        current_severity = "unknown"

        def _add(
            cve_id: str,
            severity: str = "unknown",
            description: str = "",
            *,
            source: str,
        ) -> CVEInfo | None:
            if cve_id in seen:
                return None
            seen.add(cve_id)
            info = CVEInfo(
                cve_id=cve_id,
                severity=severity,
                description=description,
                source=source,
            )
            cves.append(info)
            return info

        for child in sub.children:
            if not isinstance(child, Tag):
                continue

            if child.name == "font":
                self._parse_font_block(child, _add)
                # 2026+ SVE divs inherit severity from the last Google label in this font.
                for node in reversed(list(child.children)):
                    if isinstance(node, Tag) and node.name == "strong":
                        sev = self._extract_severity(node.get_text(strip=True))
                        if sev != "unknown":
                            current_severity = sev
                            break

            elif child.name == "strong":
                sev = self._extract_severity(child.get_text(strip=True))
                if sev != "unknown":
                    current_severity = sev

            elif child.name == "div" and "padding-left" in (child.get("style") or ""):
                header_el = child.select_one("strong font") or child.select_one("strong")
                if not header_el:
                    continue
                header = header_el.get_text(strip=True)
                if not _SVE_HEADER.search(header):
                    continue
                cve_ids = CVE_PATTERN.findall(header)
                if not cve_ids:
                    continue
                desc_el = child.find("font", attrs={"size": "3"})
                description = desc_el.get_text(separator=" ", strip=True) if desc_el else ""
                for cve_id in cve_ids:
                    _add(cve_id, current_severity, description, source="sve")

    def _parse_font_block(self, font: Tag, _add) -> None:
        zone = "android"
        severity = "unknown"
        last_sve: list[CVEInfo] = []

        for node in font.children:
            if isinstance(node, NavigableString):
                text = str(node).strip()
                if not text:
                    continue
                sev_m = _SEVERITY_LINE.match(text)
                if sev_m and last_sve:
                    sev = self._extract_severity(sev_m.group(1))
                    if sev != "unknown":
                        for info in last_sve:
                            if info.severity == "unknown":
                                info.severity = sev
                    continue
                # Apply zone switch before same-line CVE ids.
                if _ZONE_SEMI.search(text):
                    zone = "semiconductor"
                    severity = "unknown"
                    last_sve = []
                elif _ZONE_SVE.search(text):
                    zone = "sve"
                    severity = "unknown"
                    last_sve = []
                elif _ZONE_ANDROID.search(text):
                    zone = "android"
                    severity = "unknown"
                    last_sve = []
                if zone in ("android", "semiconductor"):
                    for cve_id in CVE_PATTERN.findall(text):
                        _add(cve_id, severity, source=zone)
                continue

            if not isinstance(node, Tag):
                continue

            if node.name == "font":
                # Nested blurbs can change zone without carrying CVEs.
                nested = node.get_text(" ", strip=True)
                if _ZONE_SEMI.search(nested):
                    zone = "semiconductor"
                    severity = "unknown"
                    last_sve = []
                elif _ZONE_ANDROID.search(nested):
                    zone = "android"
                    severity = "unknown"
                    last_sve = []
                elif _ZONE_SVE.search(nested):
                    zone = "sve"
                    severity = "unknown"
                    last_sve = []
                continue

            if node.name == "strong":
                text = node.get_text(" ", strip=True)
                if _SVE_HEADER.search(text):
                    zone = "sve"
                    last_sve = []
                    for cve_id in CVE_PATTERN.findall(text):
                        info = _add(cve_id, "unknown", text, source="sve")
                        if info:
                            last_sve.append(info)
                    continue
                sev = self._extract_severity(text)
                if sev != "unknown":
                    severity = sev
                continue

    def _parse_table_cves(self, table, cves: list[CVEInfo]) -> None:
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if not cells:
                continue
            row_text = " ".join(c.get_text(strip=True) for c in cells)
            for cve_id in CVE_PATTERN.findall(row_text):
                if not any(c.cve_id == cve_id for c in cves):
                    cves.append(CVEInfo(
                        cve_id=cve_id,
                        severity=self._extract_severity(row_text),
                    ))

    @staticmethod
    def _extract_spl_date(text: str) -> str | None:
        low = text.lower().strip()

        m = re.search(r"smr[- ](\w{3,9})[- ](\d{4})", low)
        if m:
            month = MONTH_MAP.get(m.group(1))
            if month:
                return f"{m.group(2)}-{month}-01"

        # Longest month name first; word boundary avoids "mar" inside "summary".
        for name, num in sorted(MONTH_MAP.items(), key=lambda kv: -len(kv[0])):
            if re.search(rf"\b{re.escape(name)}\b", low):
                year = re.search(r"20\d{2}", text)
                if year:
                    return f"{year.group()}-{num}-01"

        m = re.search(r"(20\d{2})[/-](\d{2})(?!\d)", text)
        if m and 1 <= int(m.group(2)) <= 12:
            return f"{m.group(1)}-{m.group(2)}-01"

        return None

    @staticmethod
    def _extract_severity(text: str) -> str:
        low = text.lower()
        for kw, sev in SEVERITY_KEYWORDS.items():
            if kw in low:
                return sev
        return "unknown"

    async def fetch_devices(self) -> list[DeviceInfo]:
        # Without browser headers Knox answers 202 + an HTML bot challenge instead of JSON.
        knox_headers = {**_BROWSER_HEADERS, "Accept": "application/json"}
        async with self._client(self.KNOX_URL, knox_headers) as client:
            knox_data = None
            for attempt in range(1, 4):
                try:
                    resp = await client.get("/en/api/supported-devices", params={"limit": "5000"})
                    resp.raise_for_status()
                    knox_data = resp.json()
                    break
                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning("Knox device list attempt %d/3 failed: %s", attempt, exc)
                    await asyncio.sleep(10 * attempt)
            if knox_data is None:
                logger.error("Failed to fetch device list from Knox")
                return []

        frequencies: dict[str, str] = {}
        try:
            async with self._client(self.BULLETIN_URL, _BROWSER_HEADERS) as client:
                resp = await client.get("/workScope.smsb")
                if resp.status_code == 200:
                    frequencies = self._parse_frequencies(resp.text)
        except Exception as exc:
            logger.debug("workScope.smsb fetch failed (%s), skipping frequencies", exc)

        return self._parse_devices(knox_data, frequencies)

    @staticmethod
    def _parse_frequencies(html: str) -> dict[str, str]:
        freq_map: dict[str, str] = {}
        soup = BeautifulSoup(html, "lxml")
        for container in soup.find_all("div", class_="list_basic"):
            for section in container.find_all("div"):
                text = section.get_text(" ")
                if "Current Models" not in text:
                    continue
                if "Monthly" in text:
                    freq = "monthly"
                elif "Quarterly" in text:
                    freq = "quarterly"
                elif "Biannual" in text:
                    freq = "biannual"
                else:
                    continue
                for li in section.find_all("li"):
                    for entry in li.get_text().split(","):
                        entry = entry.strip()
                        if "Enterprise Models" in entry:
                            parts = entry.split(":")
                            entry = parts[1].strip() if len(parts) >= 2 else ""
                        if entry:
                            freq_map[entry] = freq
        return freq_map

    @staticmethod
    def _parse_devices(data: dict, frequencies: dict[str, str] | None = None) -> list[DeviceInfo]:
        devices: list[DeviceInfo] = []
        seen: set[str] = set()
        freq = frequencies or {}
        for entry in data.get("data", []):
            if entry.get("os") != "Android":
                continue
            name = entry.get("deviceName", "").replace('"', "").replace("w/ S-Pen", "").strip()
            dtype = entry.get("deviceGroup", "phone")
            aer: bool | None = entry.get("androidEnterpriseRecommended")
            if aer is not None:
                aer = bool(aer)
            security_update_end = entry.get("aerSecurityMRGuaranteedUpTo") or None
            os_update_end = entry.get("aerOSVersionUpdateGuaranteedUpTo") or None
            knox_vault: bool | None = entry.get("knoxVault")
            if knox_vault is not None:
                knox_vault = bool(knox_vault)
            spl_frequency = freq.get(name)
            for code in entry.get("modelCode", "").split(","):
                code = code.strip()
                if code and code not in seen:
                    seen.add(code)
                    devices.append(DeviceInfo(
                        name=name,
                        model_code=code,
                        manufacturer="samsung",
                        device_type=dtype,
                        aer_recommended=aer,
                        security_update_end=security_update_end,
                        os_update_end=os_update_end,
                        knox_vault=knox_vault,
                        spl_frequency=spl_frequency,
                    ))
        return devices

    async def fetch_all_spls(
        self,
        model_code: str,
        default_csc: str,
        csc_hints: list[str] | None = None,
    ) -> dict[str, str]:
        """Try previous CSCs first; only scan the full region if none answer."""
        if csc_hints:
            narrow = list(dict.fromkeys([default_csc, *csc_hints, "OXM"]))
            results = await self._fetch_spls_for_cscs(model_code, narrow)
            if results:
                return results
        cscs = candidate_cscs(model_code, default_csc, registry=self._csc_registry)
        return await self._fetch_spls_for_cscs(model_code, cscs)

    async def _fetch_spls_for_cscs(
        self, model_code: str, cscs: list[str]
    ) -> dict[str, str]:
        results: dict[str, str] = {}
        async with self._client(self.FOTA_URL, _BROWSER_HEADERS) as client:
            async def fetch_csc(csc: str) -> None:
                spl = await self._try_fetch_spl(client, model_code, csc)
                if spl:
                    results[csc] = spl
            await asyncio.gather(*(fetch_csc(csc) for csc in cscs))
        return results

    async def _try_fetch_spl(
        self, client: httpx.AsyncClient, model_code: str, csc: str
    ) -> str | None:
        try:
            resp = await client.get(f"/{model_code}/{csc}/doc.html")
        except httpx.HTTPError as exc:
            logger.debug("SPL doc fetch failed for %s/%s: %s", model_code, csc, exc)
            return None

        if resp.status_code != 200:
            return None

        url_match = re.search(r"/\w+-\w+/\w+/eng\.html", resp.text)
        if not url_match:
            return None

        try:
            resp = await client.get(url_match.group(0))
            if resp.status_code != 200:
                return None
        except httpx.HTTPError as exc:
            logger.debug("SPL eng fetch failed for %s/%s: %s", model_code, csc, exc)
            return None

        return self._parse_spl_page(resp.text)

    @staticmethod
    def _parse_spl_page(html: str) -> str | None:
        today = date.today()
        soup = BeautifulSoup(html, "lxml")
        for div in soup.find_all("div"):
            text = div.get_text()
            if "Security patch level" in text:
                m = re.search(r"\d{4}-\d{2}-\d{2}", text)
                if m:
                    try:
                        spl = date.fromisoformat(m.group(0))
                    except ValueError:
                        return None
                    if spl > today:
                        return None
                    return m.group(0)
        return None
