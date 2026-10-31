import json
import logging
import re
from datetime import date
from pathlib import Path
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup, Tag

from .base import CVEInfo, DeviceInfo, ManufacturerScraper, SecurityBulletin

logger = logging.getLogger("mcb.google")

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_BASE = "https://source.android.com"
_PIXEL_INDEX = f"{_BASE}/docs/security/bulletin/pixel"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
SPL_PATTERN = re.compile(r"(20\d{2})-(\d{2})-(\d{2})")

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
}

_DEVICES_PATH = Path(__file__).with_name("pixel_devices.json")


class GoogleScraper(ManufacturerScraper):
    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        self._supported_models: set[str] = set()
        self._latest_bulletin_spl: str | None = None

    @property
    def name(self) -> str:
        return "google"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers=_BROWSER_HEADERS,
        )

    async def fetch_bulletins(self, from_year: int | None = None) -> list[SecurityBulletin]:
        async with self._client() as client:
            pixel_months = await self._list_pixel_months(client)
            if pixel_months:
                self._latest_bulletin_spl = max(m["spl"] for m in pixel_months)
                logger.info("Latest Pixel bulletin SPL: %s", self._latest_bulletin_spl)
            if from_year is not None:
                pixel_months = [m for m in pixel_months if int(m["spl"][:4]) >= from_year]
                logger.info("Pixel index: %d months since %d", len(pixel_months), from_year)
            else:
                logger.info("Pixel index: %d months (full history)", len(pixel_months))

            bulletins: list[SecurityBulletin] = []
            for month in pixel_months:
                cves = await self._fetch_month_cves(client, month)
                if not cves:
                    continue
                bulletins.append(
                    SecurityBulletin(
                        spl_date=month["spl"],
                        manufacturer="google",
                        url=month["pixel_url"],
                        cves=cves,
                    )
                )
            return bulletins

    async def fetch_devices(self) -> list[DeviceInfo]:
        catalog = json.loads(_DEVICES_PATH.read_text(encoding="utf-8"))
        today = date.today()
        devices: list[DeviceInfo] = []
        self._supported_models = set()
        for entry in catalog:
            launch = date.fromisoformat(entry["launch"])
            end = date(
                launch.year + int(entry["support_years"]),
                launch.month,
                1,
            )
            code = entry["model_code"]
            if end > today:
                self._supported_models.add(code)
            devices.append(
                DeviceInfo(
                    name=entry["name"],
                    model_code=code,
                    manufacturer="google",
                    device_type=entry.get("device_type", "phone"),
                    security_update_end=end.isoformat(),
                    os_update_end=end.isoformat(),
                    spl_frequency="monthly" if end > today else None,
                )
            )
        logger.info(
            "Pixel catalog: %d devices (%d still supported)",
            len(devices),
            len(self._supported_models),
        )
        return devices

    async def fetch_all_spls(
        self,
        model_code: str,
        _default_csc: str,
        _csc_hints: list[str] | None = None,
    ) -> dict[str, str]:
        # No publishable per-device build feed: assume supported models track the
        # latest Pixel Update Bulletin SPL.
        if model_code not in self._supported_models or not self._latest_bulletin_spl:
            return {}
        return {"GLOBAL": self._latest_bulletin_spl}

    async def _list_pixel_months(self, client: httpx.AsyncClient) -> list[dict]:
        try:
            resp = await client.get(_PIXEL_INDEX)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch Pixel bulletin index: %s", exc)
            return []
        return self._parse_pixel_index(resp.text)

    @staticmethod
    def _parse_pixel_index(html: str) -> list[dict]:
        soup = BeautifulSoup(html, "lxml")
        months: list[dict] = []
        for table in soup.find_all("table"):
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            joined = " ".join(headers)
            if "bulletin" not in joined or "security" not in joined:
                continue
            for tr in table.find_all("tr")[1:]:
                cells = tr.find_all(["td", "th"])
                if len(cells) < 4:
                    continue
                spl_m = SPL_PATTERN.search(cells[3].get_text(" ", strip=True))
                if not spl_m:
                    continue
                spl = f"{spl_m.group(1)}-{spl_m.group(2)}-{spl_m.group(3)}"
                link = tr.find("a", href=True)
                if not link:
                    continue
                href = link["href"]
                pixel_url = urljoin(_BASE, href)
                slug_m = re.search(r"(20\d{2}-\d{2}-\d{2})", href)
                slug = slug_m.group(1) if slug_m else f"{spl[:7]}-01"
                year = slug[:4]
                android_candidates = [
                    f"{_BASE}/docs/security/bulletin/{year}/{slug}",
                    f"{_BASE}/docs/security/bulletin/{slug}",
                    f"{_BASE}/security/bulletin/{slug}.html",
                ]
                months.append(
                    {
                        "spl": spl,
                        "slug": slug,
                        "pixel_url": pixel_url,
                        "android_urls": android_candidates,
                    }
                )
            break
        return months

    async def _fetch_month_cves(
        self, client: httpx.AsyncClient, month: dict
    ) -> list[CVEInfo]:
        seen: set[str] = set()
        cves: list[CVEInfo] = []

        def _absorb(page_cves: list[CVEInfo]) -> None:
            for c in page_cves:
                cid = c.cve_id.upper()
                if cid in seen:
                    continue
                seen.add(cid)
                cves.append(CVEInfo(cve_id=cid, severity=c.severity, description=c.description))

        android_html = await self._get_first_ok(client, month["android_urls"])
        if android_html:
            _absorb(self._parse_cve_tables(android_html))

        pixel_candidates = [
            month["pixel_url"],
            f"{_BASE}/docs/security/bulletin/pixel/{month['slug']}",
            f"{_BASE}/security/bulletin/pixel/{month['slug']}.html",
        ]
        pixel_html = await self._get_first_ok(client, pixel_candidates)
        if pixel_html:
            _absorb(self._parse_cve_tables(pixel_html))

        if not cves:
            logger.debug("No CVEs for Pixel month %s", month["spl"])
        return cves

    async def _get_first_ok(
        self, client: httpx.AsyncClient, urls: list[str]
    ) -> str | None:
        for url in urls:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                logger.debug("GET %s failed: %s", url, exc)
                continue
            if resp.status_code != 200:
                continue
            if CVE_PATTERN.search(resp.text) or "security patch level" in resp.text.lower():
                return resp.text
        return None

    @classmethod
    def _parse_cve_tables(cls, html: str) -> list[CVEInfo]:
        soup = BeautifulSoup(html, "lxml")
        body = soup.select_one(".devsite-article-body") or soup
        results: list[CVEInfo] = []
        seen: set[str] = set()
        for table in body.find_all("table"):
            if not isinstance(table, Tag):
                continue
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            if not any("cve" == h or h.startswith("cve") for h in headers):
                first_cells = [
                    td.get_text(strip=True)
                    for td in table.select("tr td:first-child")[:3]
                ]
                if not any(CVE_PATTERN.fullmatch(t) for t in first_cells):
                    continue
            sev_idx = next(
                (i for i, h in enumerate(headers) if "severity" in h),
                None,
            )
            cve_idx = next(
                (i for i, h in enumerate(headers) if h == "cve" or h.startswith("cve")),
                0,
            )
            for tr in table.find_all("tr")[1:]:
                cells = tr.find_all(["td", "th"])
                if not cells:
                    continue
                texts = [c.get_text(" ", strip=True) for c in cells]
                blob = " ".join(texts)
                if sev_idx is not None and sev_idx < len(texts):
                    severity = cls._normalize_severity(texts[sev_idx])
                else:
                    severity = cls._normalize_severity(blob)
                for m in CVE_PATTERN.finditer(blob):
                    cve_id = m.group(0).upper()
                    if cve_id in seen:
                        continue
                    if cve_idx < len(texts) and cve_id not in texts[cve_idx].upper():
                        continue
                    seen.add(cve_id)
                    results.append(CVEInfo(cve_id=cve_id, severity=severity))
        return results

    @staticmethod
    def _normalize_severity(text: str) -> str:
        low = text.lower().strip()
        for kw, sev in SEVERITY_MAP.items():
            if kw in low:
                return sev
        return "unknown"
