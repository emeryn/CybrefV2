import asyncio
import gzip
import json
import logging
import re
from datetime import date, datetime
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup, Tag

from .base import CVEInfo, DeviceInfo, ManufacturerScraper, SecurityBulletin
from .version import version_key, version_major, version_sort_desc

logger = logging.getLogger("mcb.apple")

_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_SECURITY_INDEX = "https://support.apple.com/en-us/100100"
_APPLEDB_DEVICES = "https://api.appledb.dev/device/main.json.gz"
_APPLEDB_IOS = "https://api.appledb.dev/ios/iOS/main.json.gz"
_ARCHIVE_LINK = re.compile(r"Apple security updates\s*\(([^)]+)\)", re.I)
_YEAR_IN_TEXT = re.compile(r"\b(?:19|20)\d{2}\b")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
IOS_VER_IN_TITLE = re.compile(
    r"\biOS\s+(\d+(?:\.\d+){0,3})\b",
    re.I,
)
IPHONE_ID_RE = re.compile(r"^iPhone\d+,\d+$")
_MONTHS = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}


class AppleScraper(ManufacturerScraper):
    def __init__(self, timeout: float = 45.0):
        self._timeout = timeout
        self._ios_by_device: dict[str, list[str]] = {}

    @property
    def name(self) -> str:
        return "apple"

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers=_BROWSER_HEADERS,
        )

    async def fetch_bulletins(self, from_year: int | None = None) -> list[SecurityBulletin]:
        async with self._client() as client:
            try:
                resp = await client.get(_SECURITY_INDEX)
                resp.raise_for_status()
            except httpx.HTTPError as exc:
                logger.error("Apple security index fetch failed: %s", exc)
                return []

            index_pages = [_SECURITY_INDEX, *self._archive_index_urls(resp.text, from_year)]
            months = self._parse_security_index(resp.text)
            for url in index_pages[1:]:
                try:
                    r = await client.get(url)
                    r.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.warning("Apple archive index fetch failed (%s): %s", url, exc)
                    continue
                months.extend(self._parse_security_index(r.text))
                logger.info("Apple archive index %s: parsed cumulative %d rows", url, len(months))

            # Same advisory URL can appear twice, keep the earliest release.
            by_url: dict[str, dict] = {}
            for m in months:
                prev = by_url.get(m["url"])
                if prev is None or m["released"] < prev["released"]:
                    by_url[m["url"]] = m
            months = list(by_url.values())
            if from_year is not None:
                months = [m for m in months if int(m["released"][:4]) >= from_year]
            months.sort(key=lambda m: (m["released"], m["ios_version"]))
            if from_year is not None:
                logger.info(
                    "Apple iOS advisories: %d since %d (%d index pages)",
                    len(months), from_year, len(index_pages),
                )
            else:
                logger.info(
                    "Apple iOS advisories: %d full history (%d index pages)",
                    len(months), len(index_pages),
                )

            sem = asyncio.Semaphore(6)

            async def one(month: dict) -> SecurityBulletin | None:
                async with sem:
                    cves = await self._fetch_advisory_cves(client, month["url"])
                if not cves:
                    return None
                return SecurityBulletin(
                    spl_date=month["released"],
                    manufacturer="apple",
                    url=month["url"],
                    cves=cves,
                    fixed_in_version=month["ios_version"],
                )

            results = await asyncio.gather(*(one(m) for m in months))
            out = [b for b in results if b is not None]
            logger.info("Apple bulletins with CVEs: %d", len(out))
            return out

    async def fetch_devices(self) -> list[DeviceInfo]:
        async with self._client() as client:
            devices_raw, ios_raw = await asyncio.gather(
                self._get_json_gz(client, _APPLEDB_DEVICES),
                self._get_json_gz(client, _APPLEDB_IOS),
            )
        if not devices_raw or not ios_raw:
            logger.error("AppleDB fetch failed — no iPhone catalog")
            return []

        self._ios_by_device = self._versions_by_device(ios_raw)
        devices: list[DeviceInfo] = []
        for entry in devices_raw:
            if not isinstance(entry, dict):
                continue
            if (entry.get("type") or "").lower() != "iphone":
                continue
            identifiers = entry.get("identifier") or []
            if isinstance(identifiers, str):
                identifiers = [identifiers]
            model = next((i for i in identifiers if IPHONE_ID_RE.match(i)), None)
            if not model:
                continue
            versions = self._ios_by_device.get(model, [])
            if not versions:
                continue
            latest = versions[0]
            top_major = version_major(latest)
            versions = [v for v in versions if version_major(v) >= top_major - 1][:40]
            name = entry.get("name") or model
            devices.append(
                DeviceInfo(
                    name=name,
                    model_code=model,
                    manufacturer="apple",
                    device_type="phone",
                    os_version=latest,
                    os_versions=versions,
                )
            )
        # AppleDB lists GSM/Global variants as separate entries with the same model_code.
        by_code: dict[str, DeviceInfo] = {}
        for d in devices:
            prev = by_code.get(d.model_code)
            if prev is None or version_key(d.os_version or "") > version_key(prev.os_version or ""):
                by_code[d.model_code] = d
        out = sorted(by_code.values(), key=lambda d: d.name)
        logger.info("Apple catalog: %d iPhones", len(out))
        return out

    async def fetch_all_spls(
        self,
        _model_code: str,
        _default_csc: str,
        _csc_hints: list[str] | None = None,
    ) -> dict[str, str]:
        return {}

    @staticmethod
    async def _get_json_gz(client: httpx.AsyncClient, url: str) -> list | dict | None:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("GET %s failed: %s", url, exc)
            return None
        raw = resp.content
        if url.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return json.loads(raw)

    @classmethod
    def _versions_by_device(cls, ios_entries: list) -> dict[str, list[str]]:
        by_dev: dict[str, set[str]] = {}
        for entry in ios_entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("beta") or entry.get("rc") or entry.get("rsr"):
                continue
            if (entry.get("osStr") or "iOS") != "iOS":
                continue
            version = str(entry.get("version") or "").strip()
            if not version or not re.match(r"^\d+(\.\d+){0,3}$", version):
                continue
            # Simulator / internal build labels slip past the numeric regex.
            if any(x in version.lower() for x in ("sim", "beta", "rc")):
                continue
            device_map = entry.get("deviceMap") or entry.get("devices") or []
            if not isinstance(device_map, list):
                continue
            for dev in device_map:
                if not isinstance(dev, str) or not IPHONE_ID_RE.match(dev):
                    continue
                by_dev.setdefault(dev, set()).add(version)
        return {k: version_sort_desc(list(v)) for k, v in by_dev.items()}

    @classmethod
    def _archive_index_urls(cls, html: str, start_year: int | None) -> list[str]:
        """Archive index URLs; if *start_year* set, drop archives whose max year is older."""
        soup = BeautifulSoup(html, "lxml")
        out: list[str] = []
        seen: set[str] = set()
        for a in soup.find_all("a", href=True):
            title = a.get_text(" ", strip=True)
            m = _ARCHIVE_LINK.search(title)
            if not m:
                continue
            years = [int(y) for y in _YEAR_IN_TEXT.findall(m.group(1))]
            if start_year is not None and (not years or max(years) < start_year):
                continue
            href = a["href"]
            url = href if href.startswith("http") else urljoin("https://support.apple.com", href)
            if url.rstrip("/") == _SECURITY_INDEX.rstrip("/") or url in seen:
                continue
            seen.add(url)
            out.append(url)
        return out

    @classmethod
    def _parse_security_index(cls, html: str) -> list[dict]:
        soup = BeautifulSoup(html, "lxml")
        rows: list[dict] = []
        seen_urls: set[str] = set()
        for table in soup.find_all("table"):
            for tr in table.find_all("tr"):
                cells = tr.find_all(["td", "th"])
                if len(cells) < 3:
                    continue
                link = cells[0].find("a", href=True)
                if not link:
                    continue
                title = link.get_text(" ", strip=True)
                if "no published cve" in title.lower():
                    continue
                ios_m = IOS_VER_IN_TITLE.search(title)
                if not ios_m:
                    continue
                # macOS rows often mention iOS in passing - require iOS at the start.
                if not re.search(r"^\s*iOS\b", title, re.I) and "and iPadOS" not in title:
                    if not title.lower().startswith("ios"):
                        continue
                href = link["href"]
                url = href if href.startswith("http") else urljoin("https://support.apple.com", href)
                if url in seen_urls:
                    continue
                released = cls._parse_release_date(cells[2].get_text(" ", strip=True))
                if not released:
                    continue
                seen_urls.add(url)
                rows.append(
                    {
                        "ios_version": ios_m.group(1),
                        "url": url,
                        "released": released,
                        "available_for": cells[1].get_text(" ", strip=True),
                        "title": title,
                    }
                )
        return rows

    @staticmethod
    def _parse_release_date(text: str) -> str | None:
        # "29 Jun 2026" / "June 29, 2026"
        t = text.strip()
        m = re.match(
            r"(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$",
            t,
        )
        if m:
            day, mon, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
            month = _MONTHS.get(mon) or _MONTHS.get(mon[:3])
            if not month:
                return None
            try:
                return date(year, month, day).isoformat()
            except ValueError:
                return None
        m = re.match(
            r"([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})$",
            t,
        )
        if m:
            mon, day, year = m.group(1).lower(), int(m.group(2)), int(m.group(3))
            month = _MONTHS.get(mon) or _MONTHS.get(mon[:3])
            if not month:
                return None
            try:
                return date(year, month, day).isoformat()
            except ValueError:
                return None
        try:
            return datetime.strptime(t, "%Y-%m-%d").date().isoformat()
        except ValueError:
            return None

    async def _fetch_advisory_cves(
        self, client: httpx.AsyncClient, url: str
    ) -> list[CVEInfo]:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            logger.debug("Advisory fetch failed %s: %s", url, exc)
            return []
        if resp.status_code != 200:
            return []
        text = resp.text
        if "no published cve" in text.lower():
            return []
        return self._parse_advisory_cves(text)

    @staticmethod
    def _parse_advisory_cves(html: str) -> list[CVEInfo]:
        seen: set[str] = set()
        out: list[CVEInfo] = []
        for m in CVE_PATTERN.finditer(html):
            cid = m.group(0).upper()
            if cid in seen:
                continue
            seen.add(cid)
            out.append(CVEInfo(cve_id=cid, severity="unknown"))
        return out
