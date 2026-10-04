"""NVD enrichment: local data/ bulk feeds + NVD REST API / cve.org fallbacks for gaps."""

import asyncio
import gzip
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import date

import httpx

logger = logging.getLogger("mcb.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"
_BULK_FEEDS = ("nvdcve-2.0-recent.json", "nvdcve-2.0-modified.json")
_NIST_SOURCE = "nvd@nist.gov"
_CISA_ADP_SOURCE = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
_CVSS_VERSION_ORDER = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass
class CVEDetail:
    severity: str = "unknown"
    description: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] = field(default_factory=list)
    nvd_found: bool = True  # False = cve.org fallback only


def _metric_rank(item: dict) -> int | None:
    cvss = item.get("cvssData", {})
    raw_sev = (cvss.get("baseSeverity") or "").upper()
    if not raw_sev or raw_sev == "NONE":
        return None
    source = item.get("source", "")
    mtype = (item.get("type") or "").lower()
    if source == _NIST_SOURCE and mtype == "primary":
        return 0
    if source == _NIST_SOURCE:
        return 1
    if source == _CISA_ADP_SOURCE:
        return 2
    return 3


def _pick_cvss(metrics: dict) -> tuple[str, float | None, str | None]:
    best_rank: int | None = None
    best_version = len(_CVSS_VERSION_ORDER)
    severity = "unknown"
    score: float | None = None
    vector: str | None = None

    for version_idx, key in enumerate(_CVSS_VERSION_ORDER):
        for item in metrics.get(key) or []:
            rank = _metric_rank(item)
            if rank is None:
                continue
            if best_rank is None or rank < best_rank or (
                rank == best_rank and version_idx < best_version
            ):
                best_rank = rank
                best_version = version_idx
                data = item.get("cvssData", {})
                severity = data.get("baseSeverity", "").lower()
                score = data.get("baseScore")
                vector = data.get("vectorString")

    return severity, score, vector


def _parse_entry(item: dict) -> CVEDetail | None:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})

    severity, score, vector = _pick_cvss(metrics)

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    refs = [r["url"] for r in cve.get("references", []) if r.get("url")]

    return CVEDetail(
        severity=severity,
        description=description,
        cvss_score=score,
        cvss_vector=vector,
        references=refs,
    )


def _parse_bulk(data: dict) -> dict[str, CVEDetail]:
    result: dict[str, CVEDetail] = {}
    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cve", {}).get("id")
        if not cve_id:
            continue
        detail = _parse_entry(item)
        if detail:
            result[cve_id] = detail
    return result


def _cve_year(cve_id: str) -> str | None:
    parts = cve_id.split("-")
    return parts[1] if len(parts) >= 2 and parts[1].isdigit() else None


def _cve_is_recent(cve_id: str) -> bool:
    year = _cve_year(cve_id)
    today = date.today()
    return year is not None and int(year) >= today.year - 1


def _load_nvd_feed(nvd_dir: str, filename: str) -> dict | None:
    base = os.path.join(nvd_dir, filename)
    candidates = [base]
    if filename.endswith(".json.gz"):
        candidates.append(base[:-3])
    elif filename.endswith(".json"):
        candidates.append(base + ".gz")
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rb") as f:
                    return json.loads(f.read())
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("NVD: failed to read %s: %s", path, exc)
    return None


class _NVDRateLimiter:
    def __init__(self, max_per_window: int, window: float = 30.0):
        self._max = max_per_window
        self._window = window
        self._tokens = max_per_window
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                if now - self._last_refill >= self._window:
                    self._tokens = self._max
                    self._last_refill = now
                if self._tokens > 0:
                    self._tokens -= 1
                    return
                wait = self._window - (time.monotonic() - self._last_refill)
            await asyncio.sleep(max(wait, 0.1))


def _parse_cve_org_entry(data: dict) -> CVEDetail | None:
    cna = data.get("containers", {}).get("cna", {})

    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "")
            break

    severity = "unknown"
    score: float | None = None
    vector: str | None = None
    for metric_block in cna.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            m = metric_block.get(key)
            if not m:
                continue
            raw_sev = m.get("baseSeverity", "")
            if raw_sev and raw_sev.upper() != "NONE":
                severity = raw_sev.lower()
                score = m.get("baseScore")
                vector = m.get("vectorString")
                break
        if severity != "unknown":
            break

    refs = [r["url"] for r in cna.get("references", []) if r.get("url")]

    if not description and severity == "unknown":
        return None

    return CVEDetail(
        severity=severity,
        description=description,
        cvss_score=score,
        cvss_vector=vector,
        references=refs,
        nvd_found=False,
    )


class CVEOrgEnricher:
    def __init__(self, concurrency: int = 5):
        self._concurrency = concurrency

    async def enrich(self, cve_ids: list[str]) -> dict[str, CVEDetail]:
        result: dict[str, CVEDetail] = {}
        semaphore = asyncio.Semaphore(self._concurrency)

        async def fetch_one(client: httpx.AsyncClient, cve_id: str) -> None:
            async with semaphore:
                try:
                    resp = await client.get(f"{CVE_ORG_API_BASE}/{cve_id}")
                    if resp.status_code == 404:
                        return
                    resp.raise_for_status()
                    detail = _parse_cve_org_entry(resp.json())
                    if detail:
                        result[cve_id] = detail
                except Exception as exc:
                    logger.debug("cve.org: %s failed: %s", cve_id, exc)

        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            await asyncio.gather(*(fetch_one(client, cid) for cid in cve_ids))

        return result


class NVDEnricher:
    def __init__(
        self,
        nvd_api_key: str | None = None,
        concurrency: int = 5,
        nvd_dir: str | None = None,
    ):
        self._nvd_dir = nvd_dir or "data"
        self._cve_org = CVEOrgEnricher(concurrency)
        self._api_key = nvd_api_key
        self._concurrency = concurrency
        max_rps = 50 if nvd_api_key else 5
        self._limiter = _NVDRateLimiter(max_per_window=max_rps)

    def _load_bulk(self, cve_ids: set[str]) -> dict[str, CVEDetail]:
        years = {y for cid in cve_ids if (y := _cve_year(cid))}
        result: dict[str, CVEDetail] = {}

        for year in sorted(years):
            data = _load_nvd_feed(self._nvd_dir, f"nvdcve-2.0-{year}.json.gz")
            if data:
                parsed = _parse_bulk(data)
                result.update(parsed)
                logger.info("NVD local: %s → %d entries (total: %d)", year, len(parsed), len(result))

        for name in _BULK_FEEDS:
            data = _load_nvd_feed(self._nvd_dir, name)
            if data:
                parsed = _parse_bulk(data)
                result.update(parsed)
                logger.info("NVD local: %s → %d entries", name, len(parsed))

        return result

    async def build_map(self, cve_ids: set[str]) -> dict[str, CVEDetail]:
        result = self._load_bulk(cve_ids)

        missing_recent = [
            cid for cid in cve_ids
            if cid not in result and _cve_is_recent(cid)
        ]
        if missing_recent:
            logger.info("NVD API: fetching %d recent CVEs not in bulk feeds", len(missing_recent))
            api_results = await self._fetch_from_api(missing_recent)
            result.update(api_results)
            logger.info("NVD API: got details for %d CVEs", len(api_results))

        nvd_missing = [
            cid for cid in cve_ids
            if cid not in result or result[cid].severity == "unknown"
        ]
        if nvd_missing:
            logger.info("cve.org: fetching %d CVEs absent/incomplete in NVD", len(nvd_missing))
            cve_org_results = await self._cve_org.enrich(nvd_missing)
            for cid, detail in cve_org_results.items():
                if cid not in result or result[cid].severity == "unknown":
                    result[cid] = detail
            logger.info("cve.org: enriched %d CVEs", len(cve_org_results))

        return result

    async def _fetch_from_api(self, cve_ids: list[str]) -> dict[str, CVEDetail]:
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        total = len(cve_ids)
        result: dict[str, CVEDetail] = {}
        semaphore = asyncio.Semaphore(self._concurrency)
        completed = 0
        log_every = max(1, min(10, total // 5))

        async def fetch_one(client: httpx.AsyncClient, cve_id: str) -> None:
            nonlocal completed
            async with semaphore:
                await self._limiter.acquire()
                try:
                    resp = await client.get(NVD_API_BASE, params={"cveId": cve_id})
                    resp.raise_for_status()
                    vulns = resp.json().get("vulnerabilities", [])
                    if vulns:
                        detail = _parse_entry(vulns[0])
                        if detail:
                            result[cve_id] = detail
                except Exception as exc:
                    logger.debug("NVD API: %s failed: %s", cve_id, exc)
                completed += 1
                if completed % log_every == 0 or completed == total:
                    logger.info(
                        "NVD API: %d/%d fetched, %d with data",
                        completed, total, len(result),
                    )

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            await asyncio.gather(*(fetch_one(client, cid) for cid in cve_ids))

        return result
