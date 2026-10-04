"""Mobile CVE sync: OEM bulletins + device catalogs, enriched with NVD data."""

import argparse
import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .nvd import CVEDetail, NVDEnricher
from .scrapers import SCRAPERS, ManufacturerScraper
from .scrapers.base import CVEInfo, DeviceInfo, SecurityBulletin
from .scrapers.csc_registry import CscMeta, load_csc_registry

logger = logging.getLogger("mcb")
_LOG_INTERVAL = 5.0
_SPL_STALE_DAYS = 35
_DEFAULT_NVD_DIR = Path("data")
_MIN_RETAINED_RATIO = 0.80

_RE_ISO_HEAD = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def _normalize_eol_to_iso(s: str | None) -> str | None:
    """Knox AER returns "March, 2032" - normalize to YYYY-MM-01."""
    if not s or not str(s).strip():
        return None
    t = str(s).strip()
    m = _RE_ISO_HEAD.match(t)
    if m:
        return m.group(1)
    t = t.replace("Sept", "Sep")
    for fmt in ("%B, %Y", "%b, %Y"):
        try:
            d = datetime.strptime(t, fmt)
            return date(d.year, d.month, 1).isoformat()
        except ValueError:
            pass
    return None


def _eol_for_json_field(raw: str | None) -> str | None:
    """ISO when parseable; keep opaque text (e.g. "Android 23") otherwise."""
    if not raw or not str(raw).strip():
        return None
    t = str(raw).strip()
    n = _normalize_eol_to_iso(t)
    if n:
        return n
    return t


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch CVE + device data and generate static JSON files."
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        metavar="DIR",
        help="JSON output directory",
    )
    parser.add_argument(
        "--nvd-dir",
        type=Path,
        default=_DEFAULT_NVD_DIR,
        metavar="DIR",
        help="Directory with NVD bulk feeds (default: ./data)",
    )
    parser.add_argument(
        "--csc",
        default="XEF",
        metavar="CSC",
        help="Preferred CSC for Samsung current_spl (default: XEF)",
    )
    parser.add_argument(
        "--concurrency",
        default=20,
        type=int,
        metavar="N",
        help="Concurrent SPL / NVD tasks (default: 20)",
    )
    parser.add_argument(
        "--from-scratch",
        action="store_true",
        help=(
            "Rebuild everything from scratch: ignore previous output, re-scrape all "
            "bulletins/devices, and re-enrich all CVEs from NVD"
        ),
    )
    parser.add_argument(
        "--write-individual",
        action="store_true",
        help="Also write per-CVE JSON files under cves/ (debug)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run continuously, syncing daily at --sync-hour/--sync-minute UTC",
    )
    parser.add_argument(
        "--sync-hour",
        type=int,
        default=3,
        metavar="H",
        help="UTC hour for --loop daily sync (default: 3)",
    )
    parser.add_argument(
        "--sync-minute",
        type=int,
        default=0,
        metavar="M",
        help="UTC minute for --loop daily sync (default: 0)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    nvd_api_key = os.environ.get("NVD_API_KEY")

    kwargs = dict(
        output=args.output,
        nvd_dir=args.nvd_dir,
        default_csc=args.csc,
        concurrency=args.concurrency,
        nvd_api_key=nvd_api_key,
        write_individual=args.write_individual,
        full_sync=args.from_scratch,
    )
    if args.loop:
        asyncio.run(_run_loop(
            **kwargs,
            sync_hour=args.sync_hour,
            sync_minute=args.sync_minute,
        ))
    else:
        asyncio.run(sync(**kwargs))


async def _run_loop(
    output: Path,
    nvd_dir: Path,
    default_csc: str,
    concurrency: int,
    nvd_api_key: str | None,
    write_individual: bool = False,
    full_sync: bool = False,
    sync_hour: int = 3,
    sync_minute: int = 0,
) -> None:
    logger.info("Starting background daemon scheduler (%02dh%02d UTC daily)", sync_hour, sync_minute)

    await sync(output, nvd_dir, default_csc, concurrency, nvd_api_key, write_individual, full_sync)

    while True:
        now = datetime.now(timezone.utc)
        next_run = now.replace(hour=sync_hour, minute=sync_minute, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        wait = (next_run - now).total_seconds()
        logger.info("Next scheduled sync in %.0f seconds (%s UTC)", wait, next_run.isoformat())
        await asyncio.sleep(wait)
        try:
            await sync(output, nvd_dir, default_csc, concurrency, nvd_api_key, write_individual, full_sync)
        except Exception as e:
            logger.exception("An error occurred during scheduled sync: %s", e)


@dataclass
class _PreviousState:
    devices_by_model: dict[str, dict]
    cve_details: dict[str, dict]
    cves_index: list[dict]


class SyncValidationError(RuntimeError):
    """Abort before overwrite when a scrape looks dangerously incomplete."""


async def sync(
    output: Path,
    nvd_dir: Path,
    default_csc: str,
    concurrency: int,
    nvd_api_key: str | None,
    write_individual: bool = False,
    full_sync: bool = False,
) -> None:
    logger.info("=== Sync started ===")
    t0 = time.monotonic()

    prev = None if full_sync else _load_previous(output)
    if full_sync:
        logger.info("From-scratch sync: ignoring previous output in %s", output)
    elif prev:
        logger.info(
            "Incremental sync: %d devices, %d CVEs cached in %s",
            len(prev.devices_by_model), len(prev.cve_details), output,
        )
    else:
        logger.info("No previous output — full sync")

    all_bulletins: list[SecurityBulletin] = []
    all_devices: list[DeviceInfo] = []
    current_year = date.today().year

    for name, cls in SCRAPERS.items():
        scraper = cls()
        logger.info("[%s] Fetching bulletins and devices...", name)
        if prev:
            fresh = await scraper.fetch_bulletins(from_year=current_year)
            historical = _bulletins_from_previous(
                prev, manufacturer=name, exclude_year=current_year
            )
            bulletins = _merge_bulletins(historical, fresh)
            logger.info("[%s] %d bulletins (%d historical + %d fresh)",
                        name, len(bulletins), len(historical), len(fresh))
        else:
            bulletins = await scraper.fetch_bulletins()
            logger.info("[%s] %d bulletins", name, len(bulletins))

        devices = await scraper.fetch_devices()
        logger.info("[%s] %d devices", name, len(devices))

        all_bulletins.extend(bulletins)
        await _fetch_spls(scraper, devices, default_csc, concurrency, prev)
        await _infer_spls(scraper, devices)
        all_devices.extend(devices)

    _validate_scrape(all_bulletins, all_devices, prev)

    all_cve_ids = {cve.cve_id for b in all_bulletins for cve in b.cves}
    prev_nvd = _stored_to_nvd_map(prev.cve_details) if prev else {}
    new_cve_ids = all_cve_ids - set(prev_nvd)
    if new_cve_ids:
        logger.info(
            "Enriching %d CVEs from NVD (%d reused from previous output)",
            len(new_cve_ids), len(all_cve_ids) - len(new_cve_ids),
        )
        fresh_nvd = await NVDEnricher(
            nvd_api_key, concurrency, nvd_dir=str(nvd_dir),
        ).build_map(new_cve_ids)
        nvd_map = {**prev_nvd, **fresh_nvd}
    else:
        logger.info("All %d CVEs reused from previous output", len(all_cve_ids))
        nvd_map = prev_nvd

    csc_registry = load_csc_registry()
    _write_output(output, all_bulletins, all_devices, nvd_map, csc_registry, write_individual)
    logger.info("=== Sync done in %.0fs ===", time.monotonic() - t0)


def _validate_scrape(
    bulletins: list[SecurityBulletin],
    devices: list[DeviceInfo],
    prev: _PreviousState | None,
) -> None:
    """Block overwrite when the scrape looks incomplete vs a healthy previous catalog."""
    errors: list[str] = []
    expected = set(SCRAPERS)
    device_counts = {
        name: sum(d.manufacturer.lower() == name.lower() for d in devices)
        for name in expected
    }
    cve_counts = {
        name: len({
            cve.cve_id
            for b in bulletins
            if b.manufacturer.lower() == name.lower()
            for cve in b.cves
        })
        for name in expected
    }

    for name in sorted(expected):
        if device_counts[name] == 0:
            errors.append(f"{name}: no devices")
        if cve_counts[name] == 0:
            errors.append(f"{name}: no bulletin CVEs")

    if prev:
        previous_device_counts = {
            name: sum(
                (d.get("manufacturer") or "").lower() == name.lower()
                for d in prev.devices_by_model.values()
            )
            for name in expected
        }
        previous_cve_counts = {
            name: sum(
                (c.get("manufacturer") or "").lower() == name.lower()
                for c in prev.cves_index
            )
            for name in expected
        }
        for name in sorted(expected):
            previous_devices = previous_device_counts[name]
            if (
                previous_devices
                and device_counts[name] < previous_devices * _MIN_RETAINED_RATIO
            ):
                errors.append(
                    f"{name}: device count dropped from {previous_devices} "
                    f"to {device_counts[name]}"
                )
            previous_cves = previous_cve_counts[name]
            if previous_cves and cve_counts[name] < previous_cves * _MIN_RETAINED_RATIO:
                errors.append(
                    f"{name}: bulletin CVE count dropped from {previous_cves} "
                    f"to {cve_counts[name]}"
                )

    if errors:
        raise SyncValidationError(
            "Refusing to write an incomplete mobile catalog: " + "; ".join(errors)
        )

    logger.info(
        "Scrape validation passed: devices=%s, bulletin CVEs=%s",
        device_counts,
        cve_counts,
    )


async def _fetch_spls(
    scraper: ManufacturerScraper,
    devices: list[DeviceInfo],
    default_csc: str,
    concurrency: int,
    prev: _PreviousState | None = None,
) -> None:
    to_fetch: list[DeviceInfo] = []
    reused = 0
    for d in devices:
        prev_d = prev.devices_by_model.get(d.model_code) if prev else None
        if prev_d and _reuse_spl(d, prev_d):
            reused += 1
        else:
            to_fetch.append(d)

    total = len(devices)
    logger.info("[%s] SPL: %d reused, %d to fetch", scraper.name, reused, len(to_fetch))
    if not to_fetch:
        logger.info("[%s] %d/%d devices have a confirmed SPL", scraper.name, reused, total)
        return

    results: dict[str, dict[str, str]] = {}

    if concurrency == 1:
        for i, d in enumerate(to_fetch, 1):
            hints = _csc_hints(prev, d.model_code) if prev else None
            try:
                spls = await scraper.fetch_all_spls(d.model_code, default_csc, csc_hints=hints)
            except Exception:
                spls = {}
            results[d.model_code] = spls
            if i % max(1, len(to_fetch) // 10) == 0 or i == len(to_fetch):
                logger.info(
                    "[%s] SPL fetch: %d/%d (%d%%)",
                    scraper.name, i, len(to_fetch), i * 100 // len(to_fetch),
                )
    else:
        semaphore = asyncio.Semaphore(concurrency)
        completed = 0
        last_log = time.monotonic()

        async def fetch_one(d: DeviceInfo) -> None:
            nonlocal completed, last_log
            async with semaphore:
                hints = _csc_hints(prev, d.model_code) if prev else None
                try:
                    spls = await scraper.fetch_all_spls(d.model_code, default_csc, csc_hints=hints)
                except Exception:
                    spls = {}
                results[d.model_code] = spls
                completed += 1
                now = time.monotonic()
                if now - last_log >= _LOG_INTERVAL or completed == len(to_fetch):
                    logger.info(
                        "[%s] SPL fetch: %d/%d (%d%%)",
                        scraper.name, completed, len(to_fetch),
                        completed * 100 // len(to_fetch),
                    )
                    last_log = now

        await asyncio.gather(*(fetch_one(d) for d in to_fetch))

    found = reused
    for d in devices:
        if d.current_spl is not None:
            continue
        spl_dict = results.get(d.model_code, {})
        d.spl_by_csc = spl_dict
        if spl_dict:
            best_str = spl_dict.get(default_csc) or max(spl_dict.values())
            try:
                d.current_spl = date.fromisoformat(best_str)
                d.spl_inferred = False
                d.spl_inferred_from = None
                found += 1
            except ValueError:
                logger.debug("Invalid SPL date for %s: %s", d.model_code, best_str)

    logger.info("[%s] %d/%d devices have a confirmed SPL", scraper.name, found, total)


async def _infer_spls(scraper, devices: list[DeviceInfo]) -> None:
    confirmed: dict[str, date] = {
        d.model_code: d.current_spl
        for d in devices
        if d.current_spl is not None and not d.spl_inferred
    }
    # Same device name, different regional variant - fallback after Samsung suffix-stripping.
    siblings_by_name: dict[str, list[tuple[str, date]]] = {}
    for d in devices:
        if d.current_spl is not None and not d.spl_inferred:
            siblings_by_name.setdefault(d.name, []).append((d.model_code, d.current_spl))
    for lst in siblings_by_name.values():
        lst.sort(key=lambda t: t[1], reverse=True)

    inferred = 0
    for d in devices:
        if d.current_spl is not None:
            continue
        result = scraper.infer_spl(d.model_code, confirmed, siblings_by_name.get(d.name, []))
        if result is not None:
            d.current_spl, d.spl_inferred_from = result
            d.spl_inferred = True
            inferred += 1

    logger.info("[%s] Inferred SPL for %d devices", scraper.name, inferred)


def _write_output(
    output: Path,
    bulletins: list[SecurityBulletin],
    devices: list[DeviceInfo],
    nvd_map: dict[str, CVEDetail],
    csc_registry: dict[str, CscMeta],
    write_individual: bool = False,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "cves").mkdir(exist_ok=True)

    # Keyed by (cve_id, OEM): earliest bulletin wins; Apple merges fixed_in_versions across OS trains.
    cve_by_oem: dict[tuple[str, str], dict] = {}
    # OEM-agnostic enrichment only; bulletin metadata stays in cve_by_oem / index.json.
    cve_details: dict[str, dict] = {}
    for bulletin in sorted(bulletins, key=lambda b: b.spl_date):
        for cve in bulletin.cves:
            key = (cve.cve_id, bulletin.manufacturer)
            nvd = nvd_map.get(cve.cve_id)
            fix = bulletin.fixed_in_version
            if key in cve_by_oem:
                if fix and bulletin.manufacturer == "apple":
                    versions = cve_by_oem[key].setdefault("fixed_in_versions", [])
                    if fix not in versions:
                        versions.append(fix)
                continue
            # Prefer NVD severity only when it actually resolved; keep bulletin otherwise.
            severity = cve.severity
            description = cve.description
            if nvd:
                if nvd.severity and nvd.severity != "unknown":
                    severity = nvd.severity
                elif severity == "unknown":
                    severity = nvd.severity
                if nvd.description:
                    description = nvd.description
            entry = {
                "cve_id": cve.cve_id,
                "severity": severity,
                "description": description,
                "cvss_score": nvd.cvss_score if nvd else None,
                "cvss_vector": nvd.cvss_vector if nvd else None,
                "bulletin_date": bulletin.spl_date,
                "bulletin_url": bulletin.url,
                "manufacturer": bulletin.manufacturer,
                "source": cve.source,
                "references": nvd.references if nvd else [],
                "nvd_found": nvd.nvd_found if nvd else False,
                "fixed_in_versions": [fix] if fix else [],
            }
            cve_by_oem[key] = entry
            if cve.cve_id not in cve_details:
                cve_details[cve.cve_id] = {
                    "cve_id": cve.cve_id,
                    "severity": severity,
                    "description": description,
                    "cvss_score": nvd.cvss_score if nvd else None,
                    "cvss_vector": nvd.cvss_vector if nvd else None,
                    "references": nvd.references if nvd else [],
                    "nvd_found": nvd.nvd_found if nvd else False,
                }

    devices_index = [_device_to_dict(d, csc_registry) for d in devices]
    cves_index = [
        {
            "cve_id": v["cve_id"],
            "severity": v["severity"],
            "bulletin_date": v["bulletin_date"],
            "manufacturer": v["manufacturer"],
            "source": v.get("source"),
            "fixed_in_versions": v.get("fixed_in_versions") or [],
            "bulletin_url": v.get("bulletin_url") or "",
        }
        for v in cve_by_oem.values()
    ]

    (output / "index.json").write_text(json.dumps({
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "devices": devices_index,
        "cves": cves_index,
    }, ensure_ascii=False), encoding="utf-8")

    by_year: dict[str, dict[str, dict]] = {}
    for cve_id, d in cve_details.items():
        parts = cve_id.split("-")
        year = parts[1] if len(parts) > 1 and parts[1].isdigit() else "unknown"
        by_year.setdefault(year, {})[cve_id] = {
            "cve_id": d["cve_id"],
            "severity": d["severity"],
            "description": d["description"],
            "cvss_score": d["cvss_score"],
            "cvss_vector": d["cvss_vector"],
            "nist_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if d["nvd_found"] else None,
            "cve_org_url": f"https://www.cve.org/CVERecord?id={cve_id}",
            "references": d["references"],
        }

    for year, year_cves in by_year.items():
        (output / "cves" / f"{year}.json").write_text(
            json.dumps(year_cves, ensure_ascii=False), encoding="utf-8"
        )

    if write_individual:
        for cve_id, d in cve_details.items():
            (output / "cves" / f"{cve_id}.json").write_text(json.dumps({
                "cve_id": d["cve_id"],
                "severity": d["severity"],
                "description": d["description"],
                "cvss_score": d["cvss_score"],
                "cvss_vector": d["cvss_vector"],
                "nist_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if d["nvd_found"] else None,
                "cve_org_url": f"https://www.cve.org/CVERecord?id={cve_id}",
                "references": d["references"],
            }, ensure_ascii=False), encoding="utf-8")

    logger.info("Output: %d devices, %d CVEs → %s", len(devices_index), len(cves_index), output)


def _device_to_dict(d: DeviceInfo, csc_registry: dict[str, CscMeta]) -> dict:
    spl_by_csc: dict[str, dict] = {}
    for csc, spl in d.spl_by_csc.items():
        entry: dict = {"spl": spl}
        meta = csc_registry.get(csc)
        if meta:
            entry["country"] = meta.country
            entry["carrier"] = meta.carrier
            entry["region"] = meta.region
            entry["subregion"] = meta.subregion
        spl_by_csc[csc] = entry
    return {
        "name": d.name,
        "model_code": d.model_code,
        "manufacturer": d.manufacturer,
        "device_type": d.device_type,
        "current_spl": d.current_spl.isoformat() if d.current_spl else None,
        "spl_inferred": d.spl_inferred,
        "spl_inferred_from": d.spl_inferred_from,
        "spl_by_csc": spl_by_csc,
        "aer_recommended": d.aer_recommended,
        "security_update_end": _eol_for_json_field(d.security_update_end),
        "os_update_end": _eol_for_json_field(d.os_update_end),
        "knox_vault": d.knox_vault,
        "spl_frequency": d.spl_frequency,
        "os_version": d.os_version,
        "os_versions": list(d.os_versions),
    }


def _load_previous(output: Path) -> _PreviousState | None:
    index_path = output / "index.json"
    if not index_path.is_file():
        return None
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Could not read previous index.json: %s", exc)
        return None
    devices = index.get("devices")
    cves_index = index.get("cves")
    if not isinstance(devices, list) or not isinstance(cves_index, list):
        return None

    cve_details: dict[str, dict] = {}
    cves_dir = output / "cves"
    if cves_dir.is_dir():
        for path in cves_dir.glob("*.json"):
            if len(path.stem) != 4 or not path.stem.isdigit():
                continue
            try:
                cve_details.update(json.loads(path.read_text(encoding="utf-8")))
            except Exception as exc:
                logger.warning("Could not read %s: %s", path, exc)

    return _PreviousState(
        devices_by_model={d["model_code"]: d for d in devices if d.get("model_code")},
        cve_details=cve_details,
        cves_index=cves_index,
    )


def _stored_to_nvd_map(stored: dict[str, dict]) -> dict[str, CVEDetail]:
    result: dict[str, CVEDetail] = {}
    for cve_id, d in stored.items():
        result[cve_id] = CVEDetail(
            severity=d.get("severity", "unknown"),
            description=d.get("description", ""),
            cvss_score=d.get("cvss_score"),
            cvss_vector=d.get("cvss_vector"),
            references=d.get("references") or [],
            nvd_found=bool(d.get("nist_url")),
        )
    return result


def _bulletins_from_previous(
    prev: _PreviousState,
    manufacturer: str,
    exclude_year: int | None = None,
) -> list[SecurityBulletin]:
    exclude_prefix = f"{exclude_year}-" if exclude_year else None
    # Keyed by (bulletin_date, fixed_in_version) so Apple OS trains stay distinct.
    by_key: dict[tuple[str, str | None], list[CVEInfo]] = {}
    url_by_key: dict[tuple[str, str | None], str] = {}
    for entry in prev.cves_index:
        if (entry.get("manufacturer") or "").lower() != manufacturer.lower():
            continue
        bulletin_date = entry.get("bulletin_date")
        cve_id = entry.get("cve_id")
        if not bulletin_date or not cve_id:
            continue
        if exclude_prefix and str(bulletin_date).startswith(exclude_prefix):
            continue
        detail = prev.cve_details.get(cve_id, {})
        fixes = entry.get("fixed_in_versions") or [None]
        info = CVEInfo(
            cve_id=cve_id,
            severity=entry.get("severity") or detail.get("severity", "unknown"),
            description=detail.get("description", ""),
            source=entry.get("source") or detail.get("source"),
        )
        url = (entry.get("bulletin_url") or detail.get("bulletin_url") or "").strip()
        for fix in fixes:
            key = (str(bulletin_date), fix)
            bucket = by_key.setdefault(key, [])
            if any(c.cve_id == cve_id for c in bucket):
                continue
            bucket.append(info)
            if url and not url_by_key.get(key):
                url_by_key[key] = url
    return [
        SecurityBulletin(
            spl_date=d,
            manufacturer=manufacturer,
            url=url_by_key.get((d, fix), ""),
            cves=cves,
            fixed_in_version=fix,
        )
        for (d, fix), cves in sorted(by_key.items(), key=lambda t: (t[0][0], t[0][1] or ""))
        if cves
    ]


def _merge_bulletins(
    historical: list[SecurityBulletin], fresh: list[SecurityBulletin]
) -> list[SecurityBulletin]:
    by_key = {(b.spl_date, b.fixed_in_version): b for b in historical}
    for b in fresh:
        by_key[(b.spl_date, b.fixed_in_version)] = b
    return [by_key[k] for k in sorted(by_key, key=lambda t: (t[0], t[1] or ""))]


def _reuse_spl(device: DeviceInfo, prev_d: dict) -> bool:
    if prev_d.get("spl_inferred"):
        return False
    spl_str = prev_d.get("current_spl")
    if not spl_str:
        return False
    try:
        spl = date.fromisoformat(spl_str)
    except ValueError:
        return False
    if (date.today() - spl).days > _SPL_STALE_DAYS:
        return False
    spl_by_csc = prev_d.get("spl_by_csc") or {}
    device.spl_by_csc = {
        csc: meta["spl"] for csc, meta in spl_by_csc.items() if meta.get("spl")
    }
    device.current_spl = spl
    device.spl_inferred = False
    device.spl_inferred_from = prev_d.get("spl_inferred_from")
    return True


def _csc_hints(prev: _PreviousState | None, model_code: str) -> list[str] | None:
    if not prev:
        return None
    prev_d = prev.devices_by_model.get(model_code)
    if not prev_d:
        return None
    hints = [csc for csc in (prev_d.get("spl_by_csc") or {}) if csc]
    return hints or None

