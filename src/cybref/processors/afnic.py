"""AFNIC .fr open data (the full registered-domain list)."""

from __future__ import annotations

import asyncio
import logging
import zipfile
from contextlib import ExitStack
from pathlib import Path

from ..engine import Context, gzip_open_write
from ..http import NotModified

logger = logging.getLogger("cybref.afnic")


async def domains(ctx: Context) -> None:
    """The monthly .fr archive, re-split by domain initial: <dir>/<a-z|0-9|other>.csv.gz.

    The CSV is 713 MB raw and ~123 MB gzipped as one file, past GitHub's 100 MB limit, so it
    cannot be published whole. Parquet does not rescue it either: 10M unique domain names are
    near-incompressible, and even zstd + delta encoding only reaches ~95 MB, which leaves no
    room for a zone that grows every month. The archive is sorted by domain name, so a split
    by initial is stable month to month and lets consumers load only the bucket they look up.
    Streamed straight out of the zip: the full CSV never lands on disk.
    """
    archive = await _download(ctx)
    subdir = ctx.options["dir"].rstrip("/")
    minimum = ctx.options.get("min_domains", 3_000_000)
    count, buckets = await asyncio.to_thread(_split, archive, ctx.stage / subdir)
    if count < minimum:
        raise ValueError(f"only {count} domains (min {minimum})")
    logger.info("[afnic] %d domains across %d buckets", count, buckets)


async def _download(ctx: Context) -> Path:
    """AFNIC publishes a month's archive during the following month: try each candidate."""
    urls = ctx.source.resolved_urls()
    last_exc: Exception | None = None
    for url in urls:
        try:
            return await ctx.download(url, cache=len(urls) == 1)
        except NotModified:
            raise
        except Exception as exc:  # noqa: BLE001 - fall back to the other month
            last_exc = exc
    assert last_exc is not None
    raise last_exc


def _bucket(line: bytes) -> str:
    """First byte of the domain name; IDN domains start with a multi-byte char -> "other"."""
    initial = line[:1].lower()
    if b"a" <= initial <= b"z":
        return initial.decode()
    return "0-9" if initial.isdigit() else "other"


def _split(archive: Path, target_dir: Path) -> tuple[int, int]:
    with zipfile.ZipFile(archive) as zf:
        members = [n for n in zf.namelist() if n.lower().endswith(".csv")]
        if len(members) != 1:
            raise ValueError(f"expected exactly one CSV in the archive, found {members or 'none'}")
        count = 0
        writers: dict[str, object] = {}
        with zf.open(members[0]) as raw, ExitStack() as stack:
            header = raw.readline()
            if b";" not in header:
                raise ValueError(f"unexpected header: {header[:120]!r}")
            for line in raw:
                if not line.strip():
                    continue
                bucket = _bucket(line)
                if bucket not in writers:
                    fh = stack.enter_context(gzip_open_write(target_dir / f"{bucket}.csv.gz"))
                    fh.write(header)
                    writers[bucket] = fh
                writers[bucket].write(line)
                count += 1
    return count, len(writers)
