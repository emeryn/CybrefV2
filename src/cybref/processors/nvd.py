"""NIST NVD bulk feeds (CVE JSON 2.0 per year + CPE dictionary)."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import logging
import tarfile
from contextlib import ExitStack
from datetime import date
from pathlib import Path

from ..engine import Context, gzip_open_write
from ..http import get_text

logger = logging.getLogger("cybref.nvd")

_CVE_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
_CPE_BUNDLE = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"


async def cve_feeds(ctx: Context) -> None:
    """Every yearly feed + recent + modified, kept as the original .json.gz.

    NVD publishes a .meta file (sha256 of the JSON) next to each feed: a feed is
    only re-downloaded when its sha256 changed, and the download is verified against it.
    """
    first_year = int(ctx.options.get("first_year", 2002))
    names = [f"nvdcve-2.0-{y}" for y in range(first_year, date.today().year + 1)]
    names += ["nvdcve-2.0-recent", "nvdcve-2.0-modified"]
    known: dict = ctx.state.setdefault("sha256", {})
    folder = ctx.options["dir"].rstrip("/")
    sem = asyncio.Semaphore(3)

    async def one(name: str) -> None:
        async with sem:
            out = f"{folder}/{name}.json.gz"
            sha = None
            try:
                meta = await get_text(ctx.client, f"{_CVE_BASE}/{name}.meta")
                sha = _meta_sha256(meta)
            except Exception as exc:  # noqa: BLE001 - meta is an optimisation only
                logger.warning("[nvd] %s.meta unavailable: %s", name, exc)
            if sha and not ctx.force and known.get(name) == sha and ctx.published(out).is_file():
                return
            target = ctx.work / f"{name}.json.gz"
            await ctx.download(f"{_CVE_BASE}/{name}.json.gz", target)
            if sha:
                actual = await asyncio.to_thread(_gunzip_sha256, target)
                if actual != sha:
                    # NVD regenerates feeds continuously: meta and feed may have raced.
                    sha = _meta_sha256(await get_text(ctx.client, f"{_CVE_BASE}/{name}.meta"))
                    if actual != sha:
                        await ctx.download(f"{_CVE_BASE}/{name}.json.gz", target)
                        if await asyncio.to_thread(_gunzip_sha256, target) != sha:
                            raise ValueError("sha256 mismatch with .meta (corrupted download?)")
                known[name] = sha
            # Staged only once complete and verified (a failed year leaves nothing behind).
            target.replace(ctx.path(out))
            logger.info("[nvd] %s downloaded", out)

    results = await asyncio.gather(*(one(n) for n in names), return_exceptions=True)
    failed = [f"{n}: {r}" for n, r in zip(names, results) if isinstance(r, BaseException)]
    if len(failed) == len(names):
        raise RuntimeError(f"every NVD feed failed, first: {failed[0]}")
    # One flaky year must not block the others: publish what worked, report the rest.
    ctx.errors.extend(failed)


def _meta_sha256(meta: str) -> str | None:
    for line in meta.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "sha256":
            return value.strip().lower()
    return None


def _gunzip_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with gzip.open(path, "rb") as fh:
        while chunk := fh.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


async def cpe_dictionary(ctx: Context) -> None:
    """CPE 2.0 bundle (tar of JSON chunks) re-split by vendor initial: <dir>/<a-z|0-9|other>.json.gz,
    each {"products": [...]}.

    One merged file would exceed GitHub's 100 MB limit (1.8M+ products and growing); a split by
    vendor is stable over time and lets consumers load only what they look up.
    Streams chunk by chunk so memory stays bounded.
    """
    bundle = await ctx.download(_CPE_BUNDLE, cache=True)
    subdir = ctx.options["dir"].rstrip("/")
    count = await asyncio.to_thread(_split_cpe, bundle, ctx.work / "cpe", ctx.stage / subdir)
    if count < 100_000:
        raise ValueError(f"only {count} CPE products found")
    logger.info("[nvd] CPE dictionary: %d products", count)


def _bucket(product: dict) -> str:
    name = product.get("cpe", {}).get("cpeName", "")
    parts = name.split(":")
    initial = parts[3][:1].lower() if len(parts) > 3 else ""
    if initial.isascii() and initial.isalpha():
        return initial
    return "0-9" if initial.isdigit() else "other"


def _split_cpe(bundle: Path, workdir: Path, target_dir: Path) -> int:
    with tarfile.open(bundle, "r:gz") as tar:
        tar.extractall(workdir, filter="data")
    chunks = sorted(workdir.rglob("*.json"))
    count = 0
    with ExitStack() as stack:
        writers: dict[str, tuple] = {}

        def writer(bucket: str):
            if bucket not in writers:
                fh = stack.enter_context(gzip_open_write(target_dir / f"{bucket}.json.gz"))
                fh.write(b'{"products":[')
                stack.callback(fh.write, b"]}")
                writers[bucket] = (fh, [0])
            return writers[bucket]

        for chunk in chunks:
            for product in json.loads(chunk.read_bytes()).get("products", []):
                fh, n = writer(_bucket(product))
                fh.write((b"," if n[0] else b"") + json.dumps(product, separators=(",", ":")).encode())
                n[0] += 1
                count += 1
            chunk.unlink()
    return count
