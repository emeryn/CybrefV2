"""OSV.dev per-ecosystem advisory archives."""

from __future__ import annotations

import asyncio
import json
import zipfile
from pathlib import Path

from ..engine import Context, gzip_open_write


async def advisories_zip(ctx: Context) -> None:
    """OSV `all.zip`: one JSON file per advisory, merged into a single gzipped array."""
    archive = await ctx.download(ctx.source.resolved_urls()[0], cache=True)
    minimum = ctx.options.get("min_advisories", 1000)
    count = await asyncio.to_thread(_merge_zip, archive, ctx.path(ctx.source.output))
    if count < minimum:
        raise ValueError(f"only {count} advisories merged (min {minimum})")


def _merge_zip(archive: Path, target: Path) -> int:
    count = 0
    with zipfile.ZipFile(archive) as zf, gzip_open_write(target) as out:
        out.write(b"[")
        for name in sorted(zf.namelist()):
            if not name.endswith(".json"):
                continue
            try:
                doc = json.loads(zf.read(name))
            except ValueError:
                continue
            out.write((b"," if count else b"") + json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode())
            count += 1
        out.write(b"]")
    return count
