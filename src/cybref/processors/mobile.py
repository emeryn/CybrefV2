"""Mobile CVE catalog (Samsung / Pixel / Apple), built by the mcb package."""

from __future__ import annotations

import os
import shutil

from ..engine import Context


async def mobile_cve(ctx: Context) -> None:
    """Run mcb on a copy of the published output (it syncs incrementally from it).

    Needs the NVD feeds (nvd_cve source, options.nvd_dir) for local enrichment.
    --force rebuilds from scratch.
    """
    from mcb.sync import sync

    subdir = ctx.options["dir"].rstrip("/")
    published = ctx.published(subdir)
    staged = ctx.stage / subdir
    if published.is_dir() and not ctx.force:
        shutil.copytree(published, staged)
    staged.mkdir(parents=True, exist_ok=True)

    await sync(
        output=staged,
        nvd_dir=ctx.published(ctx.options["nvd_dir"]),
        default_csc=ctx.options.get("csc", "XEF"),
        concurrency=int(ctx.options.get("concurrency", 20)),
        nvd_api_key=os.environ.get("NVD_API_KEY"),
        full_sync=ctx.force,
    )
