"""Source processors. A processor is `async def fn(ctx: Context) -> None` writing into ctx.stage.

Sources without `processor:` in sources.yaml go through `plain_download`.
"""

from __future__ import annotations

import asyncio

from ..engine import Context, gunzip_file, gzip_file, unzip_member
from ..http import NotModified
from . import apis, github, mobile, nvd, registries, scrape


async def plain_download(ctx: Context) -> None:
    src = ctx.source
    urls = src.resolved_urls()
    raw = ctx.work / "download"
    last_exc: Exception | None = None
    for url in urls:
        try:
            # HTTP caching only with a single URL: with fallbacks we can't tell which one won.
            await ctx.download(url, raw, cache=len(urls) == 1)
            break
        except NotModified:
            raise
        except Exception as exc:  # noqa: BLE001 - try the next fallback URL
            last_exc = exc
    else:
        assert last_exc is not None
        raise last_exc

    await asyncio.to_thread(_transform, ctx, raw)


def _transform(ctx: Context, raw) -> None:
    src = ctx.source
    data = raw
    if src.extract == "gunzip":
        data = ctx.work / "extracted"
        gunzip_file(raw, data)
    elif src.extract == "unzip":
        data = ctx.work / "extracted"
        unzip_member(raw, data, src.member)

    if src.encoding:
        recoded = ctx.work / "recoded"
        text = data.read_bytes().decode(src.encoding)
        recoded.write_text(text.lstrip("﻿"), encoding="utf-8", newline="")
        data = recoded

    target = ctx.path(src.output)
    if src.compress:
        gzip_file(data, target)
    else:
        data.replace(target)


PROCESSORS = {
    "html_table": scrape.html_table,
    "malapi": scrape.malapi,
    "usb_ids": registries.usb_ids,
    "github_advisories": github.github_advisories,
    "lottunnels": github.lottunnels,
    "misp_warninglists": github.misp_warninglists,
    "nvd_cve_feeds": nvd.cve_feeds,
    "nvd_cpe_dictionary": nvd.cpe_dictionary,
    "mobile_cve": mobile.mobile_cve,
    "euvd_exploited": apis.euvd_exploited,
    "mitre_atlas": apis.mitre_atlas,
}
