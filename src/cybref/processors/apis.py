"""Paginated JSON APIs."""

from __future__ import annotations

import json

import yaml

from ..engine import Context
from ..http import get_text

_EUVD_SEARCH = "https://euvdservices.enisa.europa.eu/api/search"


async def euvd_exploited(ctx: Context) -> None:
    """ENISA EUVD: every vulnerability flagged as exploited (API pages are capped at 100)."""
    items: dict[str, dict] = {}
    total = None
    page = 0
    while total is None or len(items) < total:
        data = json.loads(await get_text(
            ctx.client, _EUVD_SEARCH, params={"exploited": "true", "size": 100, "page": page},
        ))
        batch = data.get("items") or []
        total = data.get("total", 0)
        if not batch:
            break
        items.update((i["id"], i) for i in batch if i.get("id"))
        page += 1
        if page > 500:
            raise RuntimeError("EUVD pagination did not converge")
    if total and len(items) < total * 0.95:
        raise ValueError(f"EUVD: got {len(items)} of {total} exploited entries")
    ctx.write_json(ctx.source.output, [items[k] for k in sorted(items)], indent=1)


_ATLAS_DIST = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist"


async def mitre_atlas(ctx: Context) -> None:
    """MITRE ATLAS: the *-latest.yaml files are git symlinks (served as a one-line path),
    so resolve the current release from dist/manifest.yaml."""
    manifest = yaml.safe_load(await get_text(ctx.client, f"{_ATLAS_DIST}/manifest.yaml"))
    releases = sorted(manifest, key=lambda r: str(r.get("release-date", "")), reverse=True)
    path = releases[0]["versions"][-1]["path"]
    await ctx.download(f"{_ATLAS_DIST}/{path}", ctx.path(ctx.source.output), cache=True)
