"""Parsers for text registries (usb.ids, ...)."""

from __future__ import annotations

import asyncio
import re

from ..engine import Context

_VENDOR = re.compile(r"^([0-9a-fA-F]{4})\s+(.+)$")
_DEVICE = re.compile(r"^\t([0-9a-fA-F]{4})\s+(.+)$")


async def usb_ids(ctx: Context) -> None:
    """usb.ids -> {vendor_id: {name, products: {product_id: name}}}."""
    raw = await ctx.download(ctx.source.urls[0], cache=True)
    data = await asyncio.to_thread(_parse_usb_ids, raw.read_text(encoding="utf-8", errors="replace"))
    if len(data) < 1000:
        raise ValueError(f"only {len(data)} vendors parsed")
    ctx.write_json(ctx.source.output, data, indent=2)


def _parse_usb_ids(text: str) -> dict:
    data: dict[str, dict] = {}
    vendor: dict | None = None
    for line in text.splitlines():
        if not line.strip() or line.startswith("#") or line.startswith("\t\t"):
            continue
        if line.startswith("\t"):
            m = _DEVICE.match(line)
            if m and vendor is not None:
                vendor["products"][m.group(1).lower()] = m.group(2).strip()
            continue
        m = _VENDOR.match(line)
        if m:
            vendor = {"name": m.group(2).strip(), "products": {}}
            data[m.group(1).lower()] = vendor
        else:
            # Trailing sections (device classes, HID usages...) - not vendors.
            vendor = None
    return data
