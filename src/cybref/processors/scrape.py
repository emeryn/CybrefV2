"""HTML scrapers for sites that only publish their data as web pages."""

from __future__ import annotations

import csv
import io

from bs4 import BeautifulSoup

from ..engine import Context
from ..http import get_bytes


async def _soup(ctx: Context, url: str) -> BeautifulSoup:
    body = await get_bytes(ctx.client, url, headers=ctx.source.resolved_headers())
    return BeautifulSoup(body, "lxml")


def _write_csv(ctx: Context, header: list[str], rows: list[list[str]]) -> None:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    ctx.path(ctx.source.output).write_text(buf.getvalue(), encoding="utf-8")


async def html_table(ctx: Context) -> None:
    """First <table> (or options.selector) of the page -> CSV."""
    soup = await _soup(ctx, ctx.source.urls[0])
    table = soup.select_one(ctx.options.get("selector", "table"))
    if table is None:
        raise ValueError("table not found (site layout changed?)")
    trs = table.find_all("tr")
    header = [c.get_text(" ", strip=True) for c in trs[0].find_all(["th", "td"])] if trs else []
    header = header or ctx.options.get("header", [])
    rows = []
    for tr in trs[1:]:
        cells = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
        if any(cells):
            rows.append(cells)
    if not rows:
        raise ValueError("table has no data rows")
    _write_csv(ctx, header, rows)


async def malapi(ctx: Context) -> None:
    """malapi.io: one column per category, each cell a list of API links."""
    soup = await _soup(ctx, ctx.source.urls[0])
    table = soup.find("table", id="main-table")
    if table is None:
        raise ValueError("table#main-table not found (site layout changed?)")
    categories = [t for th in table.find_all("th") if (t := th.get_text(strip=True))]
    columns = []
    for tr in table.find_all("tr"):
        tds = tr.find_all("td", recursive=False)
        if tds:
            columns = tds
            break
    rows = []
    for idx, col in enumerate(columns):
        category = categories[idx] if idx < len(categories) else "Unknown"
        for link in col.find_all("a"):
            api = link.get_text(strip=True)
            href = link.get("href") or ""
            if api:
                url = f"https://malapi.io{href}" if href.startswith("/") else href
                rows.append([api, category, url])
    if not rows:
        raise ValueError("no API found")
    rows.sort()
    _write_csv(ctx, ["API", "Category", "Description_URL"], rows)
