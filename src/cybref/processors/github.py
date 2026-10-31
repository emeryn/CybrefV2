"""Datasets assembled from GitHub repositories."""

from __future__ import annotations

import asyncio
import fnmatch
import json
import zipfile
from pathlib import Path

import yaml

from ..engine import Context, gzip_open_write


async def _run(*cmd: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await proc.communicate()
    if proc.returncode:
        raise RuntimeError(f"{' '.join(cmd[:3])}... exited {proc.returncode}: {out.decode(errors='replace')[-300:]}")


def _zip_url(repo: str, branch: str) -> str:
    return f"https://codeload.github.com/{repo}/zip/refs/heads/{branch}"


# --------------------------------------------------------------------------- GHSA


async def github_advisories(ctx: Context) -> None:
    """Reviewed GitHub advisories (OSV format), merged into one gzipped JSON array.

    Sparse blobless clone: only advisories/github-reviewed is downloaded.
    """
    repo = ctx.work / "advisory-database"
    subdir = ctx.options.get("path", "advisories/github-reviewed")
    await _run("git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse",
               "https://github.com/github/advisory-database.git", str(repo))
    await _run("git", "-C", str(repo), "sparse-checkout", "set", subdir)
    count = await asyncio.to_thread(_merge_json_tree, repo / subdir, ctx.path(ctx.source.output))
    if count < 10000:
        raise ValueError(f"only {count} advisories merged")


def _merge_json_tree(root: Path, target: Path) -> int:
    files = sorted(root.rglob("*.json"))
    count = 0
    with gzip_open_write(target) as out:
        out.write(b"[")
        for path in files:
            try:
                doc = json.loads(path.read_bytes())
            except ValueError:
                continue
            out.write((b"," if count else b"") + json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode())
            count += 1
        out.write(b"]")
    return count


# --------------------------------------------------------------------------- LoTtunnels


async def lottunnels(ctx: Context) -> None:
    """LoTtunnels binaries: YAML front matter of each page -> JSON list."""
    archive = await ctx.download(_zip_url("LoTtunnels/LoTtunnels.github.io", "main"), cache=True)
    entries = await asyncio.to_thread(_parse_lottunnels, archive)
    if not entries:
        raise ValueError("no binaries found in archive")
    ctx.write_json(ctx.source.output, entries, indent=2)


def _parse_lottunnels(archive: Path) -> list[dict]:
    entries = []
    with zipfile.ZipFile(archive) as zf:
        names = sorted(n for n in zf.namelist() if "/_lottunnels/Binaries/" in n and n.endswith(".md"))
        for name in names:
            parts = zf.read(name).decode("utf-8", errors="replace").split("---")
            if len(parts) < 3:
                continue
            entry = yaml.safe_load(parts[1])
            if not isinstance(entry, dict):
                continue
            filename = name.rsplit("/", 1)[-1]
            entry["source_file"] = filename
            entry["url"] = f"https://lottunnels.github.io/lottunnels/{filename.removesuffix('.md')}"
            entries.append(entry)
    return entries


# --------------------------------------------------------------------------- MISP warninglists


async def misp_warninglists(ctx: Context) -> None:
    """MISP warning lists (known-benign / false-positive sets) -> {list_name: list}."""
    archive = await ctx.download(_zip_url("MISP/misp-warninglists", "main"), cache=True)
    lists = await asyncio.to_thread(_parse_misp, archive, ctx.options.get("exclude", []))
    if len(lists) < 50:
        raise ValueError(f"only {len(lists)} warning lists found")
    ctx.write_json(ctx.source.output, lists)


def _parse_misp(archive: Path, exclude: list[str]) -> dict:
    lists = {}
    with zipfile.ZipFile(archive) as zf:
        for name in sorted(zf.namelist()):
            parts = name.split("/")
            if len(parts) == 4 and parts[1] == "lists" and parts[3] == "list.json":
                if any(fnmatch.fnmatch(parts[2], pat) for pat in exclude):
                    continue
                try:
                    lists[parts[2]] = json.loads(zf.read(name))
                except ValueError:
                    continue
    return lists
