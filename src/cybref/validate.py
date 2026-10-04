"""Sanity checks run on every file before it replaces the published copy."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

_FORMATS = {
    "json": "json",
    "geojson": "json",
    "jsonl": "jsonl",
    "ndjson": "jsonl",
    "csv": "table",
    "tsv": "table",
    "xml": "xml",
}
MAX_FILE_BYTES = 95 << 20  # GitHub rejects files > 100 MB
_FULL_JSON_PARSE_LIMIT = 300 << 20  # bytes on disk; above that we only check structure


class ValidationError(ValueError):
    pass


def detect_format(name: str) -> str:
    base = name[:-3] if name.endswith(".gz") else name
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    return _FORMATS.get(ext, "text")


def validate(
    path: Path,
    *,
    min_bytes: int = 20,
    min_lines: int = 1,
    previous_size: int | None = None,
    shrink_guard: float = 0.5,
) -> None:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValidationError(f"{path.name}: {size >> 20} MB exceeds the GitHub limit, set `compress: true`")
    if size < min_bytes:
        raise ValidationError(f"{path.name}: only {size} bytes (min {min_bytes})")
    if previous_size and shrink_guard and size < previous_size * shrink_guard:
        raise ValidationError(
            f"{path.name}: shrank from {previous_size} to {size} bytes "
            f"(guard {shrink_guard:.0%}); use --force if expected"
        )

    gz = path.name.endswith(".gz")
    opener = (lambda: gzip.open(path, "rb")) if gz else (lambda: path.open("rb"))
    fmt = detect_format(path.name)

    with opener() as fh:
        head = fh.read(64 << 10)
    if not head.strip():
        raise ValidationError(f"{path.name}: empty content")
    lowered = head.lstrip()[:200].lower()
    if fmt != "xml" and (lowered.startswith(b"<!doctype html") or lowered.startswith(b"<html")):
        raise ValidationError(f"{path.name}: got an HTML page instead of data")

    if fmt == "json":
        _check_json(path, opener, size, head)
    elif fmt == "jsonl":
        lines = head.splitlines()
        if len(head) == 64 << 10:
            lines = lines[:-1]  # last line may be cut by the read window
        for i, line in enumerate(lines[:50]):
            if line.strip():
                try:
                    json.loads(line)
                except ValueError as exc:
                    raise ValidationError(f"{path.name}: invalid JSON line {i + 1}: {exc}") from exc
    elif fmt == "xml":
        if not lowered.startswith(b"<"):
            raise ValidationError(f"{path.name}: does not look like XML")

    if fmt in ("table", "text", "jsonl") and min_lines > 1:
        lines = _count_lines(opener)
        if lines < min_lines:
            raise ValidationError(f"{path.name}: {lines} lines (min {min_lines})")
    elif gz:
        # Read to the end so gzip verifies its CRC.
        with opener() as fh:
            while fh.read(8 << 20):
                pass


def _check_json(path: Path, opener, size: int, head: bytes) -> None:
    first = head.lstrip()[:1]
    if first not in (b"{", b"["):
        raise ValidationError(f"{path.name}: does not start like JSON")
    if size > _FULL_JSON_PARSE_LIMIT or path.name.endswith(".gz") and size > _FULL_JSON_PARSE_LIMIT // 10:
        return
    try:
        with opener() as fh:
            data = json.load(fh)
    except ValueError as exc:
        raise ValidationError(f"{path.name}: invalid JSON: {exc}") from exc
    if not data:
        raise ValidationError(f"{path.name}: JSON document is empty")


def _count_lines(opener) -> int:
    count = 0
    with opener() as fh:
        while chunk := fh.read(8 << 20):
            count += chunk.count(b"\n")
    return count


def count_records(path: Path) -> int | None:
    """Best-effort record count: lines (minus CSV header) or top-level JSON items."""
    fmt = detect_format(path.name)
    gz = path.name.endswith(".gz")
    opener = (lambda: gzip.open(path, "rb")) if gz else (lambda: path.open("rb"))
    try:
        if fmt == "json":
            if path.stat().st_size > (_FULL_JSON_PARSE_LIMIT // 10 if gz else _FULL_JSON_PARSE_LIMIT):
                return None
            with opener() as fh:
                data = json.load(fh)
            return _json_len(data)
        if fmt == "xml":
            return None
        lines = 0
        with opener() as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith((b"#", b";")):
                    lines += 1
        return max(lines - 1, 0) if fmt == "table" else lines
    except (OSError, ValueError):
        return None


def _json_len(data) -> int | None:
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        # {"vulnerabilities": [...], "meta": ...} -> the dominant list; {id: item} -> its keys.
        longest = max((len(v) for v in data.values() if isinstance(v, list)), default=0)
        return longest if longest > len(data) else len(data)
    return None
