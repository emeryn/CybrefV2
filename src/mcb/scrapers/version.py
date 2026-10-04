import re

_VERSION_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def version_key(version: str) -> tuple[int, ...]:
    m = _VERSION_RE.match(version.strip())
    if not m:
        return (0,)
    return tuple(int(g) for g in m.groups() if g is not None)


def version_major(version: str) -> int:
    return version_key(version)[0]


def version_sort_desc(versions: list[str]) -> list[str]:
    return sorted(set(versions), key=version_key, reverse=True)
