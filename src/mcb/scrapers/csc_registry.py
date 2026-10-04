import csv
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Bundled with the package (src/mcb/csc/), not fetched.
_DEFAULT_CSV = os.path.join(os.path.dirname(__file__), "..", "csc", "samsung-csc.csv")


@dataclass(frozen=True)
class CscMeta:
    country: str
    carrier: str
    iso_code: str
    region: str
    subregion: str


def load_csc_registry(csv_path: str | None = None) -> dict[str, CscMeta]:
    """Load CSC registry; missing file -> {} and callers use heuristics."""
    path = os.path.normpath(csv_path or _DEFAULT_CSV)
    if not os.path.isfile(path):
        logger.warning("Samsung CSC registry not found at %s — using heuristics only", path)
        return {}
    registry: dict[str, CscMeta] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            code = row["CSC"].strip()
            registry[code] = CscMeta(
                country=row["country"].strip(),
                carrier=row["carrier"].strip(),
                iso_code=row["iso_code"].strip(),
                region=row["region"].strip(),
                subregion=row["subregion"].strip(),
            )
    return registry


# Suffix/prefix -> (region, iso_filter). iso_filter needed when region="Asia"
# would mix Korea/Japan CSCs with South-East Asia.
_SUFFIX2_REGION: dict[str, tuple[str, str | None]] = {
    "B2": ("Europe", None),
    "BE": ("Europe", None),
    "N2": ("Asia", "KOR"),
    "U1": ("Americas", None),
    "V2": ("Americas", None),
}

_SUFFIX1_REGION: dict[str, tuple[str, str | None]] = {
    "B": ("Europe", None),
    "F": ("Europe", None),
    "Z": ("Europe", None),
    "N": ("Asia", "KOR"),
    "U": ("Americas", None),
    "V": ("Americas", None),
    "A": ("Americas", None),
    "T": ("Americas", None),
    "W": ("Americas", None),   # Canada
}

_PREFIX_REGION: dict[str, tuple[str, str]] = {
    "SC-": ("Asia", "JPN"),
    "SCG": ("Asia", "JPN"),
    "SCV": ("Asia", "JPN"),
}

_FALLBACK_SUFFIX2: dict[str, list[str]] = {
    "B2": ["XEF", "BTU"], "BE": ["XEF", "BTU"],
    "N2": ["SKT", "KTC"], "U1": ["XAA"],  "V2": ["VZW", "XAA"],
}
_FALLBACK_SUFFIX1: dict[str, list[str]] = {
    "U": ["XAA"], "V": ["VZW", "XAA"], "A": ["ATT", "XAA"],
    "T": ["TMB", "XAA"], "B": ["BTU", "XEF"], "F": ["XEF", "BTU"],
    "N": ["SKT", "KTC"], "Z": ["DBT", "XEF"], "W": ["BCE"],
}
_FALLBACK_PREFIX: dict[str, list[str]] = {
    "SC-": ["DCM"], "SCG": ["KDI"], "SCV": ["KDI"],
}


def _infer_region(model_code: str) -> tuple[str, str | None] | None:
    for prefix, region_info in _PREFIX_REGION.items():
        if model_code.startswith(prefix):
            return region_info
    suffix2 = model_code[-2:].upper() if len(model_code) >= 2 else ""
    if suffix2 in _SUFFIX2_REGION:
        return _SUFFIX2_REGION[suffix2]
    suffix1 = model_code[-1:].upper() if model_code else ""
    if suffix1 in _SUFFIX1_REGION:
        return _SUFFIX1_REGION[suffix1]
    return None


def candidate_cscs(
    model_code: str,
    default_csc: str | None = None,
    registry: dict[str, CscMeta] | None = None,
) -> list[str]:
    """CSCs to try for *model_code*: default first, then region match, OXM last."""
    result: list[str] = []

    region_info = _infer_region(model_code)

    if registry and region_info:
        region, iso_filter = region_info
        for code, meta in registry.items():
            if meta.region != region:
                continue
            if iso_filter and meta.iso_code != iso_filter:
                continue
            result.append(code)
    else:
        for prefix, cscs in _FALLBACK_PREFIX.items():
            if model_code.startswith(prefix):
                result.extend(cscs)
                break
        else:
            suffix2 = model_code[-2:].upper() if len(model_code) >= 2 else ""
            suffix1 = model_code[-1:].upper() if model_code else ""
            if suffix2 in _FALLBACK_SUFFIX2:
                result.extend(_FALLBACK_SUFFIX2[suffix2])
            elif suffix1 in _FALLBACK_SUFFIX1:
                result.extend(_FALLBACK_SUFFIX1[suffix1])

    if "OXM" not in result:
        result.append("OXM")

    if default_csc:
        if default_csc in result:
            result.remove(default_csc)
        result.insert(0, default_csc)

    return result
