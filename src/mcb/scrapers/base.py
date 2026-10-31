from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date


@dataclass
class CVEInfo:
    cve_id: str
    severity: str = "unknown"
    description: str = ""
    # Samsung: "android" (AOSP) or "sve" (One UI); None elsewhere / untagged.
    source: str | None = None


@dataclass
class SecurityBulletin:
    spl_date: str
    manufacturer: str
    url: str = ""
    cves: list[CVEInfo] = field(default_factory=list)
    # Apple fix train (e.g. "26.5.2"); None for SPL-based OEMs.
    fixed_in_version: str | None = None


@dataclass
class DeviceInfo:
    name: str
    model_code: str
    manufacturer: str
    device_type: str = "phone"
    current_spl: date | None = None
    spl_inferred: bool = False
    spl_inferred_from: str | None = None
    # FOTA-confirmed SPL per CSC only (not inferred), e.g. {"XEF": "2026-03-01"}.
    spl_by_csc: dict[str, str] = field(default_factory=dict)
    aer_recommended: bool | None = None
    security_update_end: str | None = None
    os_update_end: str | None = None
    knox_vault: bool | None = None
    spl_frequency: str | None = None
    # Apple: latest catalog OS + history for the UI dropdown.
    os_version: str | None = None
    os_versions: list[str] = field(default_factory=list)


class ManufacturerScraper(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def fetch_bulletins(self, from_year: int | None = None) -> list[SecurityBulletin]: ...

    @abstractmethod
    async def fetch_devices(self) -> list[DeviceInfo]: ...

    @abstractmethod
    async def fetch_all_spls(
        self,
        model_code: str,
        default_csc: str,
        csc_hints: list[str] | None = None,
    ) -> dict[str, str]:
        """Return {csc: spl_date} for CSCs that answered; always try *default_csc*."""
        ...

    def infer_spl(
        self,
        model_code: str,
        confirmed: dict[str, date],
        siblings: list[tuple[str, date]],
    ) -> tuple[date, str] | None:
        """Fallback: most recent confirmed sibling sharing the device name."""
        if siblings:
            source_code, spl = siblings[0]
            return spl, source_code
        return None
