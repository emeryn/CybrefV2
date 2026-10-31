from .base import ManufacturerScraper
from .apple import AppleScraper
from .google import GoogleScraper
from .samsung import SamsungScraper

SCRAPERS: dict[str, type[ManufacturerScraper]] = {
    "samsung": SamsungScraper,
    "google": GoogleScraper,
    "apple": AppleScraper,
}
