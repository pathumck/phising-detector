import unicodedata
from urllib.parse import urlparse
import domain_lists.whitelist as _whitelist


# Cyrillic characters visually identical to Latin
CYRILLIC_TO_LATIN = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
}

# Digit substitutions used by Method B for typosquatting
DIGIT_TO_LETTER = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
}


def _extract_brand(hostname: str) -> str:
    """Extract brand name from a full hostname by removing subdomains and TLD."""
    hostname = hostname.lower().strip()
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    if len(parts) >= 3 and \
            ".".join(parts[-2:]) in _whitelist.MULTI_PART_TLDS:
        return parts[-3]

    return parts[-2]


def _clean_hostname(url: str) -> str | None:
    """Parse URL and return a clean lowercase hostname."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        return hostname if hostname else None

    except Exception:
        return None


def _normalise_homograph(name: str) -> str:
    """Expose hidden Unicode character substitutions in a domain name."""
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(
        c for c in decomposed
        if not unicodedata.combining(c)
    )
    latin = "".join(
        CYRILLIC_TO_LATIN.get(c, c) for c in stripped
    )
    return latin.lower()


def _normalise_digits(name: str) -> str:
    """Map digit to letter substitutions for typosquatting checks."""
    return "".join(DIGIT_TO_LETTER.get(c, c) for c in name.lower())