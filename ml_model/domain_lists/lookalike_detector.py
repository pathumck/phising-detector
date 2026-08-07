
"""
Layer 3 of the hybrid detection system.

Three methods in strict execution order (stops at first match):

Method C — Homograph Attack (FIRST)
Unicode/Cyrillic characters visually identical to Latin.
Fires only when the brand contains non-ASCII characters.

Method A — TLD Swap + Subdomain Impersonation (SECOND)
Exact brand under a different TLD or brand placed as a subdomain.

Method B — Levenshtein Typosquatting (THIRD)
One or two keystrokes from a trusted brand name.
"""

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


def _levenshtein(s1: str, s2: str, max_dist: int = 2) -> int:
    """Calculate Levenshtein edit distance with early termination."""
    if abs(len(s1) - len(s2)) > max_dist:
        return max_dist + 1

    m, n = len(s1), len(s2)
    prev = list(range(n + 1))

    for i in range(1, m + 1):
        curr = [i] + [0] * n
        row_min = i

        for j in range(1, n + 1):
            if s1[i - 1] == s2[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(
                    prev[j],
                    curr[j - 1],
                    prev[j - 1],
                )

            if curr[j] < row_min:
                row_min = curr[j]

        if row_min > max_dist:
            return max_dist + 1

        prev = curr

    return prev[n]


def _check_homograph(hostname: str, brand: str) -> dict | None:
    """Method C — Detect Unicode homograph / Cyrillic substitution attacks."""
    if brand.isascii():
        return None

    normalised = _normalise_homograph(brand)

    if brand == normalised:
        return None

    if normalised in _whitelist.WHITELIST_NAMES:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.95,
            "detection_layer": "lookalike_homograph",
            "explanation": (
                f"'{hostname}' uses Unicode character substitution "
                f"to visually impersonate '{normalised}'."
            ),
            "domain": hostname,
        }
    return None


def _check_tld_swap(hostname: str, brand: str) -> dict | None:
    """Method A — Detect TLD swap and subdomain impersonation."""
    if brand in _whitelist.WHITELIST_NAMES:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.92,
            "detection_layer": "lookalike_exact_lookalike",
            "explanation": (
                f"'{hostname}' uses the exact brand name "
                f"'{brand}' of a trusted domain under a different TLD."
            ),
            "domain": hostname,
        }

    _GENERIC_SUBDOMAINS = {
        "www", "mail", "email", "ftp", "cdn", "api",
        "app", "web", "blog", "m", "en", "static",
        "media", "images", "shop", "edu", "gov",
        "support", "help", "news", "portal", "admin",
    }

    parts = hostname.split(".")
    subdomains = parts[:-2]

    for sub in subdomains:
        if sub in _GENERIC_SUBDOMAINS:
            continue
        if sub in _whitelist.WHITELIST_NAMES:
            actual_domain = ".".join(parts[-2:])
            return {
                "verdict": "phishing",
                "is_phishing": True,
                "confidence": 0.92,
                "detection_layer": "lookalike_exact_lookalike",
                "explanation": (
                    f"'{hostname}' places the trusted brand name "
                    f"'{sub}' as a subdomain of the unrelated "
                    f"domain '{actual_domain}'."
                ),
                "domain": hostname,
            }

    return None


def _check_typosquatting(hostname: str, brand: str) -> dict | None:
    """Method B — Detect Levenshtein distance typosquatting."""
    compare_brand = _normalise_digits(brand)
    digit_substituted = (compare_brand != brand)

    best_dist = 999
    best_match = None

    for trusted in _whitelist.WHITELIST_NAMES:
        dist = _levenshtein(compare_brand, trusted, max_dist=2)

        if dist < best_dist:
            best_dist = dist
            best_match = trusted

        if best_dist <= 1:
            break

    if best_dist == 0 and digit_substituted:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.94,
            "detection_layer": "lookalike_typosquatting",
            "explanation": (
                f"'{hostname}' matches trusted brand '{best_match}' "
                f"via character-substitution typosquatting ('{brand}' -> '{compare_brand}')."
            ),
            "domain": hostname,
        }

    if best_dist == 1:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.92,
            "detection_layer": "lookalike_typosquatting",
            "explanation": (
                f"'{hostname}' is one edit away from "
                f"trusted domain '{best_match}'."
            ),
            "domain": hostname,
        }

    if best_dist == 2:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.75,
            "detection_layer": "lookalike_typosquatting",
            "explanation": (
                f"'{hostname}' is two edits away from "
                f"trusted domain '{best_match}'."
            ),
            "domain": hostname,
        }

    return None


def check_lookalike(url: str) -> dict | None:
    """Run all three lookalike methods in order C -> A -> B."""
    try:
        hostname = _clean_hostname(url)
        if not hostname:
            return None

        brand = _extract_brand(hostname)
        if not brand:
            return None

        result = _check_homograph(hostname, brand)
        if result:
            return result

        result = _check_tld_swap(hostname, brand)
        if result:
            return result

        result = _check_typosquatting(hostname, brand)
        if result:
            return result

        return None

    except Exception:
        return None