"""
Layer 3 of the hybrid detection system - Lookalike & Homograph Detection.

Execution Order (Stops at first match):
1. Method C: Homograph Attack (Punycode / Unicode visual spoofing)
2. Method A: TLD Swap & Subdomain Impersonation
3. Method D: Fake ccTLD / Multi-Part-TLD Impersonation
4. Method B: Levenshtein Typosquatting & L33tspeak Substitutions
"""

import unicodedata
from urllib.parse import urlparse
import domain_lists.whitelist as _whitelist


# Cyrillic characters visually identical to Latin
CYRILLIC_TO_LATIN = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
}

# Digit substitutions used by Method B for typosquatting
DIGIT_TO_LETTER = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
}

_EXTRA_CCTLDS = {
    "au", "uk", "lk", "nz", "us", "ca", "in", "za",
    "sg", "ie", "de", "fr", "jp", "cn", "br", "ru",
    "kr", "my", "ph", "pk", "bd", "np", "ae",
}

_GENERIC_TLDS = {"com", "net", "org", "info", "biz", "co"}

_SENSITIVE_KEYWORDS = {
    "finance", "financial", "bank", "banking", "gov", "government",
    "tax", "treasury", "customs", "ministry", "embassy", "passport",
    "visa", "immigration", "trade", "export", "import", "revenue",
    "authority", "agency", "department", "national", "federal",
    "secure", "verify", "account", "login", "portal", "payment",
}

_GENERIC_SUBDOMAINS = {
    "www", "mail", "email", "ftp", "cdn", "api",
    "app", "web", "blog", "m", "en", "static",
    "media", "images", "shop", "edu", "gov",
    "support", "help", "news", "portal", "admin",
}


def _known_cctlds_priority() -> list[str]:
    """Ordered list of known country codes for Method D to ensure deterministic execution."""
    priority = {tld.split(".")[-1] for tld in _whitelist.MULTI_PART_TLDS}
    rest = _EXTRA_CCTLDS - priority
    return sorted(priority) + sorted(rest)


def _contains_sensitive_keyword(hostname: str) -> bool:
    """True if any label in the hostname contains an institutional/finance/gov keyword."""
    hostname = hostname.lower()
    return any(kw in hostname for kw in _SENSITIVE_KEYWORDS)


def _extract_brand(hostname: str) -> str:
    """Extract brand name from a full hostname by stripping subdomains and TLD."""
    hostname = hostname.lower().strip().rstrip(".")
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    candidate_suffix = ".".join(parts[-2:])
    if len(parts) >= 3 and candidate_suffix in _whitelist.MULTI_PART_TLDS:
        return parts[-3]

    return parts[-2]


def _clean_hostname(url: str) -> str | None:
    """Parse URL and return a clean lowercase hostname."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip().rstrip(".")
        return hostname if hostname else None
    except Exception:
        return None


def _decode_punycode_label(label: str) -> str:
    """Decode a single punycode label (xn--...) to Unicode."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label[4:].encode("ascii").decode("punycode")
    except Exception:
        return label


def _normalise_homograph(name: str) -> str:
    """Expose hidden Unicode character substitutions in a domain name."""
    decomposed = unicodedata.normalize("NFKD", name)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    latin = "".join(CYRILLIC_TO_LATIN.get(c, c) for c in stripped)
    return latin.lower()


def _normalise_digits(name: str) -> str:
    """Map digit-to-letter substitutions for typosquatting checks."""
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
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])

            if curr[j] < row_min:
                row_min = curr[j]

        if row_min > max_dist:
            return max_dist + 1

        prev = curr

    return prev[n]


def _max_allowed_distance(name_len: int) -> int:
    """Short strings (<=5 chars) only allow edit distance 1 to prevent false positives."""
    if name_len <= 5:
        return 1
    return 2


def _check_homograph(hostname: str) -> dict | None:
    """Method C - Detect Unicode homograph / Cyrillic substitution attacks across all labels."""
    labels = hostname.split(".")

    for raw_label in labels:
        decoded_label = _decode_punycode_label(raw_label)
        if decoded_label.isascii():
            continue

        normalised = _normalise_homograph(decoded_label)
        if decoded_label == normalised:
            continue

        if normalised in _whitelist.WHITELIST_NAMES:
            return {
                "verdict": "phishing",
                "is_phishing": True,
                "confidence": 0.95,
                "detection_layer": "lookalike_homograph",
                "explanation": (
                    f"'{hostname}' uses Unicode character substitution "
                    f"to visually impersonate trusted brand '{normalised}'."
                ),
                "domain": hostname,
            }
    return None


def _check_tld_swap(hostname: str, brand: str) -> dict | None:
    """Method A - Detect TLD swap and subdomain impersonation."""
    parts = hostname.split(".")
    
    # Calculate registrable domain to prevent flagging whitelisted parent domains
    registrable = ".".join(parts[-3:]) if ".".join(parts[-2:]) in _whitelist.MULTI_PART_TLDS else ".".join(parts[-2:])

    # Exact brand under a non-whitelisted TLD
    if brand in _whitelist.WHITELIST_NAMES and registrable not in _whitelist.WHITELIST:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 0.92,
            "detection_layer": "lookalike_exact_lookalike",
            "explanation": (
                f"'{hostname}' uses the exact brand name '{brand}' "
                f"of a trusted domain under an unverified TLD."
            ),
            "domain": hostname,
        }

    # Subdomain impersonation check
    if len(parts) > 2 and registrable not in _whitelist.WHITELIST:
        subdomains = parts[:-2] if ".".join(parts[-2:]) not in _whitelist.MULTI_PART_TLDS else parts[:-3]
        for sub in subdomains:
            if sub in _GENERIC_SUBDOMAINS:
                continue
            if sub in _whitelist.WHITELIST_NAMES:
                return {
                    "verdict": "phishing",
                    "is_phishing": True,
                    "confidence": 0.92,
                    "detection_layer": "lookalike_exact_lookalike",
                    "explanation": (
                        f"'{hostname}' places trusted brand '{sub}' "
                        f"as a subdomain of untrusted domain '{registrable}'."
                    ),
                    "domain": hostname,
                }

    return None


def _check_cctld_impersonation(hostname: str) -> dict | None:
    """Method D - Detect fake-ccTLD impersonation of government/multi-part domains."""
    parts = hostname.split(".")
    if len(parts) < 3:
        return None

    tld = parts[-1]
    sld = parts[-2]

    if tld not in _GENERIC_TLDS or ".".join(parts[-2:]) in _whitelist.MULTI_PART_TLDS:
        return None

    if len(sld) not in (2, 3):
        return None

    known = _known_cctlds_priority()
    matched_cc = None
    dist = 999

    if sld in known:
        dist = 0
        matched_cc = sld
    else:
        for cc in known:
            d = _levenshtein(sld, cc, max_dist=1)
            if d < dist:
                dist = d
                matched_cc = cc
                if dist == 0:
                    break

    if dist > 1 or matched_cc is None:
        return None

    prefix = ".".join(parts[:-2])
    if not _contains_sensitive_keyword(prefix):
        return None

    confidence = 0.92 if dist == 0 else 0.90

    return {
        "verdict": "phishing",
        "is_phishing": True,
        "confidence": confidence,
        "detection_layer": "lookalike_cctld_impersonation",
        "explanation": (
            f"'{hostname}' places an institutional keyword in front of '{sld}.{tld}', "
            f"where '{sld}' mimics the country code '.{matched_cc}' "
            f"commonly used in government TLDs (e.g., '.gov.{matched_cc}')."
        ),
        "domain": hostname,
    }


def _check_typosquatting(hostname: str, brand: str) -> dict | None:
    """Method B - Detect Levenshtein distance typosquatting and l33tspeak."""
    compare_brand = _normalise_digits(brand)
    digit_substituted = (compare_brand != brand)

    best_dist = 999
    best_match = None

    for trusted in _whitelist.WHITELIST_NAMES:
        dist = _levenshtein(compare_brand, trusted, max_dist=2)

        if dist < best_dist:
            best_dist = dist
            best_match = trusted

        if best_dist == 0:
            break

    if best_match is None:
        return None

    allowed = _max_allowed_distance(min(len(compare_brand), len(best_match)))
    if best_dist > allowed:
        return None

    # Handle digit substitutions (e.g., p4ypal -> paypal)
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
                f"'{hostname}' is one edit away from trusted brand '{best_match}'."
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
                f"'{hostname}' is two edits away from trusted brand '{best_match}'."
            ),
            "domain": hostname,
        }

    return None


def check_lookalike(url: str) -> dict | None:
    """Run lookalike detection methods in strict sequence: C -> A -> D -> B."""
    try:
        hostname = _clean_hostname(url)
        if not hostname:
            return None

        brand = _extract_brand(hostname)
        if not brand:
            return None

        result = _check_homograph(hostname)
        if result:
            return result

        result = _check_tld_swap(hostname, brand)
        if result:
            return result

        result = _check_cctld_impersonation(hostname)
        if result:
            return result

        result = _check_typosquatting(hostname, brand)
        if result:
            return result

        return None

    except Exception:
        return None