"""
Extracts 30 lexical URL features for phishing detection.

Feature groups:
  Group 1 — Length features       (4 features)
  Group 2 — Count features        (12 features)
  Group 3 — Binary flag features  (6 features)
  Group 4 — Keyword features      (2 features)
  Group 5 — Structural features   (6 features)
  TOTAL: 30 features
"""

import math
import re
from urllib.parse import urlparse

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "tiny.cc", "is.gd", "buff.ly", "rebrand.ly"
}

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".link", ".online"
}

LOW_RISK_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov",
    ".co.uk", ".ac.uk", ".gov.uk", ".gov.au"
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "account", "secure",
    "update", "banking", "confirm", "password", "credential",
    "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "bank", "free", "lucky", "bonus",
    "winner", "click", "submit", "access", "webscr"
}

# Pre-compiled regex patterns
_IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_PORT_PATTERN = re.compile(r":\d+")

# Multi-part TLD suffixes for fallback parsing without external libs
_MULTI_PART_TLDS = (".co.uk", ".ac.uk", ".gov.uk", ".gov.au", ".com.au", ".co.jp", ".ac.lk")


# FEATURE HELPERS

def _get_clean_netloc(parsed) -> str:
    """Helper to extract domain without port or user info."""
    netloc = parsed.netloc.lower()
    if "@" in netloc:
        netloc = netloc.split("@")[-1]
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return netloc


def _extract_domain_parts(netloc: str):
    """Splits netloc into (subdomains, brand_name, tld)."""
    for m_tld in _MULTI_PART_TLDS:
        if netloc.endswith(m_tld):
            base = netloc[:-len(m_tld)]
            parts = [p for p in base.split(".") if p]
            if parts:
                return parts[:-1], parts[-1], m_tld
            return [], base, m_tld

    parts = netloc.split(".")
    if len(parts) >= 2:
        return parts[:-2], parts[-2], "." + parts[-1]
    return [], netloc, ""


# Group 1 - Length Features
def get_url_length(url: str) -> int:
    return len(url)

def get_domain_length(parsed) -> int:
    return len(_get_clean_netloc(parsed))

def get_path_length(parsed) -> int:
    return len(parsed.path)

def get_query_length(parsed) -> int:
    return len(parsed.query)


# Group 2 - Count Features
def get_num_dots(url: str) -> int: return url.count(".")
def get_num_dashes(url: str) -> int: return url.count("-")
def get_num_underscores(url: str) -> int: return url.count("_")
def get_num_slashes(url: str) -> int: return url.count("/")
def get_num_question_marks(url: str) -> int: return url.count("?")
def get_num_equals(url: str) -> int: return url.count("=")
def get_num_at_symbols(url: str) -> int: return url.count("@")
def get_num_ampersands(url: str) -> int: return url.count("&")
def get_num_exclamation(url: str) -> int: return url.count("!")
def get_num_percent(url: str) -> int: return url.count("%")

def get_num_digits_in_domain(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    return sum(1 for c in netloc if c.isdigit())

def get_num_subdomains(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    subdomains, _, _ = _extract_domain_parts(netloc)
    return len(subdomains)


# Group 3 - Binary Flag Features
def has_https(parsed) -> int:
    return 1 if parsed.scheme == "https" else 0

def has_ip_address(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    return 1 if _IP_PATTERN.match(netloc) else 0

def has_at_symbol(url: str) -> int:
    return 1 if "@" in url else 0

def has_double_slash(parsed) -> int:
    return 1 if "//" in parsed.path else 0

def has_port(parsed) -> int:
    return 1 if _PORT_PATTERN.search(parsed.netloc) else 0

def has_prefix_suffix(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    return 1 if "-" in netloc else 0


# Group 4 - Keyword Features
def get_has_suspicious_words(url: str) -> int:
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0

def get_num_suspicious_words(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


# Group 5 - Structural Features
def is_shortened_url(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    _, brand, tld = _extract_domain_parts(netloc)
    registrable = f"{brand}{tld}"
    return 1 if registrable in SHORTENER_DOMAINS or netloc in SHORTENER_DOMAINS else 0

def get_tld_risk_score(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    for tld in HIGH_RISK_TLDS:
        if netloc.endswith(tld):
            return 2
    for tld in LOW_RISK_TLDS:
        if netloc.endswith(tld):
            return 0
    return 1

def get_digit_to_letter_ratio(url: str) -> float:
    digits = sum(1 for c in url if c.isdigit())
    letters = sum(1 for c in url if c.isalpha())
    return round(digits / letters, 6) if letters > 0 else 0.0

def get_url_entropy(url: str) -> float:
    if not url:
        return 0.0
    length = len(url)
    freq = {}
    for char in url:
        freq[char] = freq.get(char, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 6)

def get_consonant_ratio(parsed) -> float:
    netloc = _get_clean_netloc(parsed)
    _, brand_name, _ = _extract_domain_parts(netloc)
    vowels = set("aeiou")
    letters = [c for c in brand_name if c.isalpha()]
    if not letters:
        return 0.0
    consonants = [c for c in letters if c not in vowels]
    return round(len(consonants) / len(letters), 6)

def get_brand_name_length(parsed) -> int:
    netloc = _get_clean_netloc(parsed)
    _, brand_name, _ = _extract_domain_parts(netloc)
    return len(brand_name)



# MASTER EXTRACTION PIPELINE

FEATURE_NAMES = [
    # Group 1 — Length (4)
    "url_length", "domain_length", "path_length", "query_length",
    # Group 2 — Counts (12)
    "num_dots", "num_dashes", "num_underscores", "num_slashes",
    "num_question_marks", "num_equals", "num_at_symbols", "num_ampersands",
    "num_exclamation", "num_percent", "num_digits_in_domain", "num_subdomains",
    # Group 3 — Binary flags (6)
    "has_https", "has_ip_address", "has_at_symbol", "has_double_slash",
    "has_port", "has_prefix_suffix",
    # Group 4 — Keywords (2)
    "has_suspicious_words", "num_suspicious_words",
    # Group 5 — Structural (6)
    "is_shortened_url", "tld_risk_score", "digit_to_letter_ratio",
    "url_entropy", "consonant_ratio", "brand_name_length"
]

def extract_features(url: str) -> list:
    """Extracts all 30 numeric lexical features from a URL string."""
    url = str(url).strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    _temp = urlparse(url)
    if not _temp.path:
        url = url + "/"

    parsed = urlparse(url)

    return [
        # Group 1
        get_url_length(url),
        get_domain_length(parsed),
        get_path_length(parsed),
        get_query_length(parsed),
        # Group 2
        get_num_dots(url),
        get_num_dashes(url),
        get_num_underscores(url),
        get_num_slashes(url),
        get_num_question_marks(url),
        get_num_equals(url),
        get_num_at_symbols(url),
        get_num_ampersands(url),
        get_num_exclamation(url),
        get_num_percent(url),
        get_num_digits_in_domain(parsed),
        get_num_subdomains(parsed),
        # Group 3
        has_https(parsed),
        has_ip_address(parsed),
        has_at_symbol(url),
        has_double_slash(parsed),
        has_port(parsed),
        has_prefix_suffix(parsed),
        # Group 4
        get_has_suspicious_words(url),
        get_num_suspicious_words(url),
        # Group 5
        is_shortened_url(parsed),
        get_tld_risk_score(parsed),
        get_digit_to_letter_ratio(url),
        get_url_entropy(url),
        get_consonant_ratio(parsed),
        get_brand_name_length(parsed)
    ]