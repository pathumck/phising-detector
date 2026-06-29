"""
Extracts 27 lexical URL features for phishing detection.

Feature groups:
  Group 1 — Length features       (4 features)
  Group 2 — Count features        (12 features)
  Group 3 — Binary flag features  (6 features)
  Group 4 — Keyword features      (2 features)
  Group 5 — Structural features   (3 features)
  TOTAL: 27 features
"""

import re
import math
from urllib.parse import urlparse, parse_qs

# Known URL shortener domains.
# These are suspicious because they hide the real destination.
# A phisher uses bit.ly/abc123 so the victim cannot see the
# real domain before clicking.
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "tiny.cc", "is.gd", "buff.ly", "rebrand.ly"
}

# Top-level domains that are free to register with no identity
# verification - heavily abused by phishers because they cost
# nothing and can be abandoned instantly.
HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".link", ".online"
}

# TLDs considered low risk - established, regulated, costly to
# register, so less frequently abused for phishing.
LOW_RISK_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov",
    ".co.uk", ".ac.uk", ".gov.uk", ".gov.au"
}

# Keywords that appear disproportionately in phishing URLs.
# Phishers embed these to make URLs look like legitimate
# login or account management pages.
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "account", "secure",
    "update", "banking", "confirm", "password", "credential",
    "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "bank", "free", "lucky", "bonus",
    "winner", "click", "submit", "access", "webscr"
}

# ================================================================
# FEATURE GROUP 1 - Length Features
# Why length matters: phishing URLs tend to be much longer than
# legitimate ones. Attackers append subdomains, fake paths, and
# query strings to disguise the real domain.
# Example: http://secure-login.paypal.com.phishing-site.xyz/verify
# ================================================================

def get_url_length(url: str) -> int:
    """Total character count of the full URL string."""
    return len(url)


def get_domain_length(parsed) -> int:
    """
    Character count of the domain (netloc) only.
    parsed.netloc includes the port if present e.g. evil.com:8080
    Strip the port before measuring.
    """
    netloc = parsed.netloc
    # Remove port number if present - evil.com:8080 -> evil.com
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return len(netloc)


def get_path_length(parsed) -> int:
    """Character count of the URL path (everything after the domain)."""
    return len(parsed.path)


def get_query_length(parsed) -> int:
    """
    Character count of the query string.
    For http://site.com/page?id=1&token=abc, this returns len("id=1&token=abc")
    Long query strings often indicate tracking parameters or encoded payloads.
    """
    return len(parsed.query)

# ================================================================
# FEATURE GROUP 2 - Count Features
# Raw character counts capture obfuscation patterns.
# Phishers use extra dots (subdomain stacking), hyphens
# (paypal-secure.com), @ symbols (trick browsers into ignoring
# the left part), and digits mixed into domains.
# ================================================================

def get_num_dots(url: str) -> int:
    return url.count(".")

def get_num_dashes(url: str) -> int:
    return url.count("-")

def get_num_underscores(url: str) -> int:
    return url.count("_")

def get_num_slashes(url: str) -> int:
    # Count ALL slashes including the two in http://
    return url.count("/")

def get_num_question_marks(url: str) -> int:
    return url.count("?")

def get_num_equals(url: str) -> int:
    return url.count("=")

def get_num_at_symbols(url: str) -> int:
    return url.count("@")

def get_num_ampersands(url: str) -> int:
    return url.count("&")

def get_num_exclamation(url: str) -> int:
    return url.count("!")

def get_num_percent(url: str) -> int:
    return url.count("%")

def get_num_digits_in_domain(parsed) -> int:
    """
    Count of digit characters in the domain only (not path/query).
    Legitimate domains rarely mix numbers in: g00gle.com or
    paypa1.com are typosquatting signals. IP-based URLs score
    very high here.
    """
    netloc = parsed.netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return sum(1 for c in netloc if c.isdigit())

def get_num_subdomains(parsed) -> int:
    """
    Number of subdomains = number of domain parts minus 2.
    google.com          -> parts=2, subdomains=0 (normal)
    mail.google.com     -> parts=3, subdomains=1 (normal)
    secure.paypal.login.evil.com -> parts=5, subdomains=3 (suspicious)

    Subtract 2 because every domain has at minimum one name
    part and one TLD: [name].[tld]
    Multi-part TLDs like .co.uk are not perfectly handled here
    but the count is still a useful signal.
    """
    netloc = parsed.netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    parts = netloc.split(".")
    # Clamp to 0 minimum - malformed URLs could produce negative
    return max(0, len(parts) - 2)

# ================================================================
# FEATURE GROUP 3 - Binary Flag Features
# Each returns exactly 0 or 1. These encode specific structural
# properties that are strong individual phishing signals.
# ================================================================

# Pre-compile regex patterns once at module load time.
# Compiling inside the function would re-compile on every URL
# which is ~100x slower over 500,000 URLs.

# Matches a standard IPv4 address pattern in the netloc.
_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


# Matches a non-standard port number in the netloc.
_PORT_PATTERN = re.compile(r":\d+")


def has_https(parsed) -> int:
    """
    1 if the scheme is https, 0 otherwise.
    HTTPS alone does not guarantee safety - phishers can get
    free TLS certificates from Let's Encrypt - but its absence
    is a weak negative signal.
    """
    return 1 if parsed.scheme == "https" else 0


def has_ip_address(parsed) -> int:
    """
    1 if the domain is a raw IP address instead of a hostname.
    Legitimate services never use raw IPs in public URLs.
    Example: http://192.168.1.1/login - clearly suspicious.
    """
    netloc = parsed.netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return 1 if _IP_PATTERN.match(netloc) else 0


def has_at_symbol(url: str) -> int:
    """Binary version of num_at - 1 if any @ exists in the URL."""
    return 1 if "@" in url else 0


def has_double_slash(parsed) -> int:
    """
    1 if a double slash appears in the path (after the scheme).
    The normal // after http: is expected. A second // in the
    path is a redirect obfuscation technique.
    Example: http://legitimate.com//http://evil.com
    """
    return 1 if "//" in parsed.path else 0


def has_port(parsed) -> int:
    """
    1 if a non-standard port appears in the URL.
    Legitimate sites use port 80 (http) or 443 (https) implicitly
    and never show the port number in the URL. Phishing sites
    sometimes run on unusual ports to avoid firewalls.
    Example: http://paypal.com:8080/login
    """
    return 1 if _PORT_PATTERN.search(parsed.netloc) else 0


def has_prefix_suffix(parsed) -> int:
    """
    1 if a hyphen (-) appears in the domain name.
    Phishers use hyphens to create convincing-looking subdomains:
    paypal-secure.com, login-amazon.com, apple-id-verify.com
    Legitimate brands rarely hyphenate their primary domain.
    """
    netloc = parsed.netloc
    if ":" in netloc:
        netloc = netloc.split(":")[0]
    return 1 if "-" in netloc else 0

# ================================================================
# FEATURE GROUP 4 - Keyword Features
# Scanning the full URL string for vocabulary that phishers use
# to mimic legitimate login or account management pages.
# ================================================================

def get_has_suspicious_words(url: str) -> int:
    """1 if any keyword from SUSPICIOUS_KEYWORDS appears in the URL."""
    url_lower = url.lower()
    return 1 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0


def get_num_suspicious_words(url: str) -> int:
    """Count of how many different keywords appear in the URL."""
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)