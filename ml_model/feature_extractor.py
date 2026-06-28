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
