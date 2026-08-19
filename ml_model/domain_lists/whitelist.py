"""
Layer 2 of the hybrid detection system - Whitelist & Safe TLD Verification.

WHY TOP 300,000:
Covers the vast majority of legitimate internet traffic while excluding
untrusted low-rank domains vulnerable to rank manipulation.

WHY LAYER 2 RUNS AFTER LAYER 1:
A domain could appear in both Tranco AND PhishTank if a popular platform
(e.g., a public cloud storage service) is abused for phishing.
Blacklists (Layer 1) always override popularity ranking.

SUBDOMAIN HANDLING:
Extracts the registrable domain before checking.
mail.google.com -> google.com -> found -> SAFE
Prevents evil-google.com.attacker.com from bypassing checks.
"""

import csv
import os
from urllib.parse import urlparse

# Default to Top 300,000 for high-confidence whitelist matches
WHITELIST_TOP_N = 300_000

# Minimum brand length for Layer 3 lookalike anchor extraction
MIN_BRAND_NAME_LENGTH = 4

_HERE = os.path.dirname(os.path.abspath(__file__))
_CSV_PATH = os.path.join(_HERE, "tranco_top1m.csv")

# Full registrable domains used by Layer 2 whitelist check
WHITELIST: set[str] = set()

# Brand names used by Layer 3 lookalike detector
WHITELIST_NAMES: set[str] = set()

# Expanded multi-part TLDs required for correct registrable domain extraction
MULTI_PART_TLDS = {
    # UK & Oceania
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk", "nhs.uk", "police.uk", "mod.uk",
    "gov.au", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "govt.nz", "ac.nz",
    # Asia & Sri Lanka
    "gov.lk", "ac.lk", "edu.lk", "com.lk", "org.lk",
    "co.in", "gov.in", "ac.in", "edu.in", "res.in",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.sg", "gov.sg", "edu.sg",
    # Americas & Europe
    "com.br", "gov.br", "edu.br",
    "gc.ca", "gov.ca",
    "com.mx", "gob.mx",
}

# Generic words excluded from brand name lookalike detection
_GENERIC_NAMES = {
    "www", "mail", "email", "smtp", "ftp", "ssh",
    "cdn", "api", "app", "web", "blog", "shop",
    "edu", "gov", "com", "net", "org", "int",
    "m", "en", "de", "fr", "es", "jp", "cn",
    "static", "media", "images", "assets", "files",
    "login", "auth", "secure", "portal", "admin",
    "support", "help", "news", "home", "info", "online",
}

# Government, academic, and restricted institutional TLD suffixes
GOVERNMENT_TLDS = {
    "gov.au", "gov.uk", "gov.lk", "gov.in", "gov.nz",
    "gov.sg", "gov.za", "gov.ie", "gov.us", "usa.gov",
    "govt.nz", "gc.ca", "gob.mx", "go.jp",
    "edu.au", "ac.uk", "ac.lk", "ac.nz", "ac.in",
    "edu.lk", "edu.sg", "edu.br", "edu.in",
    "nhs.uk", "police.uk", "mod.uk",
    "edu", "gov",
}


def _extract_registrable_domain(hostname: str) -> str:
    """Strip subdomains and return the registrable domain cleanly."""
    hostname = hostname.lower().strip().rstrip(".")
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    # Check multi-part TLD match first
    candidate_suffix = ".".join(parts[-2:])
    if candidate_suffix in MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname

    return ".".join(parts[-2:])


def _extract_brand_name(registrable: str) -> str:
    """Extract primary brand name from a registrable domain."""
    return registrable.split(".")[0]


def initialise_whitelist(top_n: int = WHITELIST_TOP_N) -> None:
    """Load Tranco CSV and populate WHITELIST and WHITELIST_NAMES sets."""
    global WHITELIST, WHITELIST_NAMES

    if not os.path.exists(_CSV_PATH):
        print(f"[whitelist] WARNING: Tranco CSV not found at: {_CSV_PATH}")
        print("[whitelist] Using fallback hardcoded list.")
        _load_fallback()
        return

    new_whitelist = set()
    new_whitelist_names = set()
    loaded = 0
    skipped_short_brand = 0

    with open(_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for idx, row in enumerate(reader, start=1):
            if not row:
                continue

            # Support both 1-column (domain) and 2-column (rank, domain) Tranco CSVs
            if len(row) == 1:
                rank = idx
                domain = row[0].strip().lower()
            else:
                try:
                    rank = int(row[0])
                    domain = row[1].strip().lower()
                except ValueError:
                    continue  # Skip header row if present

            if rank > top_n:
                break

            registrable = _extract_registrable_domain(domain)
            brand = _extract_brand_name(registrable)

            new_whitelist.add(registrable)

            if brand in _GENERIC_NAMES:
                pass
            elif len(brand) < MIN_BRAND_NAME_LENGTH:
                skipped_short_brand += 1
            else:
                new_whitelist_names.add(brand)

            loaded += 1

    WHITELIST = new_whitelist
    WHITELIST_NAMES = new_whitelist_names

    print(f"[whitelist] Loaded {loaded:,} Tranco domains: "
          f"{len(WHITELIST):,} registrable domains, "
          f"{len(WHITELIST_NAMES):,} brand names "
          f"({skipped_short_brand:,} short brands excluded as lookalike anchors).")


def _load_fallback() -> None:
    """Load fallback whitelist if Tranco CSV is absent."""
    global WHITELIST, WHITELIST_NAMES

    core = {
        "google.com", "youtube.com", "facebook.com",
        "twitter.com", "instagram.com", "linkedin.com",
        "amazon.com", "microsoft.com", "apple.com",
        "netflix.com", "wikipedia.org", "reddit.com",
        "github.com", "stackoverflow.com", "paypal.com",
        "ebay.com", "bbc.co.uk", "bbc.com", "cnn.com",
        "yahoo.com", "whatsapp.com", "tiktok.com",
        "zoom.us", "dropbox.com", "spotify.com",
        "twitch.tv", "discord.com", "cloudflare.com",
    }

    WHITELIST = core.copy()
    WHITELIST_NAMES = {
        _extract_brand_name(d) for d in core
        if len(_extract_brand_name(d)) >= MIN_BRAND_NAME_LENGTH
    }

    print(f"[whitelist] Fallback active: {len(WHITELIST)} domains, "
          f"{len(WHITELIST_NAMES)} brand names.")


def check_whitelist(url: str) -> dict | None:
    """Check if URL belongs to a Whitelisted or Verified Government/Edu TLD domain."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().strip()

        if not hostname:
            return None

        registrable = _extract_registrable_domain(hostname)

        # Check Government & Educational TLD verified status
        for g_tld in GOVERNMENT_TLDS:
            if hostname.endswith("." + g_tld) or hostname == g_tld:
                return {
                    "verdict": "safe",
                    "is_phishing": False,
                    "confidence": 0.99,
                    "detection_layer": "whitelist",
                    "explanation": (
                        f"{registrable} uses a verified government or "
                        f"educational top-level domain (.{g_tld}), "
                        f"which requires strict institutional verification."
                    ),
                    "domain": registrable,
                }

        # Check Tranco Top-N Whitelist
        if registrable in WHITELIST:
            return {
                "verdict": "safe",
                "is_phishing": False,
                "confidence": 0.99,
                "detection_layer": "whitelist",
                "explanation": (
                    f"{registrable} is verified against the global top "
                    f"traffic whitelist ({WHITELIST_TOP_N:,} popular domains)."
                ),
                "domain": registrable,
            }

        return None

    except Exception:
        return None