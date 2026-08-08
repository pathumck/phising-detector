import os
import csv
from urllib.parse import urlparse

"""
Layer 2 of the hybrid detection system.

WHY TOP 10,000:
Covers approximately 90% of real browsing traffic.
Exclusive enough that any domain in this range is a
high-value phishing target worth protecting.
Excludes lower-ranked domains where Tranco's own
methodology acknowledges manipulation risk increases.

WHY LAYER 2 RUNS AFTER LAYER 1:
A domain could appear in both Tranco AND PhishTank if a
popular platform (e.g. a cloud hosting service) is abused
for phishing. Blacklist always takes priority; confirmed
phishing overrides popularity ranking.

SUBDOMAIN HANDLING:
Extracts the registrable domain before checking.
mail.google.com -> google.com -> found -> SAFE
Prevents evil.google.com.attacker.com from bypassing
the check by embedding google.com in the hostname.
"""

WHITELIST_TOP_N = 10_000

_HERE = os.path.dirname(os.path.abspath(__file__))
_CSV_PATH = os.path.join(_HERE, "tranco_top1m.csv")

# Full registrable domains used by Layer 2 whitelist check
WHITELIST: set[str] = set()

# Brand names used by Layer 3 lookalike detector
WHITELIST_NAMES: set[str] = set()

# Multi-part TLDs required for correct registrable domain extraction
MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk",
    "gov.au", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "govt.nz",
    "gov.lk", "ac.lk", "edu.lk", "com.lk", "org.lk",
}

# Generic words excluded from brand name lookalike detection
_GENERIC_NAMES = {
    "www", "mail", "email", "smtp", "ftp", "ssh",
    "cdn", "api", "app", "web", "blog", "shop",
    "edu", "gov", "com", "net", "org", "int",
    "m", "en", "de", "fr", "es", "jp", "cn",
    "static", "media", "images", "assets", "files",
    "login", "auth", "secure", "portal", "admin",
    "support", "help", "news", "home", "info",
}

# Government and education TLDs treated as safe
GOVERNMENT_TLDS = {
    "gov.au", "gov.uk", "gov.lk", "gov.in", "gov.nz",
    "gov.sg", "gov.za", "gov.ie", "gov.us", "usa.gov",
    "govt.nz", "gc.ca",
    "edu.au", "ac.uk", "ac.lk", "ac.nz", "ac.in",
    "edu.lk",
    "nhs.uk", "police.uk", "mod.uk",
    "edu", "gov",
}


def _extract_registrable_domain(hostname: str) -> str:
    """Strip subdomains and return the registrable domain only."""
    parts = hostname.lower().strip().split(".")

    if len(parts) < 2:
        return hostname.lower()

    candidate = ".".join(parts[-2:])
    if candidate in MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 \
               else hostname.lower()

    return ".".join(parts[-2:])


def _extract_brand_name(registrable: str) -> str:
    """Extract brand name from a registrable domain."""
    return registrable.split(".")[0]


def initialise_whitelist(top_n: int = WHITELIST_TOP_N) -> None:
    """Load Tranco CSV and populate WHITELIST and WHITELIST_NAMES."""
    global WHITELIST, WHITELIST_NAMES

    if not os.path.exists(_CSV_PATH):
        print(f"[whitelist] WARNING: Tranco CSV not found at:")
        print(f"            {_CSV_PATH}")
        print(f"[whitelist] Download from https://tranco-list.eu/top-1m.csv.zip")
        print(f"[whitelist] Using fallback hardcoded list.")
        _load_fallback()
        return

    WHITELIST = set()
    WHITELIST_NAMES = set()
    loaded = 0

    with open(_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
                domain = row[1].strip().lower()
            except ValueError:
                continue

            if rank > top_n:
                break

            registrable = _extract_registrable_domain(domain)
            brand = _extract_brand_name(registrable)

            if brand not in _GENERIC_NAMES:
                WHITELIST.add(registrable)
                WHITELIST_NAMES.add(brand)
            else:
                WHITELIST.add(registrable)
            loaded += 1

    print(f"[whitelist] Loaded {loaded:,} Tranco domains: "
          f"{len(WHITELIST):,} registrable domains, "
          f"{len(WHITELIST_NAMES):,} brand names.")
    

def _load_fallback() -> None:
    """Load fallback whitelist if Tranco CSV is missing."""
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
    WHITELIST_NAMES = {_extract_brand_name(d) for d in core}

    print(f"[whitelist] Fallback: {len(WHITELIST)} domains, "
          f"{len(WHITELIST_NAMES)} brand names.")    
    

def check_whitelist(url: str) -> dict | None:
    """Check if URL belongs to a Tranco-whitelisted domain."""
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            return None

        registrable = _extract_registrable_domain(hostname)

        parts = hostname.split(".")
        suffix = ".".join(parts[-2:])
        tld = parts[-1]

        if suffix in GOVERNMENT_TLDS or tld in GOVERNMENT_TLDS:
            return {
                "verdict": "safe",
                "is_phishing": False,
                "confidence": 0.99,
                "detection_layer": "whitelist",
                "explanation": (
                    f"{registrable} uses a verified government or "
                    f"educational top-level domain (.{suffix}), "
                    f"which requires institutional verification "
                    f"to register."
                ),
                "domain": registrable,
            }

        if registrable in WHITELIST:
            return {
                "verdict": "safe",
                "is_phishing": False,
                "confidence": 0.99,
                "detection_layer": "whitelist",
                "explanation": (
                    f"{registrable} is ranked in the Tranco global "
                    f"top {WHITELIST_TOP_N:,} most visited domains "
                    f"worldwide. Verified trusted domain."
                ),
                "domain": registrable,
            }

        return None

    except Exception:
        return None

