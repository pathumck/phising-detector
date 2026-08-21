"""
Layer 2 of the hybrid detection system - Whitelist & Safe TLD Verification.
Now sourced from phishing_guard.db (whitelist_domains, government_tlds,
multipart_tlds tables) instead of tranco_top1m.csv + hardcoded sets.

NOTE ON DB_PATH:
DB_PATH is resolved from the DB_PATH environment variable first, falling
back to the local relative path for development. This lets a cloud
platform (e.g. Render) point the app at a database file on a persistent
disk without any code changes - only an env var needs to be set.

NOTE ON WHITELIST_NAMES_BY_LENGTH:
Layer 3's typosquatting check (lookalike_detector.py) needs to compare a
candidate brand against every trusted brand name to find near-matches
within edit-distance 2. Looping over the full ~285k-entry WHITELIST_NAMES
set for every request is slow (multi-second). Since a Levenshtein distance
of <=2 is only mathematically possible when the two strings' lengths
differ by <=2, we pre-group brand names by length here at startup, so
the typosquatting check only has to compare against a small relevant
subset instead of the entire whitelist. This does not change which
matches are found - it only skips candidates that were guaranteed to
fail the distance check anyway.
"""

import os
import sqlite3
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(_HERE, "..", "phishing_guard.db"),
)

# Full registrable domains used by Layer 2 whitelist check
WHITELIST: set[str] = set()

# Brand names used by Layer 3 lookalike detector
WHITELIST_NAMES: set[str] = set()

# Brand names grouped by length, used by Layer 3's typosquatting check
# to avoid looping over the entire WHITELIST_NAMES set on every request.
WHITELIST_NAMES_BY_LENGTH: dict[int, set[str]] = {}

# Populated at init from multipart_tlds table (was a hardcoded set before)
MULTI_PART_TLDS: set[str] = set()

# Populated at init from government_tlds table (was a hardcoded set before)
GOVERNMENT_TLDS: set[str] = set()

# Generic words excluded from brand name lookalike detection
# (kept as a constant - this is detection logic, not data to tune live)
_GENERIC_NAMES = {
    "www", "mail", "email", "smtp", "ftp", "ssh",
    "cdn", "api", "app", "web", "blog", "shop",
    "edu", "gov", "com", "net", "org", "int",
    "m", "en", "de", "fr", "es", "jp", "cn",
    "static", "media", "images", "assets", "files",
    "login", "auth", "secure", "portal", "admin",
    "support", "help", "news", "home", "info", "online",
}


def _get_conn() -> sqlite3.Connection:
    """Open a connection to the shared SQLite database."""
    return sqlite3.connect(DB_PATH)


def _extract_registrable_domain(hostname: str) -> str:
    """Strip subdomains and return the registrable domain cleanly."""
    hostname = hostname.lower().strip().rstrip(".")
    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    candidate_suffix = ".".join(parts[-2:])
    if candidate_suffix in MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname

    return ".".join(parts[-2:])


def _build_length_index(names: set[str]) -> dict[int, set[str]]:
    """Group brand names by string length for fast candidate filtering."""
    index: dict[int, set[str]] = {}
    for name in names:
        index.setdefault(len(name), set()).add(name)
    return index


def get_length_bucketed_candidates(target_len: int, max_dist: int = 2) -> set[str]:
    """Return the set of trusted brand names whose length is within

    max_dist of target_len - the only names that could possibly be
    within max_dist Levenshtein distance of a string of that length.
    Used by lookalike_detector.py's typosquatting check instead of
    looping over the full WHITELIST_NAMES set.
    """
    candidates: set[str] = set()
    for length in range(max(1, target_len - max_dist), target_len + max_dist + 1):
        candidates |= WHITELIST_NAMES_BY_LENGTH.get(length, set())
    return candidates


def initialise_whitelist() -> None:
    """Load whitelist domains, government TLDs, and multi-part TLDs from DB."""
    global WHITELIST, WHITELIST_NAMES, WHITELIST_NAMES_BY_LENGTH
    global MULTI_PART_TLDS, GOVERNMENT_TLDS

    if not os.path.exists(DB_PATH):
        print(
            f"[whitelist] WARNING: Database not found at {DB_PATH}. "
            f"Run migrate_to_sqlite.py first."
        )
        return

    conn = _get_conn()
    try:
        # Load TLD reference tables first - domain extraction depends on them
        MULTI_PART_TLDS = {
            row[0] for row in conn.execute("SELECT tld FROM multipart_tlds")
        }
        GOVERNMENT_TLDS = {
            row[0] for row in conn.execute("SELECT tld FROM government_tlds")
        }

        rows = conn.execute(
            "SELECT domain, brand_name FROM whitelist_domains"
        ).fetchall()

        new_whitelist = {domain for domain, _ in rows}
        new_whitelist_names = {
            brand for _, brand in rows if brand
        }

        WHITELIST = new_whitelist
        WHITELIST_NAMES = new_whitelist_names
        WHITELIST_NAMES_BY_LENGTH = _build_length_index(new_whitelist_names)

    finally:
        conn.close()

    print(
        f"[whitelist] Loaded from DB: {len(WHITELIST):,} registrable domains, "
        f"{len(WHITELIST_NAMES):,} brand names "
        f"({len(WHITELIST_NAMES_BY_LENGTH)} distinct lengths indexed), "
        f"{len(MULTI_PART_TLDS)} multi-part TLDs, "
        f"{len(GOVERNMENT_TLDS)} government TLDs."
    )


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
                    f"traffic whitelist ({len(WHITELIST):,} domains)."
                ),
                "domain": registrable,
            }

        return None

    except Exception:
        return None