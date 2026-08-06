"""
Layer 1 of the hybrid detection system.
Sources loaded at startup into one unified Python set:
  Source 1: PhishTank CSV (static file)
  Source 2: blacklist.txt (runtime learning)
"""

import re
import os
import csv
from urllib.parse import urlparse

# The unified blacklist - all sources merged here at startup
BLACKLIST: set[str] = set()

_HERE           = os.path.dirname(os.path.abspath(__file__))
_PHISHTANK_PATH = os.path.join(_HERE, "phishtank.csv")
_RUNTIME_PATH   = os.path.join(_HERE, "blacklist.txt")

# Domain validation regex
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-\.]{0,250}[a-z0-9])?$"
)

# Multi-part TLDs for domain extraction
_MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk",
    "gov.au", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "govt.nz",
    "gov.lk", "ac.lk", "edu.lk", "com.lk", "org.lk",
}


# Shared platforms never blacklisted at domain level
_SHARED_PLATFORMS = {
    "google.com", "google.co.uk", "google.com.au",
    "google.co.in", "google.de", "google.fr",
    "linkedin.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "tiktok.com", "reddit.com", "pinterest.com",
    "wixsite.com", "wix.com", "weebly.com",
    "squarespace.com", "webflow.io", "carrd.co",
    "github.io", "github.com", "gitlab.io",
    "replit.app", "replit.com", "glitch.me",
    "netlify.app", "vercel.app", "pages.dev",
    "web.app", "firebaseapp.com",
    "flowcode.com", "linktr.ee", "bio.link",
    "beacons.ai", "campsite.bio",
    "drive.google.com", "docs.google.com",
    "sharepoint.com", "onedrive.live.com",
    "dropbox.com", "box.com",
    "blogspot.com", "wordpress.com",
    "medium.com", "substack.com",
    "notion.so", "sites.google.com",
}


def _extract_registrable_domain(hostname: str) -> str:
    """Extract registrable domain by stripping subdomains."""
    parts = hostname.lower().strip().split(".")
    if len(parts) < 2:
        return hostname.lower()

    candidate = ".".join(parts[-2:])
    if candidate in _MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 \
               else hostname.lower()

    return ".".join(parts[-2:])


def _extract_domain(url: str) -> str | None:
    """Extract registrable domain from a full URL."""
    try:
        url = str(url).strip()
        if not url:
            return None

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            return None

        return _extract_registrable_domain(host)

    except Exception:
        return None


def _is_valid_domain(domain: str) -> bool:
    """Check if domain matches basic format requirements."""
    return bool(domain and _DOMAIN_RE.match(domain))


def _load_phishtank() -> int:
    """Load verified active PhishTank CSV domains into BLACKLIST set."""
    if not os.path.exists(_PHISHTANK_PATH):
        print(f"[blacklist] WARNING: PhishTank CSV not found.")
        print(f"            Expected: {_PHISHTANK_PATH}")
        return 0

    loaded  = 0
    skipped = 0

    with open(_PHISHTANK_PATH, "r", encoding="utf-8",
              errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            verified = row.get("verified", "").strip().lower()
            online   = row.get("online",   "").strip().lower()

            if verified != "yes" or online != "yes":
                skipped += 1
                continue

            url    = row.get("url", "").strip()
            domain = _extract_domain(url)

            if not domain or not _is_valid_domain(domain):
                continue

            if domain in _SHARED_PLATFORMS:
                skipped += 1
                continue

            BLACKLIST.add(domain)
            loaded += 1

    print(f"[blacklist] PhishTank: {loaded:,} domains loaded  "
          f"({skipped:,} unverified/offline skipped).")
    return loaded


def _load_runtime() -> int:
    """Load runtime-learned domains from blacklist.txt."""
    if not os.path.exists(_RUNTIME_PATH):
        return 0

    loaded = 0
    with open(_RUNTIME_PATH, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and _is_valid_domain(domain):
                BLACKLIST.add(domain)
                loaded += 1

    if loaded > 0:
        print(f"[blacklist] Runtime learned: {loaded:,} domains "
              f"from blacklist.txt")
    return loaded


def initialise_blacklist() -> None:
    """Load all blacklist sources into the unified BLACKLIST set."""
    print("[blacklist] Initialising...")
    _load_phishtank()
    _load_runtime()
    print(f"[blacklist] Ready. "
          f"Total unique domains: {len(BLACKLIST):,}")