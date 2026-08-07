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
