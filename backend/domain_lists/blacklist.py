"""
Layer 1 of the hybrid detection system.
Sources loaded at startup into one unified Python set, sourced
from phishing_guard.db (blacklist_domains table).

IMPORTANT - in-memory cache design:
BLACKLIST is a Python set kept in memory for O(1) lookup speed on every
/predict request (required for the sub-500ms latency target). The database
is the source of truth, but it is only read from at startup by default.
Any addition/removal MUST go through add_to_blacklist() or
remove_from_blacklist() below, which update BOTH the in-memory set and the
database together. Editing the database directly while the app is running
will NOT be reflected until reload_blacklist() is called or the app restarts.

NOTE ON DB_PATH:
DB_PATH is resolved from the DB_PATH environment variable first, falling
back to the local relative path for development. This lets a cloud
platform (e.g. Render) point the app at a database file on a persistent
disk without any code changes - only an env var needs to be set.
"""

import os
import re
import sqlite3
from urllib.parse import urlparse

# The unified blacklist - all sources merged here at startup
BLACKLIST: set[str] = set()

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(_HERE, "..", "phishing_guard.db"),
)

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


def _get_conn() -> sqlite3.Connection:
    """Open a connection to the shared SQLite database."""
    return sqlite3.connect(DB_PATH)


def _extract_registrable_domain(hostname: str) -> str:
    """Extract registrable domain by stripping subdomains."""
    parts = hostname.lower().strip().split(".")
    if len(parts) < 2:
        return hostname.lower()

    candidate = ".".join(parts[-2:])
    if candidate in _MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname.lower()

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


def initialise_blacklist() -> None:
    """Load all blacklist domains from the database into BLACKLIST."""
    print("[blacklist] Initialising from database...")

    if not os.path.exists(DB_PATH):
        print(
            f"[blacklist] WARNING: Database not found at {DB_PATH}. "
            f"Run migrate_to_sqlite.py first."
        )
        return

    conn = _get_conn()
    try:
        rows = conn.execute("SELECT domain FROM blacklist_domains").fetchall()
        for (domain,) in rows:
            if _is_valid_domain(domain):
                BLACKLIST.add(domain)
    finally:
        conn.close()

    print(f"[blacklist] Ready. Total unique domains: {len(BLACKLIST):,}")


def reload_blacklist() -> int:
    """
    Force a full reload of BLACKLIST from the database.
    Use this after deleting/editing rows directly in the database,
    or on a timer/admin trigger, to bring the in-memory cache back
    in sync with the source of truth without restarting the app.
    """
    BLACKLIST.clear()
    initialise_blacklist()
    return len(BLACKLIST)


def clean_against_whitelist(whitelist: set) -> None:
    """Remove whitelist overlaps from BLACKLIST set (in-memory + DB)."""
    global BLACKLIST
    before = len(BLACKLIST)
    overlap = BLACKLIST & whitelist
    BLACKLIST = BLACKLIST - whitelist
    removed = before - len(BLACKLIST)

    if removed > 0:
        conn = _get_conn()
        try:
            conn.executemany(
                "DELETE FROM blacklist_domains WHERE domain = ?",
                [(d,) for d in overlap],
            )
            conn.commit()
        finally:
            conn.close()

        print(
            f"[blacklist] Removed {removed} domains also "
            f"in Tranco whitelist (shared platform cleanup): "
            f"{sorted(overlap)[:10]}"
            f"{'...' if len(overlap) > 10 else ''}"
        )


def add_to_blacklist(domain: str) -> None:
    """Add a newly detected phishing domain to memory and the database."""
    domain = domain.lower().strip()

    if not domain or not _is_valid_domain(domain):
        return

    if domain in BLACKLIST:
        return

    BLACKLIST.add(domain)

    conn = _get_conn()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO blacklist_domains (domain, source, confidence) "
            "VALUES (?, ?, ?)",
            (domain, "ml_auto_learned", 1.0),
        )
        conn.commit()
        print(f"[blacklist] Runtime learned + persisted to DB: {domain}")
    except Exception as e:
        print(f"[blacklist] WARNING: could not persist {domain}: {e}")
    finally:
        conn.close()


def remove_from_blacklist(domain: str) -> bool:
    """
    Remove a domain from both the in-memory BLACKLIST set and the
    database in one operation, so the change takes effect immediately
    on the running system without needing a restart.

    Returns True if the domain was found and removed, False if it
    wasn't in the blacklist to begin with.
    """
    domain = domain.lower().strip()

    if not domain:
        return False

    was_present = domain in BLACKLIST
    BLACKLIST.discard(domain)

    conn = _get_conn()
    try:
        cursor = conn.execute(
            "DELETE FROM blacklist_domains WHERE domain = ?", (domain,)
        )
        conn.commit()
        db_removed = cursor.rowcount > 0
    finally:
        conn.close()

    if was_present or db_removed:
        print(f"[blacklist] Removed from memory + DB: {domain}")
        return True

    return False


def get_blacklist_domains(
    source: str | None = None, limit: int = 100
) -> list[dict]:
    """Returns blacklist domains with their source, confidence, and

    added_at timestamp, most recently added first.

    Reads straight from the database rather than the in-memory BLACKLIST
    set, since BLACKLIST only stores bare domain strings with no source
    or timestamp info attached. Pass source="ml_auto_learned" to get only
    the domains the system taught itself at runtime, as opposed to the
    ones seeded from PhishTank at migration time.
    """
    conn = _get_conn()
    try:
        if source:
            rows = conn.execute(
                "SELECT domain, source, confidence, added_at FROM blacklist_domains "
                "WHERE source = ? ORDER BY added_at DESC LIMIT ?",
                (source, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT domain, source, confidence, added_at FROM blacklist_domains "
                "ORDER BY added_at DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [
            {"domain": r[0], "source": r[1], "confidence": r[2], "added_at": r[3]}
            for r in rows
        ]
    finally:
        conn.close()


def count_blacklist_by_source() -> dict[str, int]:
    """Returns {source: count} for every distinct source in blacklist_domains,

    e.g. {"phishtank": 11842, "ml_auto_learned": 47}. Lets the dashboard show
    how many domains the system has taught itself at runtime versus how many
    came from the seeded threat-intel list.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT source, COUNT(*) FROM blacklist_domains GROUP BY source"
        ).fetchall()
        return {source: count for source, count in rows}
    finally:
        conn.close()


def check_blacklist(url: str) -> dict | None:
    """Check if URL's domain is in BLACKLIST and return verdict."""
    domain = _extract_domain(url)

    if not domain:
        return None

    if domain in BLACKLIST:
        return {
            "verdict": "phishing",
            "is_phishing": True,
            "confidence": 1.00,
            "detection_layer": "blacklist",
            "explanation": (
                f"{domain} is a confirmed phishing domain from "
                f"PhishTank community threat intelligence. "
                f"Verified and currently active."
            ),
            "domain": domain,
        }

    return None