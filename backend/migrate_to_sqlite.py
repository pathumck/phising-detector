"""
One-time migration script: moves existing hardcoded/file-based data
(phishtank.csv, blacklist.txt, tranco_top1m.csv, and hardcoded Python sets)
into a single SQLite database (phishing_guard.db).

Run this ONCE from your backend/ directory:
    python migrate_to_sqlite.py

After running, update blacklist.py / whitelist.py / lookalike_detector.py
to read from the DB instead of the files (see accompanying notes).
"""

import csv
import os
import sqlite3

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_HERE, "phishing_guard.db")

# Paths to your EXISTING source files (adjust if yours differ)
PHISHTANK_CSV = os.path.join(_HERE, "domain_lists", "phishtank.csv")
RUNTIME_BLACKLIST_TXT = os.path.join(_HERE, "domain_lists", "blacklist.txt")
TRANCO_CSV = os.path.join(_HERE, "domain_lists", "tranco_top1m.csv")

MIN_BRAND_NAME_LENGTH = 4

MULTI_PART_TLDS = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk", "nhs.uk", "police.uk", "mod.uk",
    "gov.au", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "govt.nz", "ac.nz",
    "gov.lk", "ac.lk", "edu.lk", "com.lk", "org.lk",
    "co.in", "gov.in", "ac.in", "edu.in", "res.in",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.sg", "gov.sg", "edu.sg",
    "com.br", "gov.br", "edu.br",
    "gc.ca", "gov.ca",
    "com.mx", "gob.mx",
}

GOVERNMENT_TLDS = {
    "gov.au", "gov.uk", "gov.lk", "gov.in", "gov.nz",
    "gov.sg", "gov.za", "gov.ie", "gov.us", "usa.gov",
    "govt.nz", "gc.ca", "gob.mx", "go.jp",
    "edu.au", "ac.uk", "ac.lk", "ac.nz", "ac.in",
    "edu.lk", "edu.sg", "edu.br", "edu.in",
    "nhs.uk", "police.uk", "mod.uk",
    "edu", "gov",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "account", "secure",
    "update", "banking", "confirm", "password", "credential",
    "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "bank", "free", "lucky", "bonus",
    "winner", "click", "submit", "access", "webscr"
}

SENSITIVE_KEYWORDS = {
    "finance", "financial", "bank", "banking", "gov", "government",
    "tax", "treasury", "customs", "ministry", "embassy", "passport",
    "visa", "immigration", "trade", "export", "import", "revenue",
    "authority", "agency", "department", "national", "federal",
    "secure", "verify", "account", "login", "portal", "payment",
}

SHARED_PLATFORMS = {
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

GENERIC_SUBDOMAINS = {
    "www", "mail", "email", "ftp", "cdn", "api",
    "app", "web", "blog", "m", "en", "static",
    "media", "images", "shop", "edu", "gov",
    "support", "help", "news", "portal", "admin",
}

_DOMAIN_RE_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-."


def _is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    return all(c in _DOMAIN_RE_CHARS for c in domain)


def _extract_registrable_domain(hostname: str) -> str:
    hostname = hostname.lower().strip().rstrip(".")
    parts = hostname.split(".")
    if len(parts) < 2:
        return hostname
    candidate = ".".join(parts[-2:])
    if candidate in MULTI_PART_TLDS:
        return ".".join(parts[-3:]) if len(parts) >= 3 else hostname
    return candidate


def _extract_domain_from_url(url: str) -> str | None:
    from urllib.parse import urlparse
    try:
        url = str(url).strip()
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return None
        return _extract_registrable_domain(host)
    except Exception:
        return None


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS blacklist_domains (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain      TEXT NOT NULL UNIQUE,
        source      TEXT NOT NULL,
        confidence  REAL DEFAULT 1.0,
        added_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_blacklist_domain ON blacklist_domains(domain);

    CREATE TABLE IF NOT EXISTS whitelist_domains (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        domain      TEXT NOT NULL UNIQUE,
        rank        INTEGER,
        brand_name  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_whitelist_domain ON whitelist_domains(domain);
    CREATE INDEX IF NOT EXISTS idx_whitelist_brand ON whitelist_domains(brand_name);

    CREATE TABLE IF NOT EXISTS government_tlds (
        tld TEXT PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS multipart_tlds (
        tld TEXT PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS detection_keywords (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword  TEXT NOT NULL,
        category TEXT NOT NULL,
        UNIQUE(keyword, category)
    );
    CREATE INDEX IF NOT EXISTS idx_keywords_category ON detection_keywords(category);

    CREATE TABLE IF NOT EXISTS verdict_log (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        url              TEXT NOT NULL,
        domain           TEXT NOT NULL,
        verdict          TEXT NOT NULL,
        detection_layer  TEXT NOT NULL,
        confidence       REAL,
        ml_score         REAL,
        response_time_ms REAL,
        checked_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS user_overrides (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        url           TEXT NOT NULL,
        tab_id        TEXT,
        overridden_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    print("[migrate] Schema created.")


def migrate_phishtank(conn: sqlite3.Connection) -> int:
    """Load verified/online PhishTank rows into blacklist_domains."""
    if not os.path.exists(PHISHTANK_CSV):
        print(f"[migrate] SKIP: PhishTank CSV not found at {PHISHTANK_CSV}")
        return 0

    loaded = 0
    seen = set()
    with open(PHISHTANK_CSV, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            verified = row.get("verified", "").strip().lower()
            online = row.get("online", "").strip().lower()
            if verified != "yes" or online != "yes":
                continue

            domain = _extract_domain_from_url(row.get("url", "").strip())
            if not domain or not _is_valid_domain(domain):
                continue
            if domain in SHARED_PLATFORMS or domain in seen:
                continue

            seen.add(domain)
            rows.append((domain, "phishtank", 1.0))

        conn.executemany(
            "INSERT OR IGNORE INTO blacklist_domains (domain, source, confidence) VALUES (?, ?, ?)",
            rows,
        )
        loaded = len(rows)

    conn.commit()
    print(f"[migrate] PhishTank -> blacklist_domains: {loaded:,} rows.")
    return loaded


def migrate_runtime_blacklist(conn: sqlite3.Connection) -> int:
    """Load runtime-learned domains (blacklist.txt) into blacklist_domains."""
    if not os.path.exists(RUNTIME_BLACKLIST_TXT):
        print("[migrate] SKIP: no runtime blacklist.txt found (that's fine if none exists yet).")
        return 0

    loaded = 0
    with open(RUNTIME_BLACKLIST_TXT, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and _is_valid_domain(domain):
                conn.execute(
                    "INSERT OR IGNORE INTO blacklist_domains (domain, source, confidence) VALUES (?, ?, ?)",
                    (domain, "ml_auto_learned", 1.0),
                )
                loaded += 1

    conn.commit()
    print(f"[migrate] Runtime blacklist.txt -> blacklist_domains: {loaded:,} rows.")
    return loaded


def migrate_tranco(conn: sqlite3.Connection, top_n: int = 300_000) -> int:
    """Load Tranco whitelist CSV into whitelist_domains."""
    if not os.path.exists(TRANCO_CSV):
        print(f"[migrate] SKIP: Tranco CSV not found at {TRANCO_CSV}")
        return 0

    rows = []
    with open(TRANCO_CSV, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        for idx, row in enumerate(reader, start=1):
            if not row:
                continue
            if len(row) == 1:
                rank, domain = idx, row[0].strip().lower()
            else:
                try:
                    rank = int(row[0])
                    domain = row[1].strip().lower()
                except ValueError:
                    continue
            if rank > top_n:
                break

            registrable = _extract_registrable_domain(domain)
            brand = registrable.split(".")[0]
            brand = brand if len(brand) >= MIN_BRAND_NAME_LENGTH else None
            rows.append((registrable, rank, brand))

    conn.executemany(
        "INSERT OR IGNORE INTO whitelist_domains (domain, rank, brand_name) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()
    print(f"[migrate] Tranco -> whitelist_domains: {len(rows):,} rows.")
    return len(rows)


def migrate_static_sets(conn: sqlite3.Connection) -> None:
    """Load hardcoded Python sets (TLDs, keywords) into their tables."""
    conn.executemany(
        "INSERT OR IGNORE INTO multipart_tlds (tld) VALUES (?)",
        [(t,) for t in MULTI_PART_TLDS],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO government_tlds (tld) VALUES (?)",
        [(t,) for t in GOVERNMENT_TLDS],
    )

    keyword_rows = (
        [(k, "suspicious") for k in SUSPICIOUS_KEYWORDS]
        + [(k, "sensitive_institutional") for k in SENSITIVE_KEYWORDS]
        + [(k, "shared_platform") for k in SHARED_PLATFORMS]
        + [(k, "generic_subdomain") for k in GENERIC_SUBDOMAINS]
    )
    conn.executemany(
        "INSERT OR IGNORE INTO detection_keywords (keyword, category) VALUES (?, ?)",
        keyword_rows,
    )
    conn.commit()
    print(
        f"[migrate] Static sets -> multipart_tlds, government_tlds, detection_keywords "
        f"({len(keyword_rows):,} keyword rows)."
    )


def main():
    conn = sqlite3.connect(DB_PATH)
    create_schema(conn)
    migrate_phishtank(conn)
    migrate_runtime_blacklist(conn)
    migrate_tranco(conn)
    migrate_static_sets(conn)
    conn.close()
    print(f"\n[migrate] Done. Database created at: {DB_PATH}")


if __name__ == "__main__":
    main()