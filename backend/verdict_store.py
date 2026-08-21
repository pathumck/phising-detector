"""
Verdict logging and user-override tracking.

Reads/writes the `verdict_log` and `user_overrides` tables created by
migrate_to_sqlite.py. Unlike blacklist.py / whitelist.py, there is no
in-memory cache here - these tables are write-heavy audit/analytics
data, not something looked up on the hot path of every /predict call,
so every function goes straight to the database.

NOTE ON DB_PATH:
DB_PATH is resolved from the DB_PATH environment variable first, falling
back to the local relative path for development. This lets a cloud
platform (e.g. Render) point the app at a database file on a persistent
disk without any code changes - only an env var needs to be set.
"""

import os
import sqlite3

_HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(_HERE, "phishing_guard.db"),
)

# How recent an override has to be to suppress a re-warning on the same URL.
# Keeps a user from being nagged again this browsing session, without
# permanently silencing a domain that later gets blacklisted for real.
OVERRIDE_SUPPRESSION_HOURS = 24


def _get_conn() -> sqlite3.Connection:
    """Open a connection to the shared SQLite database."""
    return sqlite3.connect(DB_PATH)


# ---- verdict_log ----------------------------------------------------


def log_verdict(
    url: str, result: dict, response_time_ms: float | None = None
) -> None:
    """Persist a single check_url() result to verdict_log.

    Best-effort: a logging failure must never break /predict, so
    errors are swallowed after being printed (same pattern as
    add_to_blacklist()'s persistence try/except).
    """
    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO verdict_log "
            "(url, domain, verdict, detection_layer, confidence, ml_score, response_time_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                url,
                result.get("domain", ""),
                result.get("verdict", "unknown"),
                result.get("detection_layer", "none"),
                result.get("confidence"),
                result.get("ml_score"),
                (
                    response_time_ms
                    if response_time_ms is not None
                    else result.get("response_time_ms")
                ),
            ),
        )
        conn.commit()
    except Exception as e:
        print(f"[verdict_store] WARNING: could not log verdict for {url}: {e}")
    finally:
        conn.close()


def get_verdict_stats(limit_recent: int = 20) -> dict:
    """Summary stats for the admin/evaluation dashboard:

    - total checks logged
    - counts per detection_layer (how often each layer fires)
    - counts per verdict (safe vs phishing)
    - average response time in ms
    - most recently logged checks
    """
    conn = _get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM verdict_log").fetchone()[0]

        by_layer = dict(
            conn.execute(
                "SELECT detection_layer, COUNT(*) FROM verdict_log "
                "GROUP BY detection_layer ORDER BY COUNT(*) DESC"
            ).fetchall()
        )

        by_verdict = dict(
            conn.execute(
                "SELECT verdict, COUNT(*) FROM verdict_log GROUP BY verdict"
            ).fetchall()
        )

        avg_response_ms = conn.execute(
            "SELECT AVG(response_time_ms) FROM verdict_log "
            "WHERE response_time_ms IS NOT NULL"
        ).fetchone()[0]

        recent_rows = conn.execute(
            "SELECT url, domain, verdict, detection_layer, confidence, checked_at "
            "FROM verdict_log ORDER BY checked_at DESC LIMIT ?",
            (limit_recent,),
        ).fetchall()

        recent = [
            {
                "url": r[0],
                "domain": r[1],
                "verdict": r[2],
                "detection_layer": r[3],
                "confidence": r[4],
                "checked_at": r[5],
            }
            for r in recent_rows
        ]

        return {
            "total_checks": total,
            "by_detection_layer": by_layer,
            "by_verdict": by_verdict,
            "avg_response_time_ms": (
                round(avg_response_ms, 2) if avg_response_ms else None
            ),
            "recent": recent,
        }
    finally:
        conn.close()


# ---- user_overrides ---------------------------------------------------


def record_override(url: str, tab_id: str | None = None) -> int:
    """Record that a user dismissed a warning and proceeded to a flagged URL.

    Returns the new row's id.
    """
    conn = _get_conn()
    try:
        cursor = conn.execute(
            "INSERT INTO user_overrides (url, tab_id) VALUES (?, ?)",
            (url, tab_id),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def check_override(url: str, tab_id: str | None = None) -> bool:
    """True if this URL was already overridden recently (within

    OVERRIDE_SUPPRESSION_HOURS), so the extension can skip re-warning
    the user on a page they already chose to proceed through.

    If tab_id is given, only that tab's override counts - an override
    in one tab shouldn't silently suppress warnings in another.
    """
    conn = _get_conn()
    try:
        if tab_id:
            row = conn.execute(
                "SELECT 1 FROM user_overrides "
                "WHERE url = ? AND tab_id = ? "
                "AND overridden_at >= datetime('now', ?) LIMIT 1",
                (url, tab_id, f"-{OVERRIDE_SUPPRESSION_HOURS} hours"),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT 1 FROM user_overrides "
                "WHERE url = ? AND overridden_at >= datetime('now', ?) LIMIT 1",
                (url, f"-{OVERRIDE_SUPPRESSION_HOURS} hours"),
            ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_most_overridden_domains(
    min_count: int = 2, limit: int = 25
) -> list[dict]:
    """Domains users have overridden more than once, joined against verdict_log

    to show what each was flagged as. A domain that keeps getting overridden
    and was flagged by a rule-based layer (not the ML model) is a strong
    false-positive candidate worth reviewing - useful evidence for the
    project's evaluation chapter.
    """
    conn = _get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                v.domain,
                COUNT(DISTINCT o.id) AS override_count,
                v.verdict,
                v.detection_layer,
                v.confidence
            FROM user_overrides o
            JOIN verdict_log v ON v.url = o.url
            GROUP BY v.domain
            HAVING override_count >= ?
            ORDER BY override_count DESC
            LIMIT ?
            """,
            (min_count, limit),
        ).fetchall()

        return [
            {
                "domain": r[0],
                "override_count": r[1],
                "verdict": r[2],
                "detection_layer": r[3],
                "confidence": r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()