"""
database/db.py
--------------
SQLite persistence layer for the Local LLM Hunter agent.

Provides thin wrapper functions around sqlite3 for all database operations:
  - init_db()                       — creates tables from schema.sql
  - insert_event(event)             — writes an AIRuntimeEvent to detection_events
  - insert_scan(scan_data)          — writes a scan pass record to scan_history
  - get_all_events()                — returns all detection_events rows
  - get_active_inventory()          — returns all active ai_inventory rows
  - get_alerts(unresolved_only)     — returns alert rows
  - mark_alert_resolved(alert_id)   — flips resolved=1 on an alert

Database file : ./database/llm_hunter.db  (created automatically if absent)
Schema file   : ./database/schema.sql
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Resolve paths relative to this file so the module works regardless of
# the working directory the caller uses.
_HERE        = Path(__file__).parent
DB_PATH      = _HERE / "llm_hunter.db"
SCHEMA_PATH  = _HERE / "schema.sql"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    """
    Open and return a sqlite3 connection with:
      - Row factory set to sqlite3.Row (allows dict-like column access)
      - Foreign key enforcement enabled
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    """Convert a sqlite3.Row to a plain Python dict."""
    return dict(row)


# ---------------------------------------------------------------------------
# init_db
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Initialise the database by executing schema.sql.

    Creates all tables and indexes if they do not already exist.
    Safe to call multiple times (uses CREATE IF NOT EXISTS).

    Raises:
        FileNotFoundError : if schema.sql cannot be located.
        sqlite3.Error     : on any database error.
    """
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Schema file not found: {SCHEMA_PATH}")

    schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")

    with _get_connection() as conn:
        conn.executescript(schema_sql)

    print(f"[db] Database initialised at: {DB_PATH}")


# ---------------------------------------------------------------------------
# insert_event
# ---------------------------------------------------------------------------

def insert_event(event: Any) -> None:
    """
    Persist an AIRuntimeEvent to the detection_events table.

    Accepts either an AIRuntimeEvent Pydantic model instance or a plain
    dict with the same keys.  Uses INSERT OR IGNORE so duplicate event_ids
    are silently skipped.

    Args:
        event : AIRuntimeEvent instance (or equivalent dict).
    """
    # Support both Pydantic model and raw dict inputs
    if hasattr(event, "model_dump"):
        data = event.model_dump()
    else:
        data = dict(event)

    # Serialise list/dict fields to JSON strings for SQLite storage
    data["lib_match"]     = json.dumps(data.get("lib_match", []))
    data["signals_fired"] = json.dumps(data.get("signals_fired", {}))

    # Convert booleans to integers (SQLite has no native bool type)
    for bool_col in ("gpu_spike", "policy_violation", "vuln_flag", "endpoint_criticality"):
        data[bool_col] = int(bool(data.get(bool_col, False)))

    sql = """
        INSERT OR IGNORE INTO detection_events (
            event_id, host, runtime, model_file, port_detected,
            gpu_spike, lib_match, risk_score, timestamp, user_id,
            department, approval_status, policy_violation, vuln_flag,
            signals_fired, signal_count, endpoint_criticality
        ) VALUES (
            :event_id, :host, :runtime, :model_file, :port_detected,
            :gpu_spike, :lib_match, :risk_score, :timestamp, :user_id,
            :department, :approval_status, :policy_violation, :vuln_flag,
            :signals_fired, :signal_count, :endpoint_criticality
        )
    """

    with _get_connection() as conn:
        conn.execute(sql, data)


# ---------------------------------------------------------------------------
# insert_scan
# ---------------------------------------------------------------------------

def insert_scan(scan_data: dict[str, Any]) -> None:
    """
    Persist a completed scan pass record to the scan_history table.

    Expected keys in scan_data:
        scan_id             : str  — UUID for this scan run
        host                : str  — endpoint hostname
        scan_time           : str  — ISO-8601 UTC start timestamp
        duration_ms         : int  — wall-clock duration in milliseconds
        runtimes_found      : int  — count of detected runtimes
        total_signals_fired : int  — sum of all signals that fired

    Args:
        scan_data : dict matching the scan_history table columns.
    """
    sql = """
        INSERT OR IGNORE INTO scan_history (
            scan_id, host, scan_time, duration_ms,
            runtimes_found, total_signals_fired
        ) VALUES (
            :scan_id, :host, :scan_time, :duration_ms,
            :runtimes_found, :total_signals_fired
        )
    """

    with _get_connection() as conn:
        conn.execute(sql, scan_data)


# ---------------------------------------------------------------------------
# get_all_events
# ---------------------------------------------------------------------------

def get_all_events(limit: int = 50) -> list[dict[str, Any]]:
    """
    Return all rows from detection_events, ordered by timestamp descending.

    JSON string columns (lib_match, signals_fired) are deserialised back to
    Python lists/dicts before returning.

    Returns:
        List of dicts, one per detection event. Empty list if no events exist.
    """
    sql = "SELECT * FROM detection_events ORDER BY timestamp DESC LIMIT ?"

    with _get_connection() as conn:
        rows = conn.execute(sql, (limit,)).fetchall()

    results = []
    for row in rows:
        d = _row_to_dict(row)
        d["lib_match"]     = json.loads(d.get("lib_match") or "[]")
        d["signals_fired"] = json.loads(d.get("signals_fired") or "{}")
        results.append(d)

    return results


# ---------------------------------------------------------------------------
# get_active_inventory
# ---------------------------------------------------------------------------

def get_active_inventory() -> list[dict[str, Any]]:
    """
    Return all rows from ai_inventory where status = 'active'.

    Provides the current live picture of LLM runtimes observed across
    monitored endpoints.

    Returns:
        List of dicts representing active inventory entries.
    """
    sql = "SELECT * FROM ai_inventory WHERE status = 'active' ORDER BY last_seen DESC"

    with _get_connection() as conn:
        rows = conn.execute(sql).fetchall()

    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------

def get_alerts(unresolved_only: bool = True, limit: int = 50) -> list[dict[str, Any]]:
    """
    Return alert records from the alerts table.

    Args:
        unresolved_only : If True (default), return only open alerts
                          (resolved = 0). If False, return all alerts.
        limit : Maximum number of records to return. Default 50.

    Returns:
        List of alert dicts ordered by alerted_at descending.
    """
    if unresolved_only:
        sql = "SELECT * FROM alerts WHERE resolved = 0 ORDER BY alerted_at DESC LIMIT ?"
    else:
        sql = "SELECT * FROM alerts ORDER BY alerted_at DESC LIMIT ?"

    with _get_connection() as conn:
        rows = conn.execute(sql, (limit,)).fetchall()

    return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# mark_alert_resolved
# ---------------------------------------------------------------------------

def mark_alert_resolved(alert_id: str) -> None:
    """
    Mark a specific alert as resolved (sets resolved = 1).

    Args:
        alert_id : UUID string of the alert to resolve.

    Raises:
        ValueError : if no alert with the given alert_id exists.
    """
    sql_check  = "SELECT 1 FROM alerts WHERE alert_id = ?"
    sql_update = "UPDATE alerts SET resolved = 1 WHERE alert_id = ?"

    with _get_connection() as conn:
        exists = conn.execute(sql_check, (alert_id,)).fetchone()
        if not exists:
            raise ValueError(f"No alert found with alert_id='{alert_id}'")
        conn.execute(sql_update, (alert_id,))
