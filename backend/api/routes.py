"""
backend/api/routes.py
-----------------------
FastAPI route definitions for the Local LLM Hunter REST API.

Endpoints:
    POST   /api/events                   — ingest a detection event
    GET    /api/events                   — list detection events
    GET    /api/inventory                — AI runtime inventory
    GET    /api/alerts                   — open (or all) alerts
    PATCH  /api/alerts/{alert_id}/resolve — resolve an alert
    GET    /api/stats                    — dashboard summary statistics
    GET    /health                       — liveness / DB connectivity check

Authentication:
    All /api/* endpoints require the header:
        X-API-Key: llm-hunter-dev-key

    /health is unauthenticated (liveness probe).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Header, Query, status

# ---------------------------------------------------------------------------
# Project imports with fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import AIRuntimeEvent
    from database             import db as _db
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import AIRuntimeEvent
    from database             import db as _db

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_KEY = "llm-hunter-dev-key"

router = APIRouter()


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _require_api_key(x_api_key: str = Header(..., alias="X-API-Key")) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Raises:
        HTTPException 401 : if the key is missing or incorrect.
    """
    if x_api_key != _API_KEY:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail      = "Invalid or missing API key.",
        )
    return x_api_key


# ---------------------------------------------------------------------------
# POST /api/events
# ---------------------------------------------------------------------------

@router.post(
    "/api/events",
    status_code = status.HTTP_201_CREATED,
    summary     = "Ingest a detection event from an endpoint agent",
    tags        = ["Events"],
)
def ingest_event(
    event:   AIRuntimeEvent,
    _auth:   str = Depends(_require_api_key),
) -> dict[str, str]:
    """
    Receive a fully populated AIRuntimeEvent from a remote agent and
    persist it to the SQLite detection_events table.

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.

    Returns `{ status, event_id }` on success.
    """
    try:
        _db.insert_event(event)
    except Exception as exc:
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail      = f"DB insert failed: {exc}",
        )
    return {"status": "received", "event_id": event.event_id}


# ---------------------------------------------------------------------------
# GET /api/events
# ---------------------------------------------------------------------------

@router.get(
    "/api/events",
    summary = "List all detection events",
    tags    = ["Events"],
)
def list_events(
    risk_level: str | None = Query(
        default     = None,
        description = "Filter by risk level: LOW | MEDIUM | HIGH | CRITICAL",
    ),
    limit: int = Query(
        default     = 100,
        ge          = 1,
        le          = 1000,
        description = "Maximum number of events to return (1–1000)",
    ),
    _auth: str = Depends(_require_api_key),
) -> list[dict[str, Any]]:
    """
    Return detection events, optionally filtered by risk level.

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.
    """
    events = _db.get_all_events()

    if risk_level:
        events = [e for e in events if e.get("risk_score", "").upper() == risk_level.upper()]

    return events[:limit]


# ---------------------------------------------------------------------------
# GET /api/inventory
# ---------------------------------------------------------------------------

@router.get(
    "/api/inventory",
    summary = "AI runtime inventory grouped by host",
    tags    = ["Inventory"],
)
def get_inventory(
    _auth: str = Depends(_require_api_key),
) -> list[dict[str, Any]]:
    """
    Return the current AI inventory — all detected runtimes with their
    last-seen timestamp and active/resolved status.

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.
    """
    return _db.get_active_inventory()


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------

@router.get(
    "/api/alerts",
    summary = "List alerts",
    tags    = ["Alerts"],
)
def list_alerts(
    resolved: bool = Query(
        default     = False,
        description = "Set to true to include already-resolved alerts",
    ),
    _auth: str = Depends(_require_api_key),
) -> list[dict[str, Any]]:
    """
    Return open alerts by default. Pass `?resolved=true` to include
    all alerts regardless of resolution status.

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.
    """
    # get_alerts(unresolved_only=True) is the default behaviour
    return _db.get_alerts(unresolved_only=not resolved)


# ---------------------------------------------------------------------------
# PATCH /api/alerts/{alert_id}/resolve
# ---------------------------------------------------------------------------

@router.patch(
    "/api/alerts/{alert_id}/resolve",
    summary = "Resolve an open alert",
    tags    = ["Alerts"],
)
def resolve_alert(
    alert_id: str,
    _auth:    str = Depends(_require_api_key),
) -> dict[str, str]:
    """
    Mark a specific alert as resolved (sets `resolved = 1`).

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.

    Raises `404` if the alert_id does not exist.
    """
    try:
        _db.mark_alert_resolved(alert_id)
    except ValueError:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = f"Alert '{alert_id}' not found.",
        )
    return {"status": "resolved", "alert_id": alert_id}


# ---------------------------------------------------------------------------
# GET /api/stats
# ---------------------------------------------------------------------------

@router.get(
    "/api/stats",
    summary = "Dashboard summary statistics",
    tags    = ["Dashboard"],
)
def get_stats(
    _auth: str = Depends(_require_api_key),
) -> dict[str, Any]:
    """
    Return aggregated statistics for the dashboard.

    Fields:
        total_scans        — rows in scan_history
        total_detections   — rows in detection_events
        high_risk_count    — events with risk_score = HIGH
        critical_count     — events with risk_score = CRITICAL
        active_runtimes    — active ai_inventory entries
        compliance_status  — COMPLIANT | AT RISK | NON-COMPLIANT
                             derived from unresolved HIGH/CRITICAL alert count

    **Auth**: `X-API-Key: llm-hunter-dev-key` header required.
    """
    try:
        conn = sqlite3.connect(_db.DB_PATH)
        conn.row_factory = sqlite3.Row

        def _scalar(sql: str, params: tuple = ()) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row[0]) if row and row[0] is not None else 0

        total_scans       = _scalar("SELECT COUNT(*) FROM scan_history")
        total_detections  = _scalar("SELECT COUNT(*) FROM detection_events")
        high_risk_count   = _scalar(
            "SELECT COUNT(*) FROM detection_events WHERE risk_score = ?", ("HIGH",)
        )
        critical_count    = _scalar(
            "SELECT COUNT(*) FROM detection_events WHERE risk_score = ?", ("CRITICAL",)
        )
        active_runtimes   = _scalar(
            "SELECT COUNT(*) FROM ai_inventory WHERE status = 'active'"
        )
        unresolved_high   = _scalar(
            "SELECT COUNT(*) FROM alerts WHERE resolved = 0 AND risk_level IN ('HIGH','CRITICAL')"
        )

        conn.close()

    except Exception as exc:
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail      = f"Stats query failed: {exc}",
        )

    # Compliance status derivation
    if critical_count > 0 or unresolved_high > 2:
        compliance_status = "NON-COMPLIANT"
    elif high_risk_count > 0 or unresolved_high > 0:
        compliance_status = "AT RISK"
    else:
        compliance_status = "COMPLIANT"

    return {
        "total_scans":       total_scans,
        "total_detections":  total_detections,
        "high_risk_count":   high_risk_count,
        "critical_count":    critical_count,
        "active_runtimes":   active_runtimes,
        "compliance_status": compliance_status,
    }


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@router.get(
    "/health",
    summary = "Liveness and DB connectivity check",
    tags    = ["Health"],
)
def health_check() -> dict[str, Any]:
    """
    Unauthenticated liveness probe.

    Returns `db_connected: true` when the SQLite database file is readable
    and the detection_events table exists.
    """
    db_connected = False
    try:
        conn = sqlite3.connect(_db.DB_PATH)
        conn.execute("SELECT 1 FROM detection_events LIMIT 1")
        conn.close()
        db_connected = True
    except Exception:
        pass

    return {
        "status":       "ok",
        "version":      "1.0.0",
        "db_connected": db_connected,
    }
