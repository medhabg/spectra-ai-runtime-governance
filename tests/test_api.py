"""
tests/test_api.py
------------------
FastAPI endpoint tests using TestClient (no real network calls).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.api.main import app

CLIENT  = TestClient(app, raise_server_exceptions=False)
HEADERS = {"X-API-Key": "llm-hunter-dev-key"}


def _event_payload(**overrides) -> dict:
    base = {
        "host":                "TEST-HOST-01",
        "runtime":             "Ollama",
        "model_file":          "llama3.gguf",
        "port_detected":       11434,
        "gpu_spike":           False,
        "lib_match":           ["ollama"],
        "risk_score":          "HIGH",
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "user_id":             "test-user",
        "department":          "engineering",
        "approval_status":     "unapproved",
        "policy_violation":    True,
        "vuln_flag":           False,
        "signals_fired":       {"port": True, "file": True, "library": False, "gpu": False},
        "signal_count":        2,
        "endpoint_criticality": False,
    }
    base.update(overrides)
    return base


# ===========================================================================
# Health endpoint (unauthenticated)
# ===========================================================================

class TestHealthEndpoint:

    def test_health_returns_200(self):
        r = CLIENT.get("/health")
        assert r.status_code == 200

    def test_health_status_ok(self):
        r = CLIENT.get("/health")
        data = r.json()
        assert data["status"] == "ok"

    def test_health_version(self):
        r = CLIENT.get("/health")
        assert r.json()["version"] == "1.0.0"

    def test_health_db_connected_field_present(self):
        r = CLIENT.get("/health")
        assert "db_connected" in r.json()

    def test_health_no_auth_required(self):
        """Health endpoint must be reachable without API key."""
        r = CLIENT.get("/health")
        assert r.status_code != 401
        assert r.status_code != 422


# ===========================================================================
# POST /api/events
# ===========================================================================

class TestPostEvent:

    def test_post_event_success(self):
        r = CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        assert r.status_code == 201

    def test_post_event_returns_event_id(self):
        r = CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        data = r.json()
        assert data["status"] == "received"
        assert "event_id" in data
        assert len(data["event_id"]) > 0

    def test_post_event_custom_id_preserved(self):
        payload = _event_payload(event_id="fixed-uuid-1234")
        r = CLIENT.post("/api/events", json=payload, headers=HEADERS)
        assert r.status_code == 201
        assert r.json()["event_id"] == "fixed-uuid-1234"

    def test_unauthorized_no_key_rejected(self):
        """POST without X-API-Key → 422 (missing required header)."""
        r = CLIENT.post("/api/events", json=_event_payload())
        assert r.status_code in (401, 422)

    def test_unauthorized_wrong_key_rejected(self):
        """POST with wrong API key → 401."""
        r = CLIENT.post("/api/events", json=_event_payload(),
                        headers={"X-API-Key": "wrong-key"})
        assert r.status_code == 401

    def test_invalid_payload_rejected(self):
        """POST with missing required fields → 422."""
        r = CLIENT.post("/api/events", json={"host": "only-host"},
                        headers=HEADERS)
        assert r.status_code == 422


# ===========================================================================
# GET /api/events
# ===========================================================================

class TestGetEvents:

    def test_get_events_empty_db(self):
        """GET /api/events on empty DB → 200 with empty list."""
        r = CLIENT.get("/api/events", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_events_after_insert(self):
        """Posted event appears in GET /api/events response."""
        CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        r = CLIENT.get("/api/events", headers=HEADERS)
        assert r.status_code == 200
        events = r.json()
        assert len(events) >= 1

    def test_get_events_risk_filter(self):
        """?risk_level=HIGH filters correctly."""
        CLIENT.post("/api/events", json=_event_payload(risk_score="HIGH"),  headers=HEADERS)
        CLIENT.post("/api/events", json=_event_payload(risk_score="LOW"),   headers=HEADERS)
        r = CLIENT.get("/api/events?risk_level=HIGH", headers=HEADERS)
        events = r.json()
        assert all(e["risk_score"].upper() == "HIGH" for e in events)

    def test_get_events_limit_param(self):
        """?limit=1 returns at most 1 event."""
        CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        r = CLIENT.get("/api/events?limit=1", headers=HEADERS)
        assert len(r.json()) <= 1

    def test_get_events_unauthorized(self):
        r = CLIENT.get("/api/events")
        assert r.status_code in (401, 422)


# ===========================================================================
# GET /api/stats
# ===========================================================================

class TestGetStats:

    def test_get_stats_returns_200(self):
        r = CLIENT.get("/api/stats", headers=HEADERS)
        assert r.status_code == 200

    def test_get_stats_has_required_fields(self):
        r = CLIENT.get("/api/stats", headers=HEADERS)
        data = r.json()
        for field in ("total_detections", "high_risk_count",
                      "critical_count", "active_runtimes", "compliance_status"):
            assert field in data, f"Missing field: {field}"

    def test_get_stats_compliance_status_valid(self):
        r = CLIENT.get("/api/stats", headers=HEADERS)
        status = r.json()["compliance_status"]
        assert status in ("COMPLIANT", "AT RISK", "NON-COMPLIANT")

    def test_get_stats_counts_increase_after_insert(self):
        before = CLIENT.get("/api/stats", headers=HEADERS).json()["total_detections"]
        CLIENT.post("/api/events", json=_event_payload(), headers=HEADERS)
        after  = CLIENT.get("/api/stats", headers=HEADERS).json()["total_detections"]
        assert after == before + 1


# ===========================================================================
# GET /api/alerts + PATCH /api/alerts/{id}/resolve
# ===========================================================================

class TestAlerts:

    def test_get_alerts_returns_list(self):
        r = CLIENT.get("/api/alerts", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_resolve_nonexistent_alert_returns_404(self):
        r = CLIENT.patch("/api/alerts/nonexistent-id/resolve", headers=HEADERS)
        assert r.status_code == 404

    def test_resolve_unauthorized(self):
        r = CLIENT.patch("/api/alerts/some-id/resolve")
        assert r.status_code in (401, 422)


# ===========================================================================
# GET /api/inventory
# ===========================================================================

class TestInventory:

    def test_get_inventory_returns_list(self):
        r = CLIENT.get("/api/inventory", headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_inventory_unauthorized(self):
        r = CLIENT.get("/api/inventory")
        assert r.status_code in (401, 422)
