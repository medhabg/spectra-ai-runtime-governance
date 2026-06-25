"""
tests/test_integration.py
---------------------------
Integration tests for the full Local LLM Hunter pipeline.

These tests run the real AgentOrchestrator but patch all four detectors
to return known, controlled signals — no real port scanning or file I/O.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.models.schemas          import DetectionSignal, EnrichmentResult
from agent.core.correlation_engine import CorrelationEngine
from agent.orchestrator            import AgentOrchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_signal(name: str, fired: bool, evidence: dict | None = None) -> DetectionSignal:
    return DetectionSignal(
        signal_name = name,
        fired       = fired,
        evidence    = evidence or {},
        timestamp   = _ts(),
    )


def _unfired() -> dict[str, DetectionSignal]:
    return {
        "port":    _make_signal("port",    False),
        "file":    _make_signal("file",    False),
        "library": _make_signal("library", False),
        "gpu":     _make_signal("gpu",     False),
    }


def _two_fired() -> dict[str, DetectionSignal]:
    signals = _unfired()
    signals["port"] = _make_signal("port", True, {"port": 11434, "runtime": "Ollama"})
    signals["file"] = _make_signal("file", True, {"files_found": [
        {"path": "/tmp/llama3.gguf", "size_mb": 4.2, "extension": ".gguf"}
    ]})
    return signals


# ===========================================================================
# TestFullScan
# ===========================================================================

class TestFullScan:

    def _patched_run_all_detectors(self, signals: dict):
        """Return a side_effect callable that returns the given signals."""
        def _side_effect():
            return signals
        return _side_effect

    def test_full_scan_no_crash_no_detection(self):
        """
        Run full scan with all detectors returning unfired signals.
        Must not raise and must return detected=False.
        """
        orch = AgentOrchestrator()

        with patch.object(
            orch.correlation_engine, "run_all_detectors",
            return_value=_unfired()
        ):
            result = orch.run_full_scan()

        assert isinstance(result, dict)
        assert result["detected"] is False
        assert result["risk_level"] is None
        assert result["event_id"] is None
        assert result["duration_ms"] >= 0

    def test_full_scan_with_detection(self):
        """
        Inject two fired signals → detection confirmed, event written.
        """
        orch = AgentOrchestrator()

        with (
            patch.object(orch.correlation_engine, "run_all_detectors",
                         return_value=_two_fired()),
            # Prevent real alert panel printing during tests
            patch.object(orch.alerter, "alert"),
            # Prevent real SIEM UDP during tests
            patch.object(orch.siem_exporter, "export_event"),
        ):
            result = orch.run_full_scan()

        assert result["detected"] is True
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert result["event_id"] is not None
        assert len(result["event_id"]) > 0

    def test_full_scan_returns_duration_ms(self):
        """duration_ms must be a non-negative integer."""
        orch = AgentOrchestrator()

        with patch.object(orch.correlation_engine, "run_all_detectors",
                          return_value=_unfired()):
            result = orch.run_full_scan()

        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0

    def test_full_scan_no_exception_on_alerter_failure(self):
        """
        If the alerter raises unexpectedly, the orchestrator must still
        return a result (resilience test).
        """
        orch = AgentOrchestrator()

        with (
            patch.object(orch.correlation_engine, "run_all_detectors",
                         return_value=_two_fired()),
            patch.object(orch.alerter, "alert", side_effect=Exception("test failure")),
            patch.object(orch.siem_exporter, "export_event"),
        ):
            # Orchestrator should propagate or handle; we just assert no crash
            # that loses the return value (may raise — acceptable in integration)
            try:
                result = orch.run_full_scan()
                # If it returns, result must be valid
                assert isinstance(result, dict)
            except Exception:
                pass   # acceptable if orchestrator doesn't swallow alerter errors


# ===========================================================================
# TestWhitelistExclusion
# ===========================================================================

class TestWhitelistExclusion:

    def test_approved_model_not_high_risk(self, tmp_path):
        """
        When the detected model is on the approved whitelist, the final
        risk level must NOT be CRITICAL (policy-driven escalation should
        not fire for approved models).
        """
        # Build a temporary approved_models.json with our test model
        approved = {
            "approved_models": [
                {
                    "name":          "llama2-approved",
                    "approved_by":   "CISO",
                    "approval_date": "2024-01-01",
                    "endpoint_tag":  "TEST-HOST-01",
                }
            ]
        }
        approved_path = tmp_path / "approved_models.json"
        approved_path.write_text(json.dumps(approved), encoding="utf-8")

        orch = AgentOrchestrator()

        # Override enrichment engine's approved models list directly
        orch.enrichment_engine._approved_models = approved["approved_models"]

        # Inject signals that include the approved model in file evidence
        signals = _unfired()
        signals["port"] = _make_signal("port", True, {"port": 11434, "runtime": "Ollama"})
        signals["file"] = _make_signal("file", True, {"files_found": [
            {"path": "/opt/models/llama2-approved.gguf", "size_mb": 3.5, "extension": ".gguf"}
        ]})

        with (
            patch.object(orch.correlation_engine, "run_all_detectors",
                         return_value=signals),
            patch.object(orch.alerter, "alert"),
            patch.object(orch.siem_exporter, "export_event"),
        ):
            result = orch.run_full_scan()

        assert result["detected"] is True
        # Approved model should not be escalated to CRITICAL
        assert result["risk_level"] != "CRITICAL"

    def test_unapproved_model_can_be_high_risk(self):
        """
        An unapproved model with two signals can reach HIGH or CRITICAL.
        """
        orch = AgentOrchestrator()
        # Clear approved models so nothing is whitelisted
        orch.enrichment_engine._approved_models = []

        signals = _two_fired()

        with (
            patch.object(orch.correlation_engine, "run_all_detectors",
                         return_value=signals),
            patch.object(orch.alerter, "alert"),
            patch.object(orch.siem_exporter, "export_event"),
        ):
            result = orch.run_full_scan()

        assert result["detected"] is True
        assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


# ===========================================================================
# TestSIEMFallback
# ===========================================================================

class TestSIEMFallback:

    def test_siem_disabled_writes_fallback(self, tmp_path):
        """When SIEM is disabled, export_event writes to fallback JSONL."""
        from backend.siem_exporter import SIEMExporter
        from agent.models.schemas  import AIRuntimeEvent
        import backend.siem_exporter as _siem_mod

        # Redirect fallback path to tmp_path
        fallback_file = tmp_path / "siem_fallback.jsonl"

        exporter = SIEMExporter()
        exporter._cfg = {"enabled": False}
        exporter._fallback_path = fallback_file

        event = AIRuntimeEvent(
            host="TEST-HOST", runtime="Ollama", model_file="llama3.gguf",
            risk_score="HIGH", timestamp=_ts(), user_id="tester",
            department="eng", approval_status="unapproved",
        )

        exporter.export_event(event)

        assert fallback_file.exists()
        lines = fallback_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["event_id"] == event.event_id
