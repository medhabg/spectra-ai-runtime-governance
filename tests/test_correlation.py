"""
tests/test_correlation.py
---------------------------
Unit tests for CorrelationEngine and RiskScorer.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.core.correlation_engine import CorrelationEngine
from agent.core.risk_scorer        import RiskScorer
from agent.models.schemas          import DetectionSignal, EnrichmentResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_signal(name: str, fired: bool, evidence: dict | None = None) -> DetectionSignal:
    return DetectionSignal(
        signal_name = name,
        fired       = fired,
        evidence    = evidence or {},
        timestamp   = datetime.now(timezone.utc).isoformat(),
    )


def _unfired_signals() -> dict[str, DetectionSignal]:
    """Return a dict of all four signals in the unfired state."""
    return {
        "port":    _make_signal("port",    fired=False),
        "file":    _make_signal("file",    fired=False),
        "library": _make_signal("library", fired=False),
        "gpu":     _make_signal("gpu",     fired=False),
    }


# ===========================================================================
# TestCorrelationEngine
# ===========================================================================

class TestCorrelationEngine:

    def setup_method(self):
        self.engine = CorrelationEngine()

    # --- is_runtime_detected -----------------------------------------------

    def test_single_signal_not_detected(self):
        """Only port fired (1 signal) → below multi-signal threshold → False."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True,
                                       evidence={"port": 11434, "runtime": "Ollama"})

        assert self.engine.is_runtime_detected(signals) is False

    def test_two_signals_detected(self):
        """Port + file both fired (2 signals) → meets threshold → True."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True,
                                       evidence={"port": 11434, "runtime": "Ollama"})
        signals["file"] = _make_signal("file", fired=True,
                                       evidence={"files_found": [{"path": "/tmp/test.gguf"}]})

        assert self.engine.is_runtime_detected(signals) is True

    def test_three_signals_detected(self):
        """Three signals fired → definitely above threshold → True."""
        signals = _unfired_signals()
        signals["port"]    = _make_signal("port",    fired=True)
        signals["file"]    = _make_signal("file",    fired=True)
        signals["library"] = _make_signal("library", fired=True,
                                          evidence={"processes": [{"confidence": "HIGH"}]})

        assert self.engine.is_runtime_detected(signals) is True

    def test_no_signals_not_detected(self):
        """Zero signals fired → False."""
        signals = _unfired_signals()
        assert self.engine.is_runtime_detected(signals) is False

    # --- correlate / weighted_score ----------------------------------------

    def test_weighted_score_file_only(self):
        """File fired = 2 points."""
        signals = _unfired_signals()
        signals["file"] = _make_signal("file", fired=True,
                                       evidence={"files_found": [{"path": "/tmp/x.gguf"}]})

        result = self.engine.correlate(signals)
        assert result["weighted_score"] == 2

    def test_weighted_score_port_only(self):
        """Port fired = 1 point."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True,
                                       evidence={"port": 11434, "runtime": "Ollama"})

        result = self.engine.correlate(signals)
        assert result["weighted_score"] == 1

    def test_weighted_score_file_plus_library_high(self):
        """File (2) + Library HIGH (2) = 4 points."""
        signals = _unfired_signals()
        signals["file"]    = _make_signal("file", fired=True,
                                          evidence={"files_found": [{"path": "/tmp/m.gguf"}]})
        signals["library"] = _make_signal("library", fired=True,
                                          evidence={"processes": [
                                              {"pid": 1, "name": "ollama",
                                               "matched_libs": ["ollama"], "confidence": "HIGH"}
                                          ]})

        result = self.engine.correlate(signals)
        assert result["weighted_score"] == 4

    def test_weighted_score_all_signals(self):
        """Port(1) + File(2) + Library HIGH(2) + GPU(1) = 6 points."""
        signals = {
            "port":    _make_signal("port",    fired=True,
                                    evidence={"port": 11434, "runtime": "Ollama"}),
            "file":    _make_signal("file",    fired=True,
                                    evidence={"files_found": [{"path": "/tmp/x.gguf"}]}),
            "library": _make_signal("library", fired=True,
                                    evidence={"processes": [{"confidence": "HIGH"}]}),
            "gpu":     _make_signal("gpu",     fired=True,
                                    evidence={"gpu_util": 80}),
        }
        result = self.engine.correlate(signals)
        assert result["weighted_score"] == 6

    def test_signal_count_correct(self):
        """signal_count reflects number of fired signals, not weighted score."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True)
        signals["file"] = _make_signal("file", fired=True)

        result = self.engine.correlate(signals)
        assert result["signal_count"] == 2

    def test_detected_runtime_from_port_evidence(self):
        """detected_runtime is pulled from port evidence when available."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True,
                                       evidence={"port": 11434, "runtime": "Ollama"})
        signals["file"] = _make_signal("file", fired=True,
                                       evidence={"files_found": [{"path": "/tmp/m.gguf"}]})

        result = self.engine.correlate(signals)
        assert result.get("detected_runtime") is not None
        assert "ollama" in str(result["detected_runtime"]).lower()

    def test_detected_model_from_file_evidence(self):
        """detected_model is pulled from file evidence."""
        signals = _unfired_signals()
        signals["port"] = _make_signal("port", fired=True)
        signals["file"] = _make_signal("file", fired=True,
                                       evidence={"files_found": [
                                           {"path": "/home/user/llama3.gguf",
                                            "size_mb": 4.2, "extension": ".gguf"}
                                       ]})

        result = self.engine.correlate(signals)
        assert result.get("detected_model") is not None


# ===========================================================================
# TestRiskScorer
# ===========================================================================

class TestRiskScorer:

    def setup_method(self):
        self.scorer = RiskScorer()

    def _enrichment(
        self,
        cve: bool = False,
        policy: bool = False,
        critical: bool = False,
    ) -> EnrichmentResult:
        return EnrichmentResult(
            model_approved=False, has_known_cve=cve, cve_id="CVE-2024-001" if cve else None,
            policy_violated=policy, violated_rule="POL-001" if policy else None,
            endpoint_critical=critical, runtime_name="Ollama",
            risk_category="Local LLM Runtime", known_ports=[11434],
            vendor="Ollama, Inc.", threat_level="HIGH",
            recommendation="Investigate", summary="test",
        )

    def test_low_score_returns_low(self):
        """Score 0-1 → LOW."""
        level = self.scorer.compute_risk(1, self._enrichment())
        assert level == "LOW"

    def test_medium_score_returns_medium(self):
        """Score 2 → MEDIUM."""
        level = self.scorer.compute_risk(2, self._enrichment())
        assert level == "MEDIUM"

    def test_high_score_returns_high(self):
        """Score 3+ → HIGH (without escalation triggers)."""
        level = self.scorer.compute_risk(3, self._enrichment())
        assert level in ("HIGH", "CRITICAL")   # may already be CRITICAL at 3

    def test_risk_escalation_with_cve_and_critical_endpoint(self):
        """
        score=3 + has_known_cve=True + endpoint_critical=True → CRITICAL.
        This tests the monotonic escalation rule in RiskScorer.
        """
        level = self.scorer.compute_risk(
            3, self._enrichment(cve=True, critical=True)
        )
        assert level == "CRITICAL"

    def test_policy_violation_escalates_to_high(self):
        """A policy violation must push risk level to at least HIGH."""
        # Start with a score that would normally be MEDIUM
        level = self.scorer.compute_risk(2, self._enrichment(policy=True))
        assert level in ("HIGH", "CRITICAL")

    def test_escalation_is_monotonic(self):
        """Risk level can only increase, never decrease, during escalation."""
        base_level   = self.scorer.compute_risk(4, self._enrichment())
        escal_level  = self.scorer.compute_risk(4, self._enrichment(cve=True, critical=True))

        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert order.index(escal_level) >= order.index(base_level)

    def test_recommended_action_non_empty(self):
        """get_recommended_action() returns a non-empty string for all levels."""
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            action = self.scorer.get_recommended_action(level)
            assert isinstance(action, str) and len(action) > 0
