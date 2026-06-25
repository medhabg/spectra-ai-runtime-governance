"""
agent/core/risk_scorer.py
--------------------------
Risk Scorer for the Local LLM Hunter agent.

Converts a weighted correlation score (produced by CorrelationEngine) into
a human-readable risk level string, then applies enrichment escalation rules
to account for CVE status, policy violations, and endpoint criticality.

Risk level thresholds (base score):
    LOW      : 1 – 2
    MEDIUM   : 3 – 4
    HIGH     : 5 – 6
    CRITICAL : 7+

Escalation rules (applied after base threshold):
    has_known_cve AND endpoint_critical  → escalate to CRITICAL
    policy_violated                      → escalate to at least HIGH

Classes:
    RiskScorer — exposes compute_risk() and get_recommended_action()
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# EnrichmentResult import with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import EnrichmentResult
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import EnrichmentResult


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Converts a weighted signal score into a risk level string and determines
    the recommended security response action.

    Scoring is a two-stage process:
      1. Derive a base risk level from the weighted_score thresholds.
      2. Escalate the level based on EnrichmentResult flags.

    Attributes:
        THRESHOLDS : dict mapping risk level strings to their minimum score.
        LEVEL_ORDER: ordered list of risk levels from lowest to highest,
                     used for escalation comparisons.
    """

    THRESHOLDS: dict[str, int] = {
        "LOW":      1,
        "MEDIUM":   3,
        "HIGH":     5,
        "CRITICAL": 7,
    }

    # Ordered from lowest to highest for escalation logic
    LEVEL_ORDER: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # -----------------------------------------------------------------------
    # compute_risk
    # -----------------------------------------------------------------------

    def compute_risk(
        self,
        weighted_score: int,
        enrichment: EnrichmentResult,
    ) -> str:
        """
        Compute the final risk level for a detection event.

        Stage 1 — Base risk from weighted_score:
            score 0       → not detected (caller should check is_runtime_detected)
            score 1–2     → LOW
            score 3–4     → MEDIUM
            score 5–6     → HIGH
            score 7+      → CRITICAL

        Stage 2 — Escalation rules:
            Rule A: has_known_cve AND endpoint_critical → CRITICAL
                    (a vulnerable model running on a critical endpoint is an
                    immediate threat regardless of signal count)
            Rule B: policy_violated → at least HIGH
                    (any policy breach must be treated as high severity)

        Args:
            weighted_score : Integer score from CorrelationEngine.correlate()
            enrichment     : EnrichmentResult from the enrichment layer

        Returns:
            Final risk level string: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
        """
        # Stage 1: derive base level from score
        base_level = self._score_to_level(weighted_score)

        # Stage 2: apply escalation rules
        final_level = self._apply_escalation(base_level, enrichment)

        return final_level

    # -----------------------------------------------------------------------
    # get_recommended_action
    # -----------------------------------------------------------------------

    def get_recommended_action(self, risk_level: str) -> str:
        """
        Return the recommended security action for a given risk level.

        Actions:
            LOW      : 'Allow with monitoring'
            MEDIUM   : 'Alert security team'
            HIGH     : 'Block and notify user'
            CRITICAL : 'Immediate block — escalate to CISO'

        Args:
            risk_level : One of 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'.

        Returns:
            Action string. Falls back to 'Unknown risk level — manual review'
            for any unrecognised input.
        """
        actions: dict[str, str] = {
            "LOW":      "Allow with monitoring",
            "MEDIUM":   "Alert security team",
            "HIGH":     "Block and notify user",
            "CRITICAL": "Immediate block — escalate to CISO",
        }
        return actions.get(risk_level.upper(), "Unknown risk level — manual review")

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _score_to_level(self, score: int) -> str:
        """
        Map a raw weighted score to a base risk level.

        Uses the THRESHOLDS dict; iterates from highest to lowest so the
        first matching threshold wins.

        Args:
            score : Non-negative integer weighted score.

        Returns:
            Risk level string.
        """
        if score <= 0:
            return "LOW"  # No signals fired — treated as lowest risk

        # Iterate levels from highest to lowest
        for level in reversed(self.LEVEL_ORDER):
            if score >= self.THRESHOLDS[level]:
                return level

        return "LOW"

    def _apply_escalation(
        self,
        base_level: str,
        enrichment: EnrichmentResult,
    ) -> str:
        """
        Apply escalation rules on top of the base risk level.

        Escalation only ever increases the risk level — it never decreases it.

        Rules (evaluated in priority order):
            Rule A (highest priority):
                enrichment.has_known_cve AND enrichment.endpoint_critical
                → force CRITICAL
            Rule B:
                enrichment.policy_violated
                → escalate to at least HIGH

        Args:
            base_level : Risk level derived from the weighted score.
            enrichment : EnrichmentResult from the enrichment layer.

        Returns:
            Escalated (or unchanged) risk level string.
        """
        current = base_level

        # Rule B — policy violation → at least HIGH
        if enrichment.policy_violated:
            current = self._max_level(current, "HIGH")

        # Rule A — known CVE on a critical endpoint → CRITICAL
        # Evaluated last so it can override Rule B's result if needed
        if enrichment.has_known_cve and enrichment.endpoint_critical:
            current = "CRITICAL"

        return current

    def _max_level(self, level_a: str, level_b: str) -> str:
        """
        Return whichever of the two risk levels is higher.

        Args:
            level_a : First risk level string.
            level_b : Second risk level string.

        Returns:
            The higher of the two levels.
        """
        idx_a = self.LEVEL_ORDER.index(level_a) if level_a in self.LEVEL_ORDER else 0
        idx_b = self.LEVEL_ORDER.index(level_b) if level_b in self.LEVEL_ORDER else 0
        return self.LEVEL_ORDER[max(idx_a, idx_b)]
