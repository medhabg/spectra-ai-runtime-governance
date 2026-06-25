"""
agent/output/event_writer.py
------------------------------
Event Writer for the Local LLM Hunter agent.

Responsible for constructing a fully populated AIRuntimeEvent from the
outputs of the CorrelationEngine and EnrichmentEngine, then persisting it
to two sinks:

  1. SQLite database  (database/llm_hunter.db  via database/db.py)
  2. JSONL log file   (logs/detections.jsonl   — one JSON object per line)

Classes:
    EventWriter — build_event(), write_to_db(), write_to_jsonl(), write_event()
"""

from __future__ import annotations

import getpass
import json
import socket
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# Project imports with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import AIRuntimeEvent, EnrichmentResult
    from database             import db as _db
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import AIRuntimeEvent, EnrichmentResult
    from database             import db as _db

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT       = Path(__file__).resolve().parents[2]
_CFG_AGENT          = _PROJECT_ROOT / "config" / "agent_config.json"
_CFG_ENDPOINT       = _PROJECT_ROOT / "config" / "endpoint_config.json"
_LOG_DIR            = _PROJECT_ROOT / "logs"
_DETECTIONS_JSONL   = _LOG_DIR / "detections.jsonl"


# ---------------------------------------------------------------------------
# EventWriter
# ---------------------------------------------------------------------------

class EventWriter:
    """
    Constructs AIRuntimeEvent objects from correlation + enrichment output
    and persists them to the SQLite database and a JSONL log file.

    Config loaded on init:
        config/agent_config.json   — log_path, debug flag
        config/endpoint_config.json — host, department, owner
    """

    def __init__(self) -> None:
        """Load agent and endpoint config files on construction."""
        self._agent_cfg:    dict[str, Any] = self._load_json(_CFG_AGENT)
        self._endpoint_cfg: dict[str, Any] = self._load_json(_CFG_ENDPOINT)

        # Ensure the logs directory exists
        _LOG_DIR.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # build_event
    # -----------------------------------------------------------------------

    def build_event(
        self,
        correlation_result: dict[str, Any],
        enrichment:         EnrichmentResult,
        risk_level:         str,
    ) -> AIRuntimeEvent:
        """
        Construct a complete AIRuntimeEvent from correlation and enrichment data.

        Mapping:
            correlation_result['detected_runtime'] → runtime
            correlation_result['detected_model']   → model_file
            correlation_result['signals_fired']    → signals_fired
            correlation_result['signal_count']     → signal_count
            Port signal evidence                   → port_detected
            GPU signal evidence                    → gpu_spike
            Library signal evidence                → lib_match
            enrichment.policy_violated             → policy_violation
            enrichment.has_known_cve               → vuln_flag
            enrichment.endpoint_critical           → endpoint_criticality

        Args:
            correlation_result : dict returned by CorrelationEngine.correlate()
            enrichment         : EnrichmentResult from EnrichmentEngine.enrich()
            risk_level         : Final risk string from RiskScorer.compute_risk()

        Returns:
            Fully populated AIRuntimeEvent instance.
        """
        # -- Identity fields -----------------------------------------------
        host       = self._endpoint_cfg.get("hostname", socket.gethostname())
        department = self._endpoint_cfg.get("department", "unknown")
        user_id    = self._safe_get_user()

        # -- Detection fields from correlation result ----------------------
        runtime    = correlation_result.get("detected_runtime") or "unknown"
        model_file = correlation_result.get("detected_model")
        signals_fired: dict[str, bool] = correlation_result.get("signals_fired", {})
        signal_count: int              = correlation_result.get("signal_count", 0)

        # -- Derive specific evidence from signal keys --------------------
        port_detected = self._extract_port(correlation_result)
        gpu_spike     = bool(signals_fired.get("gpu", False))
        lib_match     = self._extract_lib_match(correlation_result)

        # -- Approval status from enrichment ------------------------------
        if enrichment.model_approved:
            approval_status = "approved"
        else:
            approval_status = "unapproved"

        return AIRuntimeEvent(
            event_id             = str(uuid4()),
            host                 = host,
            runtime              = runtime,
            model_file           = model_file,
            port_detected        = port_detected,
            gpu_spike            = gpu_spike,
            lib_match            = lib_match,
            risk_score           = risk_level,
            timestamp            = datetime.now(timezone.utc).isoformat(),
            user_id              = user_id,
            department           = department,
            approval_status      = approval_status,
            policy_violation     = enrichment.policy_violated,
            vuln_flag            = enrichment.has_known_cve,
            signals_fired        = signals_fired,
            signal_count         = signal_count,
            endpoint_criticality = enrichment.endpoint_critical,
        )

    # -----------------------------------------------------------------------
    # write_to_db
    # -----------------------------------------------------------------------

    def write_to_db(self, event: AIRuntimeEvent) -> None:
        """
        Persist an AIRuntimeEvent to the SQLite detection_events table.

        Delegates to database.db.insert_event().  Emits a RuntimeWarning
        if the database write fails, but never raises — the JSONL log is
        the fallback persistence mechanism.

        Args:
            event : The AIRuntimeEvent to persist.
        """
        try:
            _db.init_db()           # Ensure tables exist (no-op if already created)
            _db.insert_event(event)
        except Exception as exc:    # noqa: BLE001
            warnings.warn(
                f"[EventWriter] DB write failed for event {event.event_id}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    # -----------------------------------------------------------------------
    # write_to_jsonl
    # -----------------------------------------------------------------------

    def write_to_jsonl(self, event: AIRuntimeEvent) -> None:
        """
        Append an AIRuntimeEvent as a single JSON line to logs/detections.jsonl.

        Creates the file (and logs/ directory) if they do not exist.
        Each line is a valid standalone JSON object — the file as a whole is
        not a JSON array, enabling efficient append-only writes.

        Args:
            event : The AIRuntimeEvent to append.
        """
        try:
            _DETECTIONS_JSONL.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event.model_dump()) + "\n"
            with _DETECTIONS_JSONL.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            warnings.warn(
                f"[EventWriter] JSONL write failed for event {event.event_id}: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    # -----------------------------------------------------------------------
    # write_event  (convenience)
    # -----------------------------------------------------------------------

    def write_event(
        self,
        correlation: dict[str, Any],
        enrichment:  EnrichmentResult,
        risk:        str,
    ) -> AIRuntimeEvent:
        """
        Convenience method: build → write_to_db → write_to_jsonl.

        Builds a complete AIRuntimeEvent and writes it to both persistence
        sinks in a single call.

        Args:
            correlation : dict from CorrelationEngine.correlate()
            enrichment  : EnrichmentResult from EnrichmentEngine.enrich()
            risk        : Risk level string from RiskScorer.compute_risk()

        Returns:
            The constructed and persisted AIRuntimeEvent.
        """
        event = self.build_event(correlation, enrichment, risk)
        self.write_to_db(event)
        self.write_to_jsonl(event)
        return event

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _load_json(self, path: Path) -> dict[str, Any]:
        """Load a JSON file and return its top-level dict. Empty dict on error."""
        if not path.exists():
            warnings.warn(
                f"[EventWriter] Config not found: {path}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            warnings.warn(
                f"[EventWriter] Failed to load {path.name}: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}

    def _safe_get_user(self) -> str:
        """Return the current OS username, or 'unknown' on permission error."""
        try:
            return getpass.getuser()
        except Exception:   # noqa: BLE001
            return "unknown"

    def _extract_port(self, correlation: dict[str, Any]) -> int | None:
        """
        Pull the detected port number from correlation result.

        The correlation dict does not directly store per-signal evidence,
        so port is inferred from the signals_fired map and the timing_note
        field. Callers that need exact port evidence should pass it explicitly
        via a future overload; this returns None as a safe default for now.
        """
        # Future extension: CorrelationEngine could store per-signal evidence
        # in the correlation dict. For now, port is stored separately by the
        # caller if needed and we return None as the safe default.
        return None

    def _extract_lib_match(self, correlation: dict[str, Any]) -> list[str]:
        """
        Extract matched library names from correlation result.

        Returns the runtime name as the single-element list when a library
        signal fired, since per-signal evidence is not forwarded through
        the correlation dict in the current architecture.
        """
        if correlation.get("signals_fired", {}).get("library", False):
            runtime = correlation.get("detected_runtime")
            return [runtime] if runtime else []
        return []
