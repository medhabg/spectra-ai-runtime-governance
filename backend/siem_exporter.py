"""
backend/siem_exporter.py
--------------------------
SIEM Exporter for the Local LLM Hunter agent.

Forwards AIRuntimeEvent records to a syslog-compatible SIEM receiver
over UDP using the CEF (Common Event Format) standard.

When the SIEM is disabled or unreachable, events are written to a local
JSONL fallback file (logs/siem_fallback.jsonl) to ensure no event is lost.

CEF format used:
    CEF:0|LocalLLMHunter|EndpointAgent|1.0|<risk_level>|
    AI Runtime Detected|<severity_int>|
    host=<host> runtime=<runtime> model=<model> risk=<risk_score>

Severity mapping (CEF integer 0-10):
    LOW      → 3
    MEDIUM   → 5
    HIGH     → 8
    CRITICAL → 10

Config loaded from: config/siem_config.json
Fallback log:       logs/siem_fallback.jsonl
Position tracker:   logs/.siem_offset  (for export_from_jsonl dedup)

Classes:
    SIEMExporter — export_event(), fallback_export(),
                   export_from_jsonl(), test_siem_connection()
"""

from __future__ import annotations

import json
import socket
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project imports with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import AIRuntimeEvent
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from agent.models.schemas import AIRuntimeEvent

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT       = Path(__file__).resolve().parents[1]
_CFG_SIEM           = _PROJECT_ROOT / "config" / "siem_config.json"
_LOG_DIR            = _PROJECT_ROOT / "logs"
_DETECTIONS_JSONL   = _LOG_DIR / "detections.jsonl"
_FALLBACK_JSONL     = _LOG_DIR / "siem_fallback.jsonl"
_OFFSET_FILE        = _LOG_DIR / ".siem_offset"   # tracks last forwarded line

# CEF severity integers (0–10 scale)
_CEF_SEVERITY: dict[str, int] = {
    "LOW":      3,
    "MEDIUM":   5,
    "HIGH":     8,
    "CRITICAL": 10,
}

# UDP socket timeout in seconds
_SOCKET_TIMEOUT = 5


# ---------------------------------------------------------------------------
# SIEMExporter
# ---------------------------------------------------------------------------

class SIEMExporter:
    """
    Exports AIRuntimeEvent records to a syslog/SIEM receiver over UDP
    using Common Event Format (CEF), with a local JSONL fallback.

    Config keys read from siem_config.json:
        enabled          : bool   — if False, skip UDP and use fallback
        host             : str    — SIEM receiver IP / hostname
        port             : int    — UDP port (typically 514)
        protocol         : str    — 'udp' (TCP not yet supported)
        fallback_log_file: str    — path override for fallback JSONL
    """

    def __init__(self) -> None:
        """Load SIEM config from config/siem_config.json on construction."""
        self._cfg: dict[str, Any] = self._load_config()

        # Resolve fallback path — config may override the default
        fallback_override = self._cfg.get("fallback_log_file")
        if fallback_override:
            self._fallback_path = _PROJECT_ROOT / fallback_override
        else:
            self._fallback_path = _FALLBACK_JSONL

        _LOG_DIR.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # export_event
    # -----------------------------------------------------------------------

    def export_event(self, event: AIRuntimeEvent) -> None:
        """
        Export a single AIRuntimeEvent to the SIEM or fallback log.

        Flow:
            1. If siem_config.enabled is False  → fallback_export() and return
            2. Build a CEF-formatted syslog message
            3. Send via UDP to configured host:port
            4. On any network error             → warn + fallback_export()

        CEF format:
            CEF:0|LocalLLMHunter|EndpointAgent|1.0|<risk>|
            AI Runtime Detected|<severity_int>|
            host=<host> runtime=<runtime> model=<model> risk=<risk_score>

        Args:
            event : The AIRuntimeEvent to export.
        """
        if not self._cfg.get("enabled", False):
            self.fallback_export(event)
            return

        cef_message = self._build_cef(event)

        try:
            self._send_udp(cef_message)
        except OSError as exc:
            warnings.warn(
                f"[SIEMExporter] UDP send failed ({exc}) — "
                f"falling back to local log for event {event.event_id}",
                RuntimeWarning,
                stacklevel=2,
            )
            self.fallback_export(event)

    # -----------------------------------------------------------------------
    # fallback_export
    # -----------------------------------------------------------------------

    def fallback_export(self, event: AIRuntimeEvent) -> None:
        """
        Write an AIRuntimeEvent as a JSON line to the fallback JSONL log.

        Called when:
          - SIEM is disabled (siem_config.enabled = false)
          - UDP delivery to the SIEM fails

        Also prints a notice so operators are aware events are buffered locally.

        Args:
            event : The AIRuntimeEvent to write to the fallback log.
        """
        try:
            self._fallback_path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(event.model_dump()) + "\n"
            with self._fallback_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            print(
                f"SIEM offline — event written to fallback log "
                f"[event_id={event.event_id}]"
            )
        except OSError as exc:
            warnings.warn(
                f"[SIEMExporter] Fallback write failed: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    # -----------------------------------------------------------------------
    # export_from_jsonl
    # -----------------------------------------------------------------------

    def export_from_jsonl(self) -> int:
        """
        Batch-forward unprocessed lines from logs/detections.jsonl to the SIEM.

        Uses a byte-offset tracker stored in logs/.siem_offset to avoid
        re-sending events that were already forwarded in a previous run.
        The offset is updated atomically after each successful send so a
        crash mid-batch resumes from the last safe position on next start.

        Returns:
            Number of events successfully forwarded in this batch.
        """
        if not _DETECTIONS_JSONL.exists():
            print("[SIEMExporter] detections.jsonl not found — nothing to forward.")
            return 0

        # Read the last byte offset we forwarded up to
        last_offset = self._read_offset()
        current_size = _DETECTIONS_JSONL.stat().st_size

        if last_offset >= current_size:
            print("[SIEMExporter] No new events since last export.")
            return 0

        forwarded = 0

        try:
            with _DETECTIONS_JSONL.open("r", encoding="utf-8") as fh:
                fh.seek(last_offset)

                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        data  = json.loads(raw_line)
                        event = AIRuntimeEvent(**data)
                        self.export_event(event)
                        forwarded += 1
                        # Update offset after each successful export
                        self._write_offset(fh.tell())
                    except (json.JSONDecodeError, TypeError, ValueError) as exc:
                        warnings.warn(
                            f"[SIEMExporter] Skipping malformed JSONL line: {exc}",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                        continue

        except OSError as exc:
            warnings.warn(
                f"[SIEMExporter] Failed to read detections.jsonl: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

        print(f"[SIEMExporter] Batch export complete — {forwarded} event(s) forwarded.")
        return forwarded

    # -----------------------------------------------------------------------
    # test_siem_connection
    # -----------------------------------------------------------------------

    def test_siem_connection(self) -> bool:
        """
        Send a test message to the configured SIEM endpoint.

        Prints the connection outcome clearly so operators can validate
        SIEM connectivity before deploying the agent.

        Returns:
            True  — test message delivered successfully.
            False — SIEM is disabled, or UDP send raised an error.
        """
        if not self._cfg.get("enabled", False):
            print("[SIEMExporter] SIEM is disabled in siem_config.json — skipping connection test.")
            return False

        host = self._cfg.get("host", "127.0.0.1")
        port = int(self._cfg.get("port", 514))
        test_payload = (
            f"CEF:0|LocalLLMHunter|EndpointAgent|1.0|TEST|"
            f"SIEM Connection Test|0|"
            f"msg=LocalLLMHunter connectivity check "
            f"ts={datetime.now(timezone.utc).isoformat()}"
        )

        try:
            self._send_udp(test_payload)
            print(
                f"[SIEMExporter] ✓ Connection test PASSED — "
                f"test message sent to {host}:{port}"
            )
            return True
        except OSError as exc:
            print(
                f"[SIEMExporter] ✗ Connection test FAILED — "
                f"{host}:{port} unreachable: {exc}"
            )
            return False

    # -----------------------------------------------------------------------
    # Internal: CEF builder
    # -----------------------------------------------------------------------

    def _build_cef(self, event: AIRuntimeEvent) -> str:
        """
        Construct a CEF-formatted syslog message string for the given event.

        CEF specification:
            CEF:Version|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extension

        Args:
            event : The AIRuntimeEvent to serialise as CEF.

        Returns:
            CEF string suitable for transmission over syslog UDP.
        """
        risk      = event.risk_score.upper()
        severity  = _CEF_SEVERITY.get(risk, 5)
        model_val = event.model_file or "N/A"

        # CEF extension — key=value pairs (spaces separate pairs)
        # Values containing spaces or = are not escaped here for readability;
        # a production implementation should apply full CEF escaping.
        extension = (
            f"host={event.host} "
            f"runtime={event.runtime} "
            f"model={model_val} "
            f"risk={event.risk_score} "
            f"dept={event.department} "
            f"user={event.user_id} "
            f"signals={event.signal_count} "
            f"vuln={int(event.vuln_flag)} "
            f"policy_violation={int(event.policy_violation)} "
            f"event_id={event.event_id} "
            f"ts={event.timestamp}"
        )

        return (
            f"CEF:0|LocalLLMHunter|EndpointAgent|1.0|{risk}|"
            f"AI Runtime Detected|{severity}|{extension}"
        )

    # -----------------------------------------------------------------------
    # Internal: UDP send
    # -----------------------------------------------------------------------

    def _send_udp(self, message: str) -> None:
        """
        Send a UTF-8 encoded string to the configured SIEM via UDP.

        Args:
            message : Plain-text message to transmit.

        Raises:
            OSError : on any socket-level error (caller handles the fallback).
        """
        host    = self._cfg.get("host", "127.0.0.1")
        port    = int(self._cfg.get("port", 514))
        payload = message.encode("utf-8")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SOCKET_TIMEOUT)
            sock.sendto(payload, (host, port))

    # -----------------------------------------------------------------------
    # Internal: config loader
    # -----------------------------------------------------------------------

    def _load_config(self) -> dict[str, Any]:
        """Load siem_config.json. Returns empty dict on any error."""
        if not _CFG_SIEM.exists():
            warnings.warn(
                f"[SIEMExporter] siem_config.json not found at {_CFG_SIEM}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}
        try:
            return json.loads(_CFG_SIEM.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            warnings.warn(
                f"[SIEMExporter] Failed to parse siem_config.json: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}

    # -----------------------------------------------------------------------
    # Internal: offset tracker helpers
    # -----------------------------------------------------------------------

    def _read_offset(self) -> int:
        """Return the last-forwarded byte offset, or 0 if no tracker exists."""
        if not _OFFSET_FILE.exists():
            return 0
        try:
            return int(_OFFSET_FILE.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            return 0

    def _write_offset(self, offset: int) -> None:
        """Persist the current byte offset to the tracker file."""
        try:
            _OFFSET_FILE.write_text(str(offset), encoding="utf-8")
        except OSError as exc:
            warnings.warn(
                f"[SIEMExporter] Failed to write offset file: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    print("=" * 65)
    print("  SIEMExporter — standalone test")
    print("  Running with siem_enabled=False (fallback mode)")
    print("=" * 65)

    # Build a synthetic HIGH event (no real scan needed)
    sample_event = AIRuntimeEvent(
        host                 = "ENDPOINT-042",
        runtime              = "Ollama",
        model_file           = "llama3.gguf",
        port_detected        = 11434,
        gpu_spike            = False,
        lib_match            = ["ollama"],
        risk_score           = "HIGH",
        timestamp            = datetime.now(timezone.utc).isoformat(),
        user_id              = "test-user",
        department           = "engineering",
        approval_status      = "unapproved",
        policy_violation     = True,
        vuln_flag            = False,
        signals_fired        = {"port": True, "file": True, "library": False, "gpu": False},
        signal_count         = 2,
        endpoint_criticality = False,
    )

    exporter = SIEMExporter()

    # 1. Confirm SIEM is disabled (per siem_config.json default)
    siem_on = exporter._cfg.get("enabled", False)
    print(f"\n[1] SIEM enabled   : {siem_on}")
    print(f"    Fallback path  : {exporter._fallback_path}")

    # 2. Export (should route to fallback since enabled=false)
    print("\n[2] Calling export_event()...")
    exporter.export_event(sample_event)

    # 3. Verify fallback file was written
    print("\n[3] Verifying fallback file...")
    if exporter._fallback_path.exists():
        lines = exporter._fallback_path.read_text(encoding="utf-8").strip().splitlines()
        last_line = json.loads(lines[-1]) if lines else {}
        print(f"    Fallback lines : {len(lines)}")
        print(f"    Last event_id  : {last_line.get('event_id', 'N/A')}")
        print(f"    Last runtime   : {last_line.get('runtime', 'N/A')}")
        print(f"    Last risk      : {last_line.get('risk_score', 'N/A')}")
        print("    ✓ Fallback file written correctly.")
    else:
        print("    ✗ Fallback file NOT found — check write permissions.")

    # 4. CEF preview (what would be sent to the SIEM)
    print("\n[4] CEF message preview:")
    print("   ", exporter._build_cef(sample_event))

    # 5. Connection test (should report SIEM disabled)
    print("\n[5] test_siem_connection():")
    exporter.test_siem_connection()

    print("\n" + "=" * 65)
