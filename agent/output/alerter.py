"""
agent/output/alerter.py
------------------------
Alert display and logging system for the Local LLM Hunter agent.

Produces colour-coded Rich console panels for detected LLM runtime events,
writes plain-text alerts to logs/alerts.log, and inserts alert records into
the SQLite alerts table.

Risk-level colour mapping:
    LOW      → blue panel
    MEDIUM   → yellow panel
    HIGH     → red panel
    CRITICAL → red panel with bold CRITICAL header

Classes:
    Alerter — alert(), send_notification()
"""

from __future__ import annotations

import sqlite3
import warnings
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text

# ---------------------------------------------------------------------------
# Project imports with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import AIRuntimeEvent
    from database             import db as _db
    from agent.output         import siem_exporter as _siem
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import AIRuntimeEvent
    from database             import db as _db
    from agent.output         import siem_exporter as _siem

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIR      = _PROJECT_ROOT / "logs"
_ALERTS_LOG   = _LOG_DIR / "alerts.log"

# ---------------------------------------------------------------------------
# Risk-level → Rich style mapping
# ---------------------------------------------------------------------------
_RISK_STYLES: dict[str, dict] = {
    "LOW":      {"border_style": "blue",   "header": "LOW RISK DETECTION"},
    "MEDIUM":   {"border_style": "yellow", "header": "MEDIUM RISK DETECTION"},
    "HIGH":     {"border_style": "red",    "header": "HIGH RISK DETECTION"},
    "CRITICAL": {"border_style": "red",    "header": "⚠ CRITICAL — IMMEDIATE ACTION REQUIRED"},
}

# Shared Rich console (stderr=False so output goes to stdout)
_console = Console()


# ---------------------------------------------------------------------------
# Alerter
# ---------------------------------------------------------------------------

class Alerter:
    """
    Displays Rich-formatted alert panels, writes plain-text logs, and
    persists alert records to the SQLite alerts table.

    Risk-level panel styles:
        LOW      — blue border
        MEDIUM   — yellow border
        HIGH     — red border
        CRITICAL — red border, bold header
    """

    # -----------------------------------------------------------------------
    # alert
    # -----------------------------------------------------------------------

    def alert(self, event: AIRuntimeEvent) -> None:
        """
        Display a colour-coded alert panel and persist the alert record.

        Steps:
            1. Print a Rich panel to stdout (colour varies by risk_score)
            2. Append a plain-text line to logs/alerts.log
            3. Insert a row into the SQLite alerts table

        Args:
            event : The AIRuntimeEvent that triggered the alert.
        """
        risk = event.risk_score.upper()
        style_cfg = _RISK_STYLES.get(risk, _RISK_STYLES["MEDIUM"])

        # -- 1. Rich panel --------------------------------------------------
        self._print_rich_panel(event, risk, style_cfg)

        # -- 2. Plain-text log ---------------------------------------------
        self._write_alert_log(event, risk)

        # -- 3. Database insert --------------------------------------------
        self._insert_alert_db(event, risk)

        # -- 4. SIEM / Elasticsearch export --------------------------------
        self._export_to_siem(event)

    # -----------------------------------------------------------------------
    # send_notification
    # -----------------------------------------------------------------------

    def send_notification(self, event: AIRuntimeEvent) -> None:
        """
        Stub for future external notification integrations.

        Intended integration points:
            - Email (SMTP)
            - Microsoft Teams webhook
            - Slack webhook
            - PagerDuty API

        Args:
            event : The AIRuntimeEvent to notify about.
        """
        print(
            f"NOTIFICATION STUB — implement email/Teams webhook "
            f"[event_id={event.event_id}, risk={event.risk_score}]"
        )

    # -----------------------------------------------------------------------
    # Internal: Rich panel
    # -----------------------------------------------------------------------

    def _print_rich_panel(
        self,
        event:      AIRuntimeEvent,
        risk:       str,
        style_cfg:  dict,
    ) -> None:
        """
        Render and print a Rich panel to the console.

        Panel content:
            Host       — endpoint hostname
            Runtime    — detected LLM runtime name
            Model      — detected model file path (or N/A)
            Risk Level — LOW / MEDIUM / HIGH / CRITICAL
            Action     — recommended security action
            Timestamp  — event ISO-8601 UTC timestamp
        """
        border_style = style_cfg["border_style"]
        header_text  = style_cfg["header"]

        # Build the recommended action from risk level
        action_map = {
            "LOW":      "Allow with monitoring",
            "MEDIUM":   "Alert security team",
            "HIGH":     "Block and notify user",
            "CRITICAL": "Immediate block — escalate to CISO",
        }
        action = action_map.get(risk, "Review manually")

        # Compose panel body as a Rich Text object so we can style per-line
        body = Text()

        if risk == "CRITICAL":
            body.append(f"  {'Host':<14}", style="bold white")
            body.append(f": {event.host}\n")
            body.append(f"  {'Runtime':<14}", style="bold white")
            body.append(f": {event.runtime}\n")
            body.append(f"  {'Model':<14}", style="bold white")
            body.append(f": {event.model_file or 'N/A'}\n")
            body.append(f"  {'Risk Level':<14}", style="bold red")
            body.append(f": {risk}\n", style="bold red")
            body.append(f"  {'Department':<14}", style="bold white")
            body.append(f": {event.department}\n")
            body.append(f"  {'Action':<14}", style="bold red")
            body.append(f": {action}\n", style="bold red")
            body.append(f"  {'Timestamp':<14}", style="dim")
            body.append(f": {event.timestamp}\n", style="dim")
        else:
            body.append(f"  Host        : {event.host}\n")
            body.append(f"  Runtime     : {event.runtime}\n")
            body.append(f"  Model       : {event.model_file or 'N/A'}\n")
            body.append(f"  Risk Level  : {risk}\n")
            body.append(f"  Department  : {event.department}\n")
            body.append(f"  Action      : {action}\n")
            body.append(f"  Timestamp   : {event.timestamp}\n", style="dim")

        panel = Panel(
            body,
            title       = f"[bold]{header_text}[/bold]",
            border_style = border_style,
            expand      = False,
            padding     = (0, 1),
        )
        _console.print(panel)

    # -----------------------------------------------------------------------
    # Internal: plain-text log
    # -----------------------------------------------------------------------

    def _write_alert_log(self, event: AIRuntimeEvent, risk: str) -> None:
        """
        Append a plain-text alert line to logs/alerts.log.

        Format (one line per alert):
            [<timestamp>] [<RISK>] host=<host> runtime=<runtime>
            model=<model|N/A> event_id=<uuid>

        Args:
            event : The AIRuntimeEvent being alerted.
            risk  : Uppercase risk level string.
        """
        try:
            _LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts      = datetime.now(timezone.utc).isoformat()
            model   = event.model_file or "N/A"
            line    = (
                f"[{ts}] [{risk}] "
                f"host={event.host} "
                f"runtime={event.runtime} "
                f"model={model} "
                f"event_id={event.event_id}\n"
            )
            with _ALERTS_LOG.open("a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError as exc:
            warnings.warn(
                f"[Alerter] Failed to write alerts.log: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )

    # -----------------------------------------------------------------------
    # Internal: database insert
    # -----------------------------------------------------------------------

    def _insert_alert_db(self, event: AIRuntimeEvent, risk: str) -> None:
        """
        Insert a new row into the SQLite alerts table.

        Guarantees the parent detection_events row exists BEFORE the alerts
        insert so the FOREIGN KEY constraint (alerts.event_id →
        detection_events.event_id) is never violated.

        Strategy:
            1. init_db()         — ensure all tables exist
            2. insert_event()    — INSERT OR IGNORE the parent event row.
                                   Safe to call even when EventWriter already
                                   wrote it; duplicates are silently skipped.
            3. INSERT the alert  — FK constraint is now satisfied.

        Foreign key enforcement stays ON throughout. We never disable it.

        Only HIGH and CRITICAL events are persisted to the alerts table;
        LOW and MEDIUM are written to the log file only (reduces alert fatigue).

        Args:
            event : The AIRuntimeEvent being alerted.
            risk  : Uppercase risk level string.
        """
        # Only persist HIGH / CRITICAL to the alerts table
        if risk not in ("HIGH", "CRITICAL"):
            return

        try:
            # Step 1 — ensure schema exists
            _db.init_db()

            # Step 2 — guarantee the parent event row exists.
            # INSERT OR IGNORE means this is a no-op if EventWriter already
            # wrote the event; it only inserts when called standalone (e.g.
            # from the test harness) where no prior write has occurred.
            _db.insert_event(event)

            # Step 3 — insert the alert row (FK constraint now satisfied)
            alert_id   = str(uuid4())
            alerted_at = datetime.now(timezone.utc).isoformat()

            sql = """
                INSERT OR IGNORE INTO alerts
                    (alert_id, event_id, risk_level, alerted_at, resolved)
                VALUES
                    (?, ?, ?, ?, 0)
            """

            conn = sqlite3.connect(_db.DB_PATH)
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                with conn:
                    conn.execute(sql, (alert_id, event.event_id, risk, alerted_at))
            finally:
                conn.close()

        except Exception as exc:    # noqa: BLE001
            warnings.warn(
                f"[Alerter] DB alert insert failed: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )

    # -----------------------------------------------------------------------
    # Internal: SIEM / Elasticsearch export
    # -----------------------------------------------------------------------

    def _export_to_siem(self, event: AIRuntimeEvent) -> None:
        """
        POST the event to the configured Elasticsearch SIEM endpoint.

        Calls siem_exporter.export_event() which handles all network errors
        internally and writes to a fallback JSONL log when ES is unreachable.
        This method never raises — a warning is emitted on failure.

        Args:
            event : The AIRuntimeEvent to export.
        """
        try:
            ok, msg = _siem.export_event(event)
            if ok:
                print(f"[SIEMExporter] ✅ {msg} | host={event.host} runtime={event.runtime}")
            else:
                warnings.warn(
                    f"[SIEMExporter] export skipped or failed: {msg}",
                    RuntimeWarning,
                    stacklevel=3,
                )
        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"[Alerter] SIEM export raised unexpectedly: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from datetime import datetime, timezone

    print("=" * 60)
    print("  Alerter — standalone test")
    print("  Firing a synthetic HIGH severity alert...")
    print("=" * 60)

    # Build a minimal synthetic AIRuntimeEvent for the test.
    # No real detectors are run — this purely exercises the alert pipeline.
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
        signals_fired        = {
            "port": True, "file": True, "library": False, "gpu": False
        },
        signal_count         = 2,
        endpoint_criticality = False,
    )

    alerter = Alerter()

    # -- Fire the full alert (Rich panel + log file + DB insert) -----------
    alerter.alert(sample_event)

    # -- Print compact summary lines (matching expected output format) ------
    _console.print()
    _console.print("[bold red]\\[HIGH][/bold red] Shadow AI Runtime Detected")
    _console.print(f"  Runtime   : {sample_event.runtime}")
    _console.print(f"  Risk      : [red]{sample_event.risk_score}[/red]")
    _console.print(f"  Action    : Investigate and enforce policy")
    _console.print(
        f"  Timestamp : [dim]{sample_event.timestamp}[/dim]"
    )
    _console.print()

    # -- Notification stub -------------------------------------------------
    alerter.send_notification(sample_event)
