"""
agent/orchestrator.py
-----------------------
Agent Orchestrator for the Local LLM Hunter agent.

The central integration layer that wires every component together into a
single, end-to-end detection + response pipeline:

    Detectors (4)  →  CorrelationEngine  →  EnrichmentEngine
    →  RiskScorer  →  EventWriter  →  Alerter  →  SIEMExporter

Classes:
    AgentOrchestrator — run_full_scan(), run_daemon()
"""

from __future__ import annotations

import json
import socket
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import schedule

from rich.console import Console
from rich.panel   import Panel
from rich.text    import Text

# ---------------------------------------------------------------------------
# Project imports — all components
# ---------------------------------------------------------------------------
try:
    from agent.core.correlation_engine      import CorrelationEngine
    from agent.core.risk_scorer             import RiskScorer
    from agent.output.event_writer          import EventWriter
    from agent.output.alerter               import Alerter
    from backend.enrichment.enrichment_engine import EnrichmentEngine
    from backend.siem_exporter              import SIEMExporter
    from database                           import db as _db
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from agent.core.correlation_engine      import CorrelationEngine
    from agent.core.risk_scorer             import RiskScorer
    from agent.output.event_writer          import EventWriter
    from agent.output.alerter               import Alerter
    from backend.enrichment.enrichment_engine import EnrichmentEngine
    from backend.siem_exporter              import SIEMExporter
    from database                           import db as _db

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CFG_AGENT    = _PROJECT_ROOT / "config" / "agent_config.json"
_CFG_ENDPOINT = _PROJECT_ROOT / "config" / "endpoint_config.json"
_CFG_SIEM     = _PROJECT_ROOT / "config" / "siem_config.json"

_console = Console()

# Default scan interval if config is missing
_DEFAULT_INTERVAL_MINUTES = 5


# ---------------------------------------------------------------------------
# AgentOrchestrator
# ---------------------------------------------------------------------------

class AgentOrchestrator:
    """
    Top-level orchestrator that wires all detection and response components
    into a complete scan pipeline.

    Components initialised on construction:
        CorrelationEngine  — runs all 4 detectors and correlates signals
        EnrichmentEngine   — cross-references runtime against policy/CVE/whitelist
        RiskScorer         — converts weighted score to risk level
        EventWriter        — persists AIRuntimeEvent to DB + JSONL
        Alerter            — Rich console panel + log + DB alert insert
        SIEMExporter       — CEF UDP forwarding / fallback JSONL

    All DB operations use database/db.py which targets database/llm_hunter.db.
    """

    def __init__(self) -> None:
        """Load configs, initialise DB, and create all component instances."""
        self._agent_cfg    = self._load_json(_CFG_AGENT)
        self._endpoint_cfg = self._load_json(_CFG_ENDPOINT)
        self._siem_cfg     = self._load_json(_CFG_SIEM)

        # Ensure DB schema exists before any component tries to write
        _db.init_db()

        # Instantiate all pipeline components
        self.correlation_engine = CorrelationEngine()
        self.enrichment_engine  = EnrichmentEngine()
        self.risk_scorer        = RiskScorer()
        self.event_writer       = EventWriter()
        self.alerter            = Alerter()
        self.siem_exporter      = SIEMExporter()

    # -----------------------------------------------------------------------
    # run_full_scan
    # -----------------------------------------------------------------------

    def run_full_scan(self) -> dict[str, Any]:
        """
        Execute a complete detection → enrichment → response pipeline pass.

        Steps:
            1. Run all 4 detectors via CorrelationEngine
            2. Correlate signals and compute weighted score
            3. Check multi-signal threshold — exit early if not met
            4. Enrich detected runtime via EnrichmentEngine
            5. Compute final risk level via RiskScorer
            6. Build + persist AIRuntimeEvent via EventWriter
            7. Display alert panel + log via Alerter
            8. Forward event to SIEM (or fallback) via SIEMExporter
            9. Record scan pass in scan_history table

        Returns:
            dict with keys:
                detected    : bool   — True if multi-signal threshold was met
                risk_level  : str | None  — final risk level if detected
                event_id    : str | None  — UUID of written AIRuntimeEvent
                duration_ms : int    — total scan wall-clock time in ms
        """
        scan_start   = time.perf_counter()
        scan_time    = datetime.now(timezone.utc).isoformat()
        scan_id      = str(uuid4())
        host         = self._endpoint_cfg.get("hostname", socket.gethostname())

        _console.print(
            f"[dim][[{datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC] "
            f"Scan {scan_id[:8]}... starting[/dim]"
        )

        # -- Step 1: Run all detectors -------------------------------------
        signals = self.correlation_engine.run_all_detectors()

        # -- Step 2: Correlate signals -------------------------------------
        correlation = self.correlation_engine.correlate(signals)

        # -- Step 3: Multi-signal threshold check --------------------------
        if not self.correlation_engine.is_runtime_detected(signals):
            duration_ms = int((time.perf_counter() - scan_start) * 1000)
            _console.print(
                f"[green]  ✓ No AI runtime detected "
                f"({correlation['signal_count']} signal(s) fired, "
                f"threshold not met) — {duration_ms} ms[/green]"
            )
            self._record_scan(scan_id, host, scan_time, duration_ms, 0, correlation)
            return {
                "detected":    False,
                "risk_level":  None,
                "event_id":    None,
                "duration_ms": duration_ms,
            }

        runtime    = correlation.get("detected_runtime") or "unknown"
        model_file = correlation.get("detected_model")

        _console.print(
            f"[yellow]  ⚠ Runtime detected: {runtime} "
            f"(score={correlation['weighted_score']})[/yellow]"
        )

        # -- Step 4: Enrichment --------------------------------------------
        enrichment = self.enrichment_engine.enrich(runtime, model_file, host)

        # -- Step 5: Risk scoring ------------------------------------------
        risk_level = self.risk_scorer.compute_risk(
            correlation["weighted_score"], enrichment
        )
        action = self.risk_scorer.get_recommended_action(risk_level)

        _console.print(f"[bold]  Risk level: {risk_level} — {action}[/bold]")

        # -- Step 6: Write event (DB + JSONL) ------------------------------
        event = self.event_writer.write_event(correlation, enrichment, risk_level)

        # -- Step 7: Alert (Rich panel + log + DB alert row) ---------------
        self.alerter.alert(event)

        # -- Step 8: SIEM export -------------------------------------------
        self.siem_exporter.export_event(event)

        # -- Step 9: Record scan history -----------------------------------
        duration_ms = int((time.perf_counter() - scan_start) * 1000)
        self._record_scan(
            scan_id, host, scan_time, duration_ms,
            runtimes_found = 1,
            correlation    = correlation,
        )

        _console.print(
            f"[dim]  Scan complete in {duration_ms} ms — "
            f"event_id={event.event_id[:8]}...[/dim]"
        )

        return {
            "detected":    True,
            "risk_level":  risk_level,
            "event_id":    event.event_id,
            "duration_ms": duration_ms,
        }

    # -----------------------------------------------------------------------
    # run_daemon
    # -----------------------------------------------------------------------

    def run_daemon(self) -> None:
        """
        Start a scheduled background scan loop.

        Reads scan_interval_minutes from agent_config.json (default 5).
        Prints a startup banner and runs until a KeyboardInterrupt.

        Uses the `schedule` library — lightweight, no thread complexity.
        """
        interval = int(self._agent_cfg.get("scan_interval_minutes", _DEFAULT_INTERVAL_MINUTES))

        self._print_startup_banner(mode="daemon", interval=interval)

        # Schedule recurring scan
        schedule.every(interval).minutes.do(self.run_full_scan)

        _console.print(
            f"[green]  Daemon running — scanning every {interval} minute(s). "
            f"Press Ctrl+C to stop.[/green]\n"
        )

        # Run one scan immediately on startup
        self.run_full_scan()

        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            _console.print("\n[yellow]  Daemon stopped by user.[/yellow]")

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _record_scan(
        self,
        scan_id:        str,
        host:           str,
        scan_time:      str,
        duration_ms:    int,
        runtimes_found: int,
        correlation:    dict[str, Any],
    ) -> None:
        """Write a scan pass record to the scan_history table."""
        total_signals_fired = correlation.get("signal_count", 0)
        try:
            _db.insert_scan({
                "scan_id":             scan_id,
                "host":                host,
                "scan_time":           scan_time,
                "duration_ms":         duration_ms,
                "runtimes_found":      runtimes_found,
                "total_signals_fired": total_signals_fired,
            })
        except Exception as exc:    # noqa: BLE001
            warnings.warn(
                f"[Orchestrator] scan_history insert failed: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

    def _print_startup_banner(self, mode: str = "scan", interval: int = 5) -> None:
        """Print the branded startup panel using Rich."""
        siem_on  = self._siem_cfg.get("enabled", False)
        db_path  = str(_db.DB_PATH)
        dept     = self._endpoint_cfg.get("department", "unknown")
        host     = self._endpoint_cfg.get("hostname", socket.gethostname())
        debug    = self._agent_cfg.get("debug", False)

        body = Text()
        body.append("  Mode          : ", style="dim")
        body.append(f"{mode.upper()}\n", style="bold white")
        body.append("  Host          : ", style="dim")
        body.append(f"{host}\n")
        body.append("  Department    : ", style="dim")
        body.append(f"{dept}\n")
        body.append("  Scan interval : ", style="dim")
        body.append(f"{interval} min\n")
        body.append("  SIEM          : ", style="dim")
        body.append(
            "ENABLED\n" if siem_on else "DISABLED (fallback mode)\n",
            style="green" if siem_on else "yellow",
        )
        body.append("  Database      : ", style="dim")
        body.append(f"{db_path}\n", style="dim")
        body.append("  Debug         : ", style="dim")
        body.append(f"{debug}\n", style="dim")

        _console.print(Panel(
            body,
            title        = "[bold cyan]LOCAL LLM HUNTER v1.0 | Endpoint Shadow AI Detection[/bold cyan]",
            border_style = "cyan",
            expand       = False,
            padding      = (0, 2),
        ))

    def _load_json(self, path: Path) -> dict[str, Any]:
        """Load a JSON file into a dict. Returns {} on any error."""
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
