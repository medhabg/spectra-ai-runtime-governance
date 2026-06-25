"""
agent/main.py
--------------
CLI entry point for the Local LLM Hunter agent.

Usage:
    python agent/main.py scan       — Run one full detection scan immediately
    python agent/main.py status     — Show last scan and last detection event
    python agent/main.py inventory  — Show active AI runtime inventory table
    python agent/main.py alerts     — Show unresolved alerts table
    python agent/main.py daemon     — Start scheduled background scanning
    python agent/main.py test-siem  — Test SIEM connection

All commands display the startup banner first.
Tabular output is rendered using Rich's Table.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path when run as 'python agent/main.py'
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text

from agent.orchestrator import AgentOrchestrator
from backend.siem_exporter import SIEMExporter
from database import db as _db

_console = Console()


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------

def _print_banner(agent_cfg: dict, endpoint_cfg: dict, siem_cfg: dict) -> None:
    """Print the branded startup panel with current configuration."""
    body = Text()
    body.append("  Host          : ", style="dim")
    body.append(f"{endpoint_cfg.get('hostname', socket.gethostname())}\n")
    body.append("  Department    : ", style="dim")
    body.append(f"{endpoint_cfg.get('department', 'unknown')}\n")
    body.append("  Scan interval : ", style="dim")
    body.append(f"{agent_cfg.get('scan_interval_minutes', 5)} min\n")
    body.append("  SIEM          : ", style="dim")
    siem_on = siem_cfg.get("enabled", False)
    body.append(
        "ENABLED\n" if siem_on else "DISABLED (fallback mode)\n",
        style="green" if siem_on else "yellow",
    )
    body.append("  Database      : ", style="dim")
    body.append(f"{_db.DB_PATH}\n", style="dim")
    body.append("  Debug         : ", style="dim")
    body.append(f"{agent_cfg.get('debug', False)}\n", style="dim")

    _console.print(Panel(
        body,
        title        = "[bold cyan]LOCAL LLM HUNTER v1.0  |  Endpoint Shadow AI Detection[/bold cyan]",
        border_style = "cyan",
        expand       = False,
        padding      = (0, 2),
    ))
    _console.print()


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def _cmd_scan(orchestrator: AgentOrchestrator) -> None:
    """Run a single full detection scan and print the result."""
    _console.print("[bold]Running full scan...[/bold]\n")
    result = orchestrator.run_full_scan()

    _console.print()
    if result["detected"]:
        _console.print(
            f"[bold red]  DETECTION CONFIRMED[/bold red]\n"
            f"  Risk Level : [bold]{result['risk_level']}[/bold]\n"
            f"  Event ID   : {result['event_id']}\n"
            f"  Duration   : {result['duration_ms']} ms"
        )
    else:
        _console.print(
            f"[bold green]  No unauthorised AI runtime detected.[/bold green]\n"
            f"  Duration   : {result['duration_ms']} ms"
        )


def _cmd_status(orchestrator: AgentOrchestrator) -> None:
    """Show the last scan record and the most recent detection event."""
    _console.print("[bold]Scan history (last 5):[/bold]")

    # -- Last scans from scan_history --------------------------------------
    try:
        conn = __import__("sqlite3").connect(_db.DB_PATH)
        conn.row_factory = __import__("sqlite3").Row
        scans = conn.execute(
            "SELECT * FROM scan_history ORDER BY scan_time DESC LIMIT 5"
        ).fetchall()
        conn.close()
    except Exception:
        scans = []

    if scans:
        tbl = Table(show_header=True, header_style="bold cyan")
        tbl.add_column("Scan ID",      style="dim",    max_width=10)
        tbl.add_column("Host")
        tbl.add_column("Scan Time",    max_width=25)
        tbl.add_column("Duration ms",  justify="right")
        tbl.add_column("Runtimes",     justify="right")
        tbl.add_column("Signals",      justify="right")

        for s in scans:
            tbl.add_row(
                str(s["scan_id"])[:8] + "…",
                s["host"],
                s["scan_time"],
                str(s["duration_ms"]),
                str(s["runtimes_found"]),
                str(s["total_signals_fired"]),
            )
        _console.print(tbl)
    else:
        _console.print("  [dim]No scan history found. Run: python agent/main.py scan[/dim]")

    # -- Last detection event ----------------------------------------------
    _console.print("\n[bold]Last detection event:[/bold]")
    events = _db.get_all_events()
    if events:
        e = events[0]
        _console.print(
            f"  Event ID  : {e.get('event_id','?')}\n"
            f"  Host      : {e.get('host','?')}\n"
            f"  Runtime   : {e.get('runtime','?')}\n"
            f"  Risk      : [bold]{e.get('risk_score','?')}[/bold]\n"
            f"  Timestamp : [dim]{e.get('timestamp','?')}[/dim]"
        )
    else:
        _console.print("  [dim]No detection events in database.[/dim]")


def _cmd_inventory(orchestrator: AgentOrchestrator) -> None:
    """Display the active AI runtime inventory as a Rich table."""
    inventory = _db.get_active_inventory()

    _console.print("[bold]Active AI Runtime Inventory:[/bold]\n")

    if not inventory:
        _console.print("  [dim]No active runtimes in inventory.[/dim]")
        return

    tbl = Table(show_header=True, header_style="bold cyan")
    tbl.add_column("Host")
    tbl.add_column("Runtime",    style="bold")
    tbl.add_column("Model File", max_width=35)
    tbl.add_column("Last Seen",  max_width=25)
    tbl.add_column("Status")

    for row in inventory:
        status_style = "green" if row.get("status") == "active" else "dim"
        tbl.add_row(
            row.get("host",        "?"),
            row.get("runtime",     "?"),
            row.get("model_file") or "N/A",
            row.get("last_seen",   "?"),
            Text(row.get("status", "?"), style=status_style),
        )
    _console.print(tbl)


def _cmd_alerts(orchestrator: AgentOrchestrator) -> None:
    """Display unresolved alerts as a Rich table."""
    alerts = _db.get_alerts(unresolved_only=True)

    _console.print("[bold]Unresolved Alerts:[/bold]\n")

    if not alerts:
        _console.print("  [green]✓ No unresolved alerts.[/green]")
        return

    tbl = Table(show_header=True, header_style="bold red")
    tbl.add_column("Alert ID",   style="dim",  max_width=10)
    tbl.add_column("Event ID",   style="dim",  max_width=10)
    tbl.add_column("Risk Level", style="bold")
    tbl.add_column("Alerted At", max_width=25)
    tbl.add_column("Resolved",   justify="center")

    for a in alerts:
        risk = a.get("risk_level", "?")
        risk_style = "bold red" if risk in ("HIGH", "CRITICAL") else "yellow"
        tbl.add_row(
            str(a.get("alert_id", "?"))[:8] + "…",
            str(a.get("event_id", "?"))[:8] + "…",
            Text(risk, style=risk_style),
            a.get("alerted_at", "?"),
            "✓" if a.get("resolved") else "✗",
        )
    _console.print(tbl)


def _cmd_daemon(orchestrator: AgentOrchestrator) -> None:
    """Start the scheduled background scan daemon."""
    orchestrator.run_daemon()


def _cmd_test_siem(_orchestrator: AgentOrchestrator) -> None:
    """Test connectivity to the configured SIEM endpoint."""
    _console.print("[bold]Testing SIEM connection...[/bold]\n")
    exporter = SIEMExporter()
    success  = exporter.test_siem_connection()
    _console.print()
    if success:
        _console.print("[green]  ✓ SIEM connection test passed.[/green]")
    else:
        _console.print("[yellow]  ✗ SIEM unavailable — fallback mode active.[/yellow]")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog        = "local-llm-hunter",
        description = "Local LLM Hunter — Endpoint Shadow AI Detection Agent",
    )
    parser.add_argument(
        "command",
        choices = ["scan", "status", "inventory", "alerts", "daemon", "test-siem"],
        help    = (
            "scan       : Run one full scan immediately\n"
            "status     : Show last scan and last detection\n"
            "inventory  : Show active AI runtime inventory\n"
            "alerts     : Show unresolved alerts\n"
            "daemon     : Start scheduled background scanning\n"
            "test-siem  : Test SIEM connection"
        ),
    )

    args = parser.parse_args()

    # Load configs for the banner
    def _load(p: Path) -> dict:
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except Exception:
            return {}

    agent_cfg    = _load(_PROJECT_ROOT / "config" / "agent_config.json")
    endpoint_cfg = _load(_PROJECT_ROOT / "config" / "endpoint_config.json")
    siem_cfg     = _load(_PROJECT_ROOT / "config" / "siem_config.json")

    # Print startup banner (except for daemon which prints its own)
    if args.command != "daemon":
        _print_banner(agent_cfg, endpoint_cfg, siem_cfg)

    # Initialise orchestrator (inits DB, all components)
    orchestrator = AgentOrchestrator()

    # Dispatch command
    commands = {
        "scan":      _cmd_scan,
        "status":    _cmd_status,
        "inventory": _cmd_inventory,
        "alerts":    _cmd_alerts,
        "daemon":    _cmd_daemon,
        "test-siem": _cmd_test_siem,
    }

    commands[args.command](orchestrator)
    _console.print()


if __name__ == "__main__":
    main()
