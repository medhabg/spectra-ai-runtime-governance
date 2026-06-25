"""
agent/output/siem_exporter.py
------------------------------
Elasticsearch SIEM Exporter for Local LLM Hunter.

Posts detection events to a local Elasticsearch instance as structured
JSON documents.  Reads endpoint and toggle from config/siem_config.json.

Public API:
    export_event(event)   → (success: bool, message: str)
    check_connection()    → (connected: bool, message: str)
    SIEM_EXPORTER_ENABLED → bool  (mirrors config["enabled"])

Elasticsearch target (default):
    http://localhost:9200/llm-hunter-events/_doc

No authentication is required for the default local dev setup.
"""

from __future__ import annotations

import json
import uuid
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

import requests

if TYPE_CHECKING:
    from agent.models.schemas import AIRuntimeEvent

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SIEM_CFG_PATH = _PROJECT_ROOT / "config" / "siem_config.json"

_RISK_SCORE_MAP: dict[str, int] = {
    "LOW": 2,
    "MEDIUM": 5,
    "HIGH": 7,
    "CRITICAL": 10,
}


def _load_config() -> dict[str, Any]:
    """Load siem_config.json, returning safe defaults on any error."""
    try:
        return json.loads(_SIEM_CFG_PATH.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {
            "enabled": False,
            "siem_endpoint": "http://localhost:9200/llm-hunter-events/_doc",
            "timeout_seconds": 3,
            "fallback_log_file": "./logs/siem_fallback.jsonl",
        }


# Module-level flag — re-evaluated on each import / reload
_cfg = _load_config()
SIEM_EXPORTER_ENABLED: bool = bool(_cfg.get("enabled", False))
_ENDPOINT: str = _cfg.get("siem_endpoint", "http://localhost:9200/llm-hunter-events/_doc")
_TIMEOUT: int = int(_cfg.get("timeout_seconds", 3))
_FALLBACK_LOG: Path = _PROJECT_ROOT / _cfg.get(
    "fallback_log_file", "./logs/siem_fallback.jsonl"
).lstrip("./")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_payload(event: "AIRuntimeEvent") -> dict[str, Any]:
    """
    Convert an AIRuntimeEvent into the Elasticsearch document schema.

    Schema:
        @timestamp  — ISO-8601 UTC (Elasticsearch standard field)
        host        — endpoint hostname
        runtime     — detected LLM runtime name
        risk_level  — LOW / MEDIUM / HIGH / CRITICAL
        risk_score  — numeric 1-10 (LOW=2, MEDIUM=5, HIGH=7, CRITICAL=10)
        port        — detected port number (int or null)
        model       — model file path (string or null)
        alert_id    — fresh UUID for this SIEM record
        source      — always "llm-hunter"
    """
    risk_label = str(getattr(event, "risk_score", "MEDIUM")).upper()
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "host":       str(getattr(event, "host",        "unknown")),
        "runtime":    str(getattr(event, "runtime",     "unknown")),
        "risk_level": risk_label,
        "risk_score": _RISK_SCORE_MAP.get(risk_label, 5),
        "port":       getattr(event, "port_detected", None),
        "model":      getattr(event, "model_file",    None),
        "alert_id":   str(uuid.uuid4()),
        "source":     "llm-hunter",
    }


def _write_fallback(payload: dict[str, Any]) -> None:
    """Append payload as JSONL to the fallback log when ES is unreachable."""
    try:
        _FALLBACK_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _FALLBACK_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except OSError as exc:
        warnings.warn(
            f"[SIEMExporter] Fallback log write failed: {exc}",
            RuntimeWarning,
            stacklevel=3,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_event(event: "AIRuntimeEvent") -> tuple[bool, str]:
    """
    POST a detection event to the configured Elasticsearch endpoint.

    Always safe to call — never raises; failures are logged as warnings
    and written to the JSONL fallback log.

    Args:
        event: AIRuntimeEvent from the detection pipeline.

    Returns:
        (True,  "Connected — event indexed")       on HTTP 2xx
        (False, "<reason>")                        on any failure
    """
    # Reload config each call so live config changes take effect without restart
    cfg = _load_config()
    if not cfg.get("enabled", False):
        return False, "SIEM exporter disabled"

    endpoint = cfg.get("siem_endpoint", _ENDPOINT)
    timeout  = int(cfg.get("timeout_seconds", _TIMEOUT))
    payload  = _build_payload(event)

    try:
        resp = requests.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return True, f"Connected — event indexed (HTTP {resp.status_code})"

    except requests.exceptions.ConnectionError:
        msg = "Elasticsearch unreachable — wrote to fallback log"
        warnings.warn(f"[SIEMExporter] {msg}", RuntimeWarning, stacklevel=2)
        _write_fallback(payload)
        return False, msg

    except requests.exceptions.Timeout:
        msg = f"Elasticsearch timed out after {timeout}s — wrote to fallback log"
        warnings.warn(f"[SIEMExporter] {msg}", RuntimeWarning, stacklevel=2)
        _write_fallback(payload)
        return False, msg

    except requests.exceptions.HTTPError as exc:
        msg = f"Elasticsearch HTTP error: {exc}"
        warnings.warn(f"[SIEMExporter] {msg}", RuntimeWarning, stacklevel=2)
        _write_fallback(payload)
        return False, msg

    except Exception as exc:  # noqa: BLE001
        msg = f"SIEM export failed: {exc}"
        warnings.warn(f"[SIEMExporter] {msg}", RuntimeWarning, stacklevel=2)
        _write_fallback(payload)
        return False, msg


def check_connection() -> tuple[bool, str]:
    """
    Probe the Elasticsearch cluster health endpoint.

    Hits GET http://localhost:9200/_cluster/health (or configured host root).
    Used by the dashboard to set the SIEM status pill.

    Returns:
        (True,  "Connected")    if Elasticsearch responds with HTTP 2xx
        (False, "<reason>")     otherwise
    """
    cfg      = _load_config()
    endpoint = cfg.get("siem_endpoint", _ENDPOINT)
    timeout  = int(cfg.get("timeout_seconds", _TIMEOUT))

    # Derive cluster health URL from the index endpoint
    # e.g. http://localhost:9200/llm-hunter-events/_doc → http://localhost:9200
    try:
        from urllib.parse import urlparse
        parsed  = urlparse(endpoint)
        base    = f"{parsed.scheme}://{parsed.netloc}"
        health  = f"{base}/_cluster/health"
        resp    = requests.get(health, timeout=timeout)
        if resp.status_code < 400:
            return True, "Connected"
        return False, f"HTTP {resp.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Not connected"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  SIEMExporter — connection check")
    print("=" * 60)

    ok, msg = check_connection()
    status  = "✅ CONNECTED" if ok else "❌ OFFLINE"
    print(f"  Elasticsearch: {status}")
    print(f"  Detail       : {msg}")
    print(f"  Endpoint     : {_ENDPOINT}")
    print(f"  Enabled      : {SIEM_EXPORTER_ENABLED}")
    print("=" * 60)
