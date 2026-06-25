"""
agent/detectors/port_detector.py
---------------------------------
Port-based detector for the Local LLM Hunter agent.

Scans all active TCP connections on the endpoint and checks whether any
local port matches a known LLM runtime's default listening port.

Detected runtimes and their default ports:
    Ollama    : 11434
    LM Studio : 1234, 1235
    GPT4All   : 4891, 4892
    Jan       : 1337
    KoboldCpp : 5001
    LMDeploy  : 23333
    llama.cpp : 8080
    LocalAI   : 8080

Classes:
    PortDetector — main detector; exposes detect() and get_runtime_from_port()

Standalone test (python port_detector.py):
    Runs detect() and prints the result as JSON.
"""

from __future__ import annotations

import json
import socket
import warnings
from datetime import datetime, timezone

import psutil

# Import the shared signal schema.
# Works when the project root is on sys.path (e.g. via 'python -m' or pytest).
try:
    from agent.models.schemas import DetectionSignal
except ImportError:
    # Fallback for running the file directly from its own directory.
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import DetectionSignal


# ---------------------------------------------------------------------------
# PortDetector
# ---------------------------------------------------------------------------

class PortDetector:
    """
    Detects known LLM runtime API endpoints by scanning active TCP connections.

    Uses psutil.net_connections() to enumerate all open connections and
    cross-references local ports against KNOWN_PORTS.  Handles permission
    errors gracefully on both Windows and Linux.

    Attributes:
        KNOWN_PORTS : dict mapping each known LLM port (int) to its runtime
                      name (str).
    """

    # -----------------------------------------------------------------------
    # Known LLM runtime default API ports
    # -----------------------------------------------------------------------
    KNOWN_PORTS: dict[int, str] = {
        11434: "Ollama",
        1234:  "LM Studio",
        1235:  "LM Studio",
        4891:  "GPT4All",
        4892:  "GPT4All",
        1337:  "Jan",
        5001:  "KoboldCpp",
        8080:  "llama.cpp / LocalAI",
        23333: "LMDeploy",
    }

    # -----------------------------------------------------------------------
    # detect
    # -----------------------------------------------------------------------

    def detect(self) -> DetectionSignal:
        """
        Scan active TCP connections for known LLM runtime ports.

        Iterates over all network connections visible to the current process.
        Collects ALL connections whose local port matches a known LLM port
        and returns them together in a single signal — so multiple simultaneous
        runtimes (e.g. Ollama + GPT4All + LM Studio) are all captured in one
        scan pass.

        Evidence fields (when fired=True):
            runtimes          : list of dicts, each containing:
                port              : int  — matched local port number
                runtime           : str  — name of the matched LLM runtime
                status            : str  — connection status (e.g. 'LISTEN')
                pid               : int | None — PID of the owning process
                local_address     : str  — local IP:port string
                port_bypass_possible : bool — True if ESTABLISHED

        For backwards compatibility, the top-level evidence also exposes
        the first match's port/runtime/status/pid/local_address fields.

        Returns:
            DetectionSignal with fired=True if any match is found,
            fired=False with empty evidence otherwise.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            # Retrieve all TCP connections. 'tcp' covers both IPv4 and IPv6
            # on Linux; on Windows psutil may require elevated privileges for
            # PID resolution but still returns port information.
            connections = psutil.net_connections(kind="tcp")

        except psutil.AccessDenied:
            warnings.warn(
                "[PortDetector] Access denied while calling psutil.net_connections(). "
                "Run as administrator / root for full port visibility.",
                RuntimeWarning,
                stacklevel=2,
            )
            return DetectionSignal(
                signal_name="port_scan",
                fired=False,
                evidence={},
                timestamp=timestamp,
            )

        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"[PortDetector] Unexpected error during net_connections(): {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
            return DetectionSignal(
                signal_name="port_scan",
                fired=False,
                evidence={},
                timestamp=timestamp,
            )

        # ------------------------------------------------------------------
        # Collect ALL matching connections — do NOT stop at first match.
        # Multiple LLM runtimes can run simultaneously (Ollama + GPT4All
        # + LM Studio), and stopping early silently misses the rest.
        # ------------------------------------------------------------------
        seen_ports: set[int] = set()    # deduplicate by port
        matched_runtimes: list[dict] = []

        for conn in connections:
            try:
                if not conn.laddr:
                    continue

                local_port: int = conn.laddr.port
                if local_port in seen_ports:
                    continue  # already captured this port

                runtime_name = self.get_runtime_from_port(local_port)
                if runtime_name is None:
                    continue

                seen_ports.add(local_port)

                local_ip    = conn.laddr.ip
                conn_status = conn.status or "UNKNOWN"
                pid         = conn.pid
                port_bypass_possible = (conn_status == "ESTABLISHED")

                matched_runtimes.append({
                    "port":                 local_port,
                    "runtime":              runtime_name,
                    "status":               conn_status,
                    "pid":                  pid,
                    "local_address":        f"{local_ip}:{local_port}",
                    "port_bypass_possible": port_bypass_possible,
                })

            except Exception as inner_exc:  # noqa: BLE001
                warnings.warn(
                    f"[PortDetector] Skipping connection entry due to error: {inner_exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue

        if not matched_runtimes:
            return DetectionSignal(
                signal_name="port_scan",
                fired=False,
                evidence={},
                timestamp=timestamp,
            )

        # Build evidence — expose all runtimes plus first-match shortcuts
        # for backwards compatibility with consumers that read top-level fields.
        first = matched_runtimes[0]
        evidence: dict = {
            # Backwards-compat flat fields from the first match
            "port":                 first["port"],
            "runtime":              first["runtime"],
            "status":               first["status"],
            "pid":                  first["pid"],
            "local_address":        first["local_address"],
            "port_bypass_possible": first["port_bypass_possible"],
            # Full list of all detected runtimes
            "runtimes":             matched_runtimes,
        }

        return DetectionSignal(
            signal_name="port_scan",
            fired=True,
            evidence=evidence,
            timestamp=timestamp,
        )

    # -----------------------------------------------------------------------
    # get_runtime_from_port
    # -----------------------------------------------------------------------

    def get_runtime_from_port(self, port: int) -> str | None:
        """
        Look up the LLM runtime name associated with a given TCP port.

        Args:
            port : Local TCP port number to look up.

        Returns:
            Runtime name string (e.g. 'Ollama') if the port is in
            KNOWN_PORTS, or None if it is not a recognised LLM port.
        """
        return self.KNOWN_PORTS.get(port)


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  PortDetector — standalone test")
    print("  Scanning active TCP connections for known LLM ports...")
    print("=" * 60)

    detector = PortDetector()
    result: DetectionSignal = detector.detect()

    # Pretty-print the DetectionSignal as JSON
    print(json.dumps(result.model_dump(), indent=2))

    if result.fired:
        runtime = result.evidence.get("runtime", "Unknown")
        port    = result.evidence.get("port", "?")
        print(f"\n[!] ALERT — {runtime} detected on port {port}")
    else:
        print("\n[OK] No known LLM runtime ports detected.")
