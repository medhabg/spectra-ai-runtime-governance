"""
agent/core/correlation_engine.py
----------------------------------
Correlation Engine for the Local LLM Hunter agent.

Orchestrates all four detection signals, applies weighted scoring, and
determines whether a multi-signal detection threshold has been met.

Detection signals and weights:
    port    fired                        → 1 point
    file    fired                        → 2 points
    library fired at HIGH confidence     → 2 points
    library fired at MEDIUM confidence   → 1 point
    gpu     fired                        → 1 point

Multi-signal rule: a runtime is only considered DETECTED when 2 or more
independent signals fire simultaneously.  A single signal alone is never
sufficient to trigger a confirmed detection (reduces false positives).

Classes:
    CorrelationEngine — orchestrates detectors and correlates their output

Standalone / combined test at bottom (python correlation_engine.py):
    Runs all detectors → correlates → feeds result to RiskScorer → prints.
"""

from __future__ import annotations

import time
import warnings
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Detector imports
# ---------------------------------------------------------------------------
try:
    from agent.detectors.port_detector    import PortDetector
    from agent.detectors.file_detector    import FileDetector
    from agent.detectors.library_detector import LibraryDetector
    from agent.detectors.gpu_detector     import GPUDetector
    from agent.models.schemas             import DetectionSignal
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.detectors.port_detector    import PortDetector
    from agent.detectors.file_detector    import FileDetector
    from agent.detectors.library_detector import LibraryDetector
    from agent.detectors.gpu_detector     import GPUDetector
    from agent.models.schemas             import DetectionSignal


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Orchestrates all four detectors, weights their signals, and produces a
    consolidated correlation result used by the risk scorer and DB writer.

    Signal weights (used in correlate()):
        port    fired                   = 1
        file    fired                   = 2
        library fired (HIGH confidence) = 2
        library fired (MEDIUM conf.)    = 1
        gpu     fired                   = 1
        Maximum possible score          = 6  (before CVE/policy escalation)

    Multi-signal threshold (used in is_runtime_detected()):
        ≥ 2 signals must fire for a confirmed runtime detection.
    """

    # Minimum number of fired signals required for a confirmed detection
    MULTI_SIGNAL_THRESHOLD: int = 2

    # -----------------------------------------------------------------------
    # run_all_detectors
    # -----------------------------------------------------------------------

    def run_all_detectors(self) -> dict[str, DetectionSignal]:
        """
        Instantiate and run all four detectors in sequence.

        Timing is recorded per detector and attached as a warning if any
        single detector exceeds 30 seconds.  Exceptions inside individual
        detectors are caught so one failing detector never aborts the scan.

        Returns:
            dict with keys 'port', 'file', 'library', 'gpu' mapping to
            their respective DetectionSignal instances.
        """
        detectors: dict[str, Any] = {
            "port":    PortDetector,
            "file":    FileDetector,
            "library": LibraryDetector,
            "gpu":     GPUDetector,
        }

        results: dict[str, DetectionSignal] = {}

        for signal_name, DetectorClass in detectors.items():
            t0 = time.perf_counter()
            try:
                detector = DetectorClass()
                signal   = detector.detect()
            except Exception as exc:  # noqa: BLE001
                warnings.warn(
                    f"[CorrelationEngine] Detector '{signal_name}' raised an "
                    f"unexpected error: {exc}  — returning unfired signal.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                signal = DetectionSignal(
                    signal_name = signal_name,
                    fired       = False,
                    evidence    = {"error": str(exc)},
                    timestamp   = datetime.now(timezone.utc).isoformat(),
                )

            elapsed_s = time.perf_counter() - t0
            if elapsed_s > 30:
                warnings.warn(
                    f"[CorrelationEngine] Detector '{signal_name}' took "
                    f"{elapsed_s:.1f}s (> 30 s target).",
                    RuntimeWarning,
                    stacklevel=2,
                )

            results[signal_name] = signal

        return results

    # -----------------------------------------------------------------------
    # correlate
    # -----------------------------------------------------------------------

    def correlate(self, signals: dict[str, DetectionSignal]) -> dict[str, Any]:
        """
        Apply signal weights to fired DetectionSignals and build a
        consolidated correlation summary.

        Weighting rules:
            port  fired                         → +1
            file  fired                         → +2
            library fired, HIGH conf. process   → +2
            library fired, MEDIUM conf. process → +1
            gpu   fired                         → +1

        Library confidence is derived from the highest-confidence process
        found in the library signal's evidence dict.

        Args:
            signals : dict returned by run_all_detectors()

        Returns:
            dict with keys:
                signals_fired    : dict { signal_name: bool }
                signal_count     : int  — number of signals that fired
                weighted_score   : int  — total weighted score
                detected_runtime : str | None — runtime name from port or
                                   library evidence
                detected_model   : str | None — model file path from file
                                   evidence (first match)
                timing_note      : str — summary line for logging
        """
        signals_fired: dict[str, bool] = {}
        weighted_score = 0
        signal_count   = 0

        # -- PORT -----------------------------------------------------------
        port_sig    = signals.get("port")
        port_fired  = bool(port_sig and port_sig.fired)
        signals_fired["port"] = port_fired
        if port_fired:
            weighted_score += 1
            signal_count   += 1

        # -- FILE -----------------------------------------------------------
        file_sig    = signals.get("file")
        file_fired  = bool(file_sig and file_sig.fired)
        signals_fired["file"] = file_fired
        if file_fired:
            weighted_score += 2
            signal_count   += 1

        # -- LIBRARY --------------------------------------------------------
        lib_sig     = signals.get("library")
        lib_fired   = bool(lib_sig and lib_sig.fired)
        signals_fired["library"] = lib_fired
        if lib_fired:
            lib_conf = self._get_library_top_confidence(lib_sig)
            if lib_conf == "HIGH":
                weighted_score += 2
            else:
                # MEDIUM (LOW would not have set fired=True, but guard anyway)
                weighted_score += 1
            signal_count += 1

        # -- GPU ------------------------------------------------------------
        gpu_sig    = signals.get("gpu")
        gpu_fired  = bool(gpu_sig and gpu_sig.fired)
        signals_fired["gpu"] = gpu_fired
        if gpu_fired:
            weighted_score += 1
            signal_count   += 1

        # -- Extract detected runtime name ----------------------------------
        detected_runtime = self._extract_runtime(signals)

        # -- Extract detected model file path -------------------------------
        detected_model = self._extract_model(signals)

        timing_note = (
            f"{signal_count} signal(s) fired | "
            f"weighted_score={weighted_score} | "
            f"runtime={detected_runtime or 'unknown'}"
        )

        return {
            "signals_fired":    signals_fired,
            "signal_count":     signal_count,
            "weighted_score":   weighted_score,
            "detected_runtime": detected_runtime,
            "detected_model":   detected_model,
            "timing_note":      timing_note,
        }

    # -----------------------------------------------------------------------
    # is_runtime_detected
    # -----------------------------------------------------------------------

    def is_runtime_detected(self, signals: dict[str, DetectionSignal]) -> bool:
        """
        Determine whether a confirmed runtime detection threshold is met.

        A confirmed detection requires MULTI_SIGNAL_THRESHOLD (≥ 2) independent
        signals to have fired.  A single signal alone is never sufficient.

        Args:
            signals : dict returned by run_all_detectors()

        Returns:
            True if ≥ 2 signals fired, False otherwise.
        """
        fired_count = sum(
            1 for sig in signals.values()
            if sig is not None and sig.fired
        )
        return fired_count >= self.MULTI_SIGNAL_THRESHOLD

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _get_library_top_confidence(
        self, lib_signal: DetectionSignal | None
    ) -> str:
        """
        Extract the highest confidence level from library signal evidence.

        Iterates over the 'processes' list in the library evidence and
        returns the highest confidence string found.

        Returns:
            'HIGH', 'MEDIUM', or 'LOW'.
        """
        if lib_signal is None or not lib_signal.fired:
            return "LOW"

        processes = lib_signal.evidence.get("processes", [])
        if not processes:
            return "LOW"

        # Precedence order
        priority = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top = "LOW"
        for proc in processes:
            conf = proc.get("confidence", "LOW")
            if priority.get(conf, 0) > priority.get(top, 0):
                top = conf
        return top

    def _extract_runtime(
        self, signals: dict[str, DetectionSignal]
    ) -> str | None:
        """
        Identify the PRIMARY runtime name from available evidence.

        Returns only the first/highest-priority runtime so events store a
        clean single name.  The full list is in port evidence['runtimes'].
        Priority: port evidence -> library evidence -> None.
        """
        # 1. Port evidence: return only the FIRST matched runtime
        port_sig = signals.get("port")
        if port_sig and port_sig.fired:
            runtimes_list = port_sig.evidence.get("runtimes", [])
            if runtimes_list:
                first_name = runtimes_list[0].get("runtime")
                if first_name:
                    return str(first_name)
            # Legacy flat field
            runtime = port_sig.evidence.get("runtime")
            if runtime:
                return str(runtime)

        # 2. Library evidence — use first matched library name of the highest-
        #    confidence process as a proxy for the runtime
        lib_sig = signals.get("library")
        if lib_sig and lib_sig.fired:
            processes = lib_sig.evidence.get("processes", [])
            for proc in processes:
                if proc.get("confidence") in ("HIGH", "MEDIUM"):
                    libs = proc.get("matched_libs", [])
                    if libs:
                        return str(libs[0])

        return None

    def _extract_model(
        self, signals: dict[str, DetectionSignal]
    ) -> str | None:
        """
        Extract the first detected model file path from file signal evidence.

        Returns:
            Absolute path string of the first found model file, or None.
        """
        file_sig = signals.get("file")
        if file_sig and file_sig.fired:
            files_found = file_sig.evidence.get("files_found", [])
            if files_found:
                return files_found[0].get("path")
        return None


# ---------------------------------------------------------------------------
# Combined standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    # Risk scorer import (same project, handles sys.path via its own fallback)
    try:
        from agent.core.risk_scorer    import RiskScorer
        from agent.models.schemas      import EnrichmentResult
    except ImportError:
        from pathlib import Path
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from agent.core.risk_scorer    import RiskScorer
        from agent.models.schemas      import EnrichmentResult

    print("=" * 65)
    print("  CorrelationEngine + RiskScorer — combined test")
    print("=" * 65)

    engine = CorrelationEngine()

    # 1. Run all detectors ---------------------------------------------------
    print("\n[1/3] Running all detectors...")
    t_start  = time.perf_counter()
    signals  = engine.run_all_detectors()
    t_total  = time.perf_counter() - t_start
    print(f"      Completed in {t_total:.2f} s")

    for name, sig in signals.items():
        status = "FIRED ✓" if sig.fired else "clear"
        print(f"      {name:<10} → {status}")

    # 2. Correlate -----------------------------------------------------------
    print("\n[2/3] Correlating signals...")
    correlation = engine.correlate(signals)
    print(json.dumps(correlation, indent=2))

    detected = engine.is_runtime_detected(signals)
    print(f"\n  Runtime confirmed: {'YES ⚠' if detected else 'NO (below multi-signal threshold)'}")

    # 3. Risk scoring --------------------------------------------------------
    print("\n[3/3] Computing risk score...")

    # Use a default (no-CVE, no-policy) EnrichmentResult for the standalone test
    enrichment = EnrichmentResult(
        model_approved   = False,
        has_known_cve    = False,
        policy_violated  = correlation["signal_count"] >= 2,
        endpoint_critical = False,
    )

    scorer     = RiskScorer()
    risk_level = scorer.compute_risk(correlation["weighted_score"], enrichment)
    action     = scorer.get_recommended_action(risk_level)

    print(f"\n  Weighted score   : {correlation['weighted_score']}")
    print(f"  Risk level       : {risk_level}")
    print(f"  Recommended action: {action}")
    print("\n" + "=" * 65)
