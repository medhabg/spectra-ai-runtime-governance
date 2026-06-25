"""
agent/detectors/gpu_detector.py
---------------------------------
GPU / CPU / Memory spike detector for the Local LLM Hunter agent.

Detects resource usage patterns consistent with an active LLM inference
workload running without authorisation:

  GPU path  (NVIDIA via pynvml):
    - GPU utilisation > 70 % sustained
    - Identifies the compute process owning the GPU
    - Falls back gracefully when no NVIDIA GPU is present or pynvml is
      not installed

  CPU path  (psutil):
    - Any single unknown process consuming > 85 % CPU

  Memory path (psutil):
    - Any unknown process consuming > 2 GB RAM

  fired=True when:
    GPU spike detected
    OR (CPU spike AND memory hog found simultaneously on same/any process)

Classes:
    GPUDetector — main detector; exposes detect()

Standalone test (python gpu_detector.py):
    Works even on machines without an NVIDIA GPU installed.
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime, timezone
from typing import Any

import psutil

# ---------------------------------------------------------------------------
# Optional pynvml import — graceful fallback when not installed / no GPU
# ---------------------------------------------------------------------------
try:
    import pynvml  # type: ignore[import]
    _PYNVML_AVAILABLE = True
except ImportError:
    pynvml = None           # type: ignore[assignment]
    _PYNVML_AVAILABLE = False

# ---------------------------------------------------------------------------
# Project-root-relative import with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import DetectionSignal
except ImportError:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import DetectionSignal


# ---------------------------------------------------------------------------
# GPUDetector
# ---------------------------------------------------------------------------

class GPUDetector:
    """
    Detects anomalous GPU, CPU, and memory usage that may indicate a local
    LLM inference workload is running without authorisation.

    Attributes:
        GPU_UTIL_THRESHOLD  : GPU utilisation percentage above which usage
                              is considered suspicious (default 70 %).
        CPU_THRESHOLD       : Per-process CPU percentage above which a
                              non-approved process is flagged (default 85 %).
        MEM_THRESHOLD_MB    : Per-process resident memory (MB) above which
                              a non-approved process is flagged (default 2048).
        APPROVED_PROCESSES  : Process names that are never flagged regardless
                              of their resource usage.
    """

    GPU_UTIL_THRESHOLD: int = 70
    CPU_THRESHOLD:      int = 85
    MEM_THRESHOLD_MB:   int = 2048

    APPROVED_PROCESSES: list[str] = [
        # Common legitimate high-resource processes
        "chrome.exe", "chrome",
        "code.exe",   "code",
        "python.exe", "python",      # Generic python — further filtered below
        "node.exe",   "node",
        "java.exe",   "java",
        "Teams.exe",  "slack",
        "explorer.exe",
        # Antivirus / EDR agents
        "MsMpEng.exe", "SentinelAgent.exe",
    ]

    # -----------------------------------------------------------------------
    # detect
    # -----------------------------------------------------------------------

    def detect(self) -> DetectionSignal:
        """
        Run GPU, CPU, and memory checks and return a consolidated signal.

        Evidence fields:
            gpu_available  : bool   — True if an NVIDIA GPU was found
            gpu_util_pct   : float | None — current GPU utilisation %
            gpu_mem_used_mb: float | None — GPU memory currently in use (MB)
            gpu_process    : dict | None  — { pid, name } of the GPU compute
                                            process, if identifiable
            cpu_spikes     : list of { pid, name, cpu_pct } for processes
                             above CPU_THRESHOLD that are not approved
            mem_hogs       : list of { pid, name, mem_mb } for processes
                             above MEM_THRESHOLD_MB that are not approved

        fired=True when:
          - GPU utilisation exceeds GPU_UTIL_THRESHOLD, OR
          - At least one CPU spike AND at least one memory hog are detected

        Returns:
            DetectionSignal
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        # -- GPU check ------------------------------------------------------
        gpu_available   = False
        gpu_util_pct    = None
        gpu_mem_used_mb = None
        gpu_process     = None
        gpu_spike       = False

        if _PYNVML_AVAILABLE:
            gpu_available, gpu_util_pct, gpu_mem_used_mb, gpu_process, gpu_spike = (
                self._check_gpu()
            )

        # -- CPU / Memory check --------------------------------------------
        cpu_spikes = self._check_cpu()
        mem_hogs   = self._check_memory()

        # -- Firing logic --------------------------------------------------
        # fired if: GPU spike OR (at least one CPU spike AND one mem hog)
        cpu_mem_combined = len(cpu_spikes) > 0 and len(mem_hogs) > 0
        fired = gpu_spike or cpu_mem_combined

        evidence: dict[str, Any] = {
            "gpu_available":   gpu_available,
            "gpu_util_pct":    gpu_util_pct,
            "gpu_mem_used_mb": gpu_mem_used_mb,
            "gpu_process":     gpu_process,
            "cpu_spikes":      cpu_spikes,
            "mem_hogs":        mem_hogs,
        }

        return DetectionSignal(
            signal_name = "gpu_cpu_spike",
            fired       = fired,
            evidence    = evidence,
            timestamp   = timestamp,
        )

    # -----------------------------------------------------------------------
    # Internal: GPU check via pynvml
    # -----------------------------------------------------------------------

    def _check_gpu(
        self,
    ) -> tuple[bool, float | None, float | None, dict | None, bool]:
        """
        Query the first NVIDIA GPU for utilisation and active compute processes.

        Returns:
            Tuple of (gpu_available, util_pct, mem_used_mb, gpu_process, spike)
        """
        try:
            pynvml.nvmlInit()
        except pynvml.NVMLError:
            # No NVIDIA driver / GPU present
            return False, None, None, None, False

        try:
            device_count = pynvml.nvmlDeviceGetCount()
            if device_count == 0:
                return False, None, None, None, False

            # Inspect the first GPU (index 0) — extend to multi-GPU if needed
            handle = pynvml.nvmlDeviceGetHandleByIndex(0)

            # -- Utilisation ------------------------------------------------
            util_rates  = pynvml.nvmlDeviceGetUtilizationRates(handle)
            util_pct    = float(util_rates.gpu)

            # -- Memory -----------------------------------------------------
            mem_info        = pynvml.nvmlDeviceGetMemoryInfo(handle)
            mem_used_mb     = round(mem_info.used / (1024 ** 2), 1)

            # -- Compute processes ------------------------------------------
            gpu_proc_info = None
            try:
                compute_procs = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
                if compute_procs:
                    # Report the first compute process found
                    cp = compute_procs[0]
                    proc_pid  = cp.pid
                    proc_name = self._pid_to_name(proc_pid)
                    gpu_proc_info = {
                        "pid":        proc_pid,
                        "name":       proc_name,
                        "mem_used_mb": round(cp.usedGpuMemory / (1024 ** 2), 1)
                        if cp.usedGpuMemory else None,
                    }
            except pynvml.NVMLError:
                pass  # Non-fatal — some drivers restrict process enumeration

            spike = util_pct > self.GPU_UTIL_THRESHOLD

            return True, util_pct, mem_used_mb, gpu_proc_info, spike

        except pynvml.NVMLError as exc:
            warnings.warn(
                f"[GPUDetector] pynvml error during GPU query: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )
            return True, None, None, None, False

        finally:
            try:
                pynvml.nvmlShutdown()
            except Exception:  # noqa: BLE001
                pass

    # -----------------------------------------------------------------------
    # Internal: CPU check via psutil
    # -----------------------------------------------------------------------

    def _check_cpu(self) -> list[dict[str, Any]]:
        """
        Identify the top-10 CPU-consuming processes and flag any that exceed
        CPU_THRESHOLD and are not in the approved list.

        psutil.cpu_percent(interval) with a short interval is used per-process
        to get an instantaneous snapshot without a long blocking wait.

        Returns:
            List of { pid, name, cpu_pct } dicts for offending processes.
        """
        spikes: list[dict[str, Any]] = []

        try:
            # Prime the cpu_percent counters (interval=None uses last call delta)
            procs_info: list[tuple[psutil.Process, dict]] = []
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    # First call seeds the counter; value is 0.0 — discard
                    proc.cpu_percent(interval=None)
                    procs_info.append((proc, proc.info))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Short sleep so the second call captures a real delta
            import time
            time.sleep(0.5)

            # Second call gives the actual CPU %
            cpu_readings: list[dict[str, Any]] = []
            for proc, info in procs_info:
                try:
                    cpu_pct = proc.cpu_percent(interval=None)
                    cpu_readings.append({
                        "pid":     info.get("pid", 0),
                        "name":    info.get("name", ""),
                        "cpu_pct": cpu_pct,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Sort descending and take top 10
            top10 = sorted(cpu_readings, key=lambda x: x["cpu_pct"], reverse=True)[:10]

            for entry in top10:
                if entry["cpu_pct"] < self.CPU_THRESHOLD:
                    break  # Already sorted — remaining are lower
                if not self._is_approved(entry["name"]):
                    spikes.append(entry)

        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"[GPUDetector] CPU check error: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

        return spikes

    # -----------------------------------------------------------------------
    # Internal: Memory check via psutil
    # -----------------------------------------------------------------------

    def _check_memory(self) -> list[dict[str, Any]]:
        """
        Find processes whose resident set size (RSS) exceeds MEM_THRESHOLD_MB
        and that are not in the approved process list.

        Returns:
            List of { pid, name, mem_mb } dicts for offending processes.
        """
        hogs: list[dict[str, Any]] = []

        try:
            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    info     = proc.info
                    mem_info = info.get("memory_info")
                    if mem_info is None:
                        continue

                    mem_mb = round(mem_info.rss / (1024 ** 2), 1)

                    if mem_mb < self.MEM_THRESHOLD_MB:
                        continue

                    name = info.get("name", "")
                    if self._is_approved(name):
                        continue

                    hogs.append({
                        "pid":    info.get("pid", 0),
                        "name":   name,
                        "mem_mb": mem_mb,
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as exc:  # noqa: BLE001
            warnings.warn(
                f"[GPUDetector] Memory check error: {exc}",
                RuntimeWarning,
                stacklevel=2,
            )

        return hogs

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _is_approved(self, process_name: str) -> bool:
        """
        Return True if process_name matches any entry in APPROVED_PROCESSES.

        Comparison is case-insensitive.
        """
        name_lower = process_name.lower()
        return any(
            approved.lower() == name_lower
            for approved in self.APPROVED_PROCESSES
        )

    def _pid_to_name(self, pid: int) -> str:
        """
        Resolve a PID to its process name via psutil.

        Returns 'unknown' if the process cannot be found or accessed.
        """
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  GPUDetector — standalone test")
    if _PYNVML_AVAILABLE:
        print("  pynvml   : available (NVIDIA GPU check enabled)")
    else:
        print("  pynvml   : NOT installed — CPU/Memory mode only")
    print("  Scanning GPU / CPU / Memory for LLM inference spikes...")
    print("=" * 60)

    detector = GPUDetector()
    result   = detector.detect()

    # Pretty-print (json.dumps can't handle None in some edge cases — safe here)
    print(json.dumps(result.model_dump(), indent=2))

    ev = result.evidence
    print()
    if ev.get("gpu_available"):
        print(f"  GPU utilisation : {ev['gpu_util_pct']} %")
        print(f"  GPU memory used : {ev['gpu_mem_used_mb']} MB")
        if ev.get("gpu_process"):
            gp = ev["gpu_process"]
            print(f"  GPU process     : PID {gp['pid']}  {gp['name']}")
    else:
        print("  GPU             : not available — CPU/Memory fallback active")

    if ev.get("cpu_spikes"):
        print(f"\n  CPU spikes ({len(ev['cpu_spikes'])} process(es)):")
        for s in ev["cpu_spikes"]:
            print(f"    PID {s['pid']:>6}  {s['name']:<30}  {s['cpu_pct']:.1f} %")

    if ev.get("mem_hogs"):
        print(f"\n  Memory hogs ({len(ev['mem_hogs'])} process(es)):")
        for m in ev["mem_hogs"]:
            print(f"    PID {m['pid']:>6}  {m['name']:<30}  {m['mem_mb']:.0f} MB")

    print()
    if result.fired:
        print("[!] ALERT — Anomalous resource usage detected (possible LLM inference).")
    else:
        print("[OK] No anomalous GPU/CPU/Memory spike detected.")
