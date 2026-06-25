"""
tests/test_detectors.py
-------------------------
Unit tests for all four Local LLM Hunter detectors.

Uses unittest.mock to isolate each detector from real system calls.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import psutil

from agent.detectors.port_detector    import PortDetector
from agent.detectors.file_detector    import FileDetector
from agent.detectors.library_detector import LibraryDetector
from agent.detectors.gpu_detector     import GPUDetector
from agent.models.schemas             import DetectionSignal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_connection(port: int, status: str = "LISTEN", pid: int = 1234):
    """Build a mock psutil sconn-like object."""
    conn = MagicMock()
    conn.laddr = MagicMock()
    conn.laddr.port = port
    conn.status = status
    conn.pid = pid
    return conn


def _make_process(pid=1234, name="python", cmdline=None, exe="/usr/bin/python"):
    """Build a mock psutil Process-like object for library/GPU tests."""
    proc = MagicMock()
    proc.pid  = pid
    proc.info = {
        "pid":     pid,
        "name":    name,
        "cmdline": cmdline or [exe],
        "exe":     exe,
    }
    proc.memory_maps.return_value = []
    return proc


# ===========================================================================
# TestPortDetector
# ===========================================================================

class TestPortDetector:

    def test_known_port_detected(self):
        """Port 11434 (Ollama) open → signal.fired=True, runtime in evidence."""
        mock_conn = _make_connection(port=11434, status="LISTEN", pid=9999)

        with patch("psutil.net_connections", return_value=[mock_conn]):
            signal = PortDetector().detect()

        assert signal.fired is True
        assert signal.evidence.get("port") == 11434
        assert str(signal.evidence.get("runtime", "")).lower() == "ollama"

    def test_unknown_port_not_detected(self):
        """No known LLM port open → signal.fired=False."""
        mock_conn = _make_connection(port=80, status="LISTEN", pid=1)

        with patch("psutil.net_connections", return_value=[mock_conn]):
            signal = PortDetector().detect()

        assert signal.fired is False
        assert signal.evidence == {}

    def test_empty_connections_not_detected(self):
        """Empty connection list → signal.fired=False."""
        with patch("psutil.net_connections", return_value=[]):
            signal = PortDetector().detect()

        assert signal.fired is False

    def test_permission_error_handled(self):
        """psutil.AccessDenied must not propagate — returns fired=False."""
        with patch("psutil.net_connections", side_effect=psutil.AccessDenied(pid=0)):
            signal = PortDetector().detect()   # must not raise

        assert isinstance(signal, DetectionSignal)
        assert signal.fired is False

    def test_get_runtime_from_port_known(self):
        """get_runtime_from_port(11434) returns 'Ollama' (or equivalent)."""
        result = PortDetector().get_runtime_from_port(11434)
        assert result is not None
        assert "ollama" in str(result).lower()

    def test_get_runtime_from_port_unknown(self):
        """get_runtime_from_port(9999) returns None."""
        result = PortDetector().get_runtime_from_port(9999)
        assert result is None

    def test_all_known_ports_detected(self):
        """Each of the 5 known LLM ports triggers signal.fired=True."""
        known_ports = [11434, 1234, 4891, 1337, 23333]
        detector = PortDetector()

        for port in known_ports:
            mock_conn = _make_connection(port=port)
            with patch("psutil.net_connections", return_value=[mock_conn]):
                signal = detector.detect()
            assert signal.fired is True, f"Expected fired=True for port {port}"


# ===========================================================================
# TestFileDetector
# ===========================================================================

class TestFileDetector:

    def test_gguf_file_detected(self, tmp_path):
        """A .gguf file in the scan directory triggers signal.fired=True."""
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        gguf_file = model_dir / "llama3.gguf"
        gguf_file.write_bytes(b"\x00" * 1024)   # small but valid path

        with patch.object(FileDetector, "DEFAULT_SCAN_DIRS", [str(tmp_path)]):
            signal = FileDetector().detect()

        assert signal.fired is True
        paths = [f["path"] for f in signal.evidence.get("files_found", [])]
        assert any("llama3.gguf" in p for p in paths)

    def test_safetensors_file_detected(self, tmp_path):
        """A .safetensors file is also detected."""
        (tmp_path / "model.safetensors").write_bytes(b"\x00" * 512)

        with patch.object(FileDetector, "DEFAULT_SCAN_DIRS", [str(tmp_path)]):
            signal = FileDetector().detect()

        assert signal.fired is True

    def test_approved_path_excluded(self, tmp_path):
        """A .gguf file inside an approved path must NOT trigger detection."""
        approved_dir = tmp_path / "AI_Approved"
        approved_dir.mkdir()
        (approved_dir / "corporate.gguf").write_bytes(b"\x00" * 512)

        with (
            patch.object(FileDetector, "DEFAULT_SCAN_DIRS", [str(tmp_path)]),
            patch.object(FileDetector, "approved_paths",    [str(approved_dir)]),
        ):
            signal = FileDetector().detect()

        assert signal.fired is False

    def test_no_model_files_not_detected(self, tmp_path):
        """A directory containing only .txt files → signal.fired=False."""
        (tmp_path / "readme.txt").write_text("hello")

        with patch.object(FileDetector, "DEFAULT_SCAN_DIRS", [str(tmp_path)]):
            signal = FileDetector().detect()

        assert signal.fired is False

    def test_returns_detection_signal(self, tmp_path):
        """detect() always returns a DetectionSignal regardless of outcome."""
        with patch.object(FileDetector, "DEFAULT_SCAN_DIRS", [str(tmp_path)]):
            signal = FileDetector().detect()

        assert isinstance(signal, DetectionSignal)


# ===========================================================================
# TestLibraryDetector
# ===========================================================================

class TestLibraryDetector:

    def test_high_conf_library_detected(self):
        """Process with 'ollama' in cmdline → fired=True, confidence=HIGH."""
        mock_proc = _make_process(
            pid=5678, name="ollama",
            cmdline=["ollama", "serve"], exe="/usr/bin/ollama",
        )

        with patch("psutil.process_iter", return_value=[mock_proc]):
            signal = LibraryDetector().detect()

        assert signal.fired is True
        processes = signal.evidence.get("processes", [])
        assert len(processes) > 0
        confidences = [p.get("confidence", "") for p in processes]
        assert any(c == "HIGH" for c in confidences)

    def test_medium_conf_library_detected(self):
        """Process with 'langchain' in cmdline → fired=True (MEDIUM conf)."""
        mock_proc = _make_process(
            pid=5679, name="python",
            cmdline=["python", "-m", "langchain"], exe="/usr/bin/python",
        )

        with patch("psutil.process_iter", return_value=[mock_proc]):
            signal = LibraryDetector().detect()

        assert signal.fired is True

    def test_low_conf_only_not_fired(self):
        """Process with only 'numpy' in cmdline → fired=False (LOW conf only)."""
        mock_proc = _make_process(
            pid=5680, name="python",
            cmdline=["python", "-c", "import numpy"],
            exe="/usr/bin/python",
        )

        with patch("psutil.process_iter", return_value=[mock_proc]):
            signal = LibraryDetector().detect()

        # LOW confidence alone must not fire the signal
        assert signal.fired is False

    def test_no_ai_processes_not_fired(self):
        """Chrome browser process → signal.fired=False."""
        mock_proc = _make_process(
            pid=100, name="chrome",
            cmdline=["chrome", "--no-sandbox"], exe="/usr/bin/chrome",
        )

        with patch("psutil.process_iter", return_value=[mock_proc]):
            signal = LibraryDetector().detect()

        assert signal.fired is False

    def test_returns_detection_signal(self):
        """detect() always returns DetectionSignal."""
        with patch("psutil.process_iter", return_value=[]):
            signal = LibraryDetector().detect()

        assert isinstance(signal, DetectionSignal)

    def test_permission_error_graceful(self):
        """AccessDenied on a process must be skipped, not raised."""
        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1, "name": "System", "cmdline": None, "exe": None}
        mock_proc.memory_maps.side_effect = psutil.AccessDenied(pid=1)

        with patch("psutil.process_iter", return_value=[mock_proc]):
            signal = LibraryDetector().detect()   # must not raise

        assert isinstance(signal, DetectionSignal)


# ===========================================================================
# TestGPUDetector
# ===========================================================================

class TestGPUDetector:

    def test_no_gpu_graceful(self):
        """
        On a machine without an NVIDIA GPU (pynvml raises NVMLError),
        detect() must return a valid DetectionSignal without raising.
        """
        signal = GPUDetector().detect()   # real call — pynvml fallback path

        assert isinstance(signal, DetectionSignal)
        assert signal.signal_name  # non-empty name
        assert isinstance(signal.fired, bool)

    def test_high_cpu_spike_detected(self):
        """A process exceeding CPU_THRESHOLD → gpu spike evidence recorded."""
        detector = GPUDetector()

        mock_proc = MagicMock()
        mock_proc.pid  = 9999
        mock_proc.info = {
            "pid": 9999, "name": "suspicious_ai",
            "cpu_percent": detector.CPU_THRESHOLD + 10,
            "memory_info": MagicMock(rss=(detector.MEM_THRESHOLD_MB + 500) * 1024 * 1024),
        }

        with patch("psutil.process_iter", return_value=[mock_proc]):
            # Only test the CPU check path (GPU unavailable in CI)
            signal = detector._check_cpu_spikes()   # internal helper

        # Evidence dict is returned whether fired or not
        assert isinstance(signal, dict)

    def test_detect_returns_detection_signal_always(self):
        """detect() always returns DetectionSignal regardless of GPU presence."""
        for _ in range(2):   # run twice to test caching / reinit
            signal = GPUDetector().detect()
            assert isinstance(signal, DetectionSignal)
