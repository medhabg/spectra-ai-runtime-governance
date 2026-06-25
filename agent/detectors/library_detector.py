"""
agent/detectors/library_detector.py
-------------------------------------
Library / SBOM-based detector for the Local LLM Hunter agent.

Inspects running processes for AI-specific library indicators by examining:
  1. Process command-line arguments and executable paths
  2. Process memory-mapped files (shared libraries / DLLs loaded at runtime)

Confidence tiers:
  HIGH   — llama.cpp, llama_cpp, ollama, lm_studio
             → fired=True immediately on any single match
  MEDIUM — langchain, openai, transformers, torch, tensorflow
             → fired=True on any single match
  LOW    — numpy, scipy
             → recorded in evidence but does NOT set fired=True alone;
               only meaningful when combined with other signals

Classes:
    LibraryDetector — main detector; exposes detect() and get_confidence_level()

Standalone test (python library_detector.py):
    Runs detect() and prints the result as JSON.
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime, timezone
from typing import Any

import psutil

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
# System process names that should always be skipped
# ---------------------------------------------------------------------------
_SKIP_PROCESS_NAMES: set[str] = {
    "system", "svchost", "svchost.exe", "kernel",
    "kthreadd", "ksoftirqd", "idle", "registry",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe",
}


# ---------------------------------------------------------------------------
# LibraryDetector
# ---------------------------------------------------------------------------

class LibraryDetector:
    """
    Detects AI/LLM-specific libraries loaded by running processes.

    Inspection sources (in order):
      1. Process cmdline tokens — flags like '--model llama_cpp_server'
      2. Executable path — e.g. '/home/user/.venv/bin/ollama'
      3. Memory-mapped files — shared objects / DLLs loaded at runtime
         (requires elevated privileges; gracefully skipped otherwise)

    Attributes:
        HIGH_CONF_LIBS : Libraries that indicate a high-confidence LLM
                         runtime match.
        MED_CONF_LIBS  : Libraries that indicate medium-confidence AI usage.
        LOW_CONF_LIBS  : Low-signal libraries; only meaningful alongside
                         other high/medium signals.
    """

    HIGH_CONF_LIBS: list[str] = [
        "llama.cpp",
        "llama_cpp",
        "ollama",
        "lm_studio",
        "lmstudio",
        "gpt4all",
        "gpt_4all",
        "koboldcpp",
        "kobold",
        "localai",
        "local_ai",
        "jan",
        "lmdeploy",
    ]

    MED_CONF_LIBS: list[str] = [
        "langchain",
        "openai",
        "transformers",
        "torch",
        "tensorflow",
        "ctransformers",
        "llm",
    ]

    LOW_CONF_LIBS: list[str] = [
        "numpy",
        "scipy",
    ]

    # Process executable names that map directly to a known LLM runtime.
    # Used when the exe/cmdline contains no library tokens but the binary
    # name itself is a definitive identifier (e.g. GPT4All ships as chat.exe
    # inside a 'gpt4all' installation directory).
    KNOWN_PROCESS_NAMES: dict[str, str] = {
        "chat.exe":        "gpt4all",    # GPT4All Windows binary
        "gpt4all.exe":    "gpt4all",
        "ollama.exe":     "ollama",
        "ollama":         "ollama",
        "lmstudio.exe":   "lm_studio",
        "koboldcpp.exe":  "koboldcpp",
        "koboldcpp":      "koboldcpp",
        "jan.exe":        "jan",
        "localai":        "localai",
        "llama-server":   "llama.cpp",
        "llama-server.exe": "llama.cpp",
    }

    # -----------------------------------------------------------------------
    # detect
    # -----------------------------------------------------------------------

    def detect(self) -> DetectionSignal:
        """
        Iterate over all running processes and inspect them for AI library
        indicators.

        Skips:
          - Processes with PID < 10 (kernel / OS scheduler threads)
          - Processes whose name appears in _SKIP_PROCESS_NAMES
          - Processes that raise AccessDenied or NoSuchProcess (silent)

        Evidence fields (when fired=True):
            processes : list of dicts, each containing:
                pid          : int   — process ID
                name         : str   — process name
                matched_libs : list  — library tokens that matched
                confidence   : str   — HIGH | MEDIUM | LOW
                source       : list  — inspection sources that produced hits
                               ('cmdline', 'exe', 'memory_maps')

        fired=True when at least one HIGH or MEDIUM confidence match is found.

        Returns:
            DetectionSignal with fired=True if a meaningful match is found.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        matched_processes: list[dict[str, Any]] = []

        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            try:
                info = proc.info

                pid  = info.get("pid") or 0
                name = (info.get("name") or "").strip()

                # ---- Skip kernel / OS scheduler threads ------------------
                if pid < 10:
                    continue

                if name.lower() in _SKIP_PROCESS_NAMES:
                    continue

                # ---- Gather text tokens for string matching --------------
                matched_libs: list[str] = []
                sources_hit:  list[str] = []

                # 0. Direct process-name lookup (highest priority).
                #    Catches runtimes whose binary name is a known indicator
                #    (e.g. GPT4All ships as chat.exe inside a gpt4all/ dir).
                name_key = name.lower()
                if name_key in {k.lower() for k in self.KNOWN_PROCESS_NAMES}:
                    mapped_lib = self.KNOWN_PROCESS_NAMES.get(name_key) or \
                                 next((v for k, v in self.KNOWN_PROCESS_NAMES.items()
                                       if k.lower() == name_key), None)
                    if mapped_lib and mapped_lib not in matched_libs:
                        # Verify with exe path when available to avoid FP
                        # on generic names like 'chat.exe' without a gpt4all dir
                        exe_verify = (info.get("exe") or "").lower().replace("\\", "/")
                        if mapped_lib in exe_verify or name_key == mapped_lib + ".exe":
                            matched_libs.append(mapped_lib)
                            sources_hit.append("process_name")

                # 1. Command-line arguments
                cmdline_tokens = self._extract_cmdline_tokens(info.get("cmdline"))
                cmd_hits = self._match_libs(cmdline_tokens)
                if cmd_hits:
                    matched_libs.extend(h for h in cmd_hits if h not in matched_libs)
                    sources_hit.append("cmdline")

                # 2. Executable path
                exe_path = info.get("exe") or ""
                exe_hits = self._match_libs([exe_path])
                if exe_hits:
                    for hit in exe_hits:
                        if hit not in matched_libs:
                            matched_libs.append(hit)
                    if "exe" not in sources_hit:
                        sources_hit.append("exe")

                # 3. Memory-mapped files (best-effort; requires elevation)
                mmap_hits = self._check_memory_maps(proc)
                if mmap_hits:
                    for hit in mmap_hits:
                        if hit not in matched_libs:
                            matched_libs.append(hit)
                    sources_hit.append("memory_maps")

                if not matched_libs:
                    continue

                # ---- Assign confidence level ----------------------------
                confidence = self.get_confidence_level(matched_libs)

                matched_processes.append({
                    "pid":          pid,
                    "name":         name,
                    "matched_libs": matched_libs,
                    "confidence":   confidence,
                    "source":       sources_hit,
                })

            except psutil.NoSuchProcess:
                # Process exited between iter and inspection — skip
                continue
            except psutil.AccessDenied:
                # Insufficient privilege to inspect this process — skip
                continue
            except Exception as exc:  # noqa: BLE001
                warnings.warn(
                    f"[LibraryDetector] Unexpected error inspecting PID "
                    f"{getattr(proc, 'pid', '?')}: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue

        # fired=True only if at least one HIGH or MEDIUM match exists
        fired = any(
            p["confidence"] in ("HIGH", "MEDIUM")
            for p in matched_processes
        )

        evidence: dict[str, Any] = (
            {"processes": matched_processes} if matched_processes else {}
        )

        return DetectionSignal(
            signal_name = "library_scan",
            fired       = fired,
            evidence    = evidence,
            timestamp   = timestamp,
        )

    # -----------------------------------------------------------------------
    # get_confidence_level
    # -----------------------------------------------------------------------

    def get_confidence_level(self, matched_libs: list[str]) -> str:
        """
        Determine the confidence level of a set of matched library tokens.

        Precedence: HIGH > MEDIUM > LOW.
        A single HIGH-confidence library match is sufficient for 'HIGH'.

        Args:
            matched_libs : List of library name strings that were matched.

        Returns:
            'HIGH', 'MEDIUM', or 'LOW'.
        """
        normalised = [lib.lower() for lib in matched_libs]

        for lib in normalised:
            for high_lib in self.HIGH_CONF_LIBS:
                if high_lib.lower() in lib or lib in high_lib.lower():
                    return "HIGH"

        for lib in normalised:
            for med_lib in self.MED_CONF_LIBS:
                if med_lib.lower() in lib or lib in med_lib.lower():
                    return "MEDIUM"

        return "LOW"

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _extract_cmdline_tokens(self, cmdline: list[str] | None) -> list[str]:
        """
        Flatten a process cmdline list into a single normalised token set.

        Splits each argument on common separators (space, slash, backslash,
        dash, underscore, dot) to maximise substring matching.

        Args:
            cmdline : Raw cmdline list from psutil (may be None or empty).

        Returns:
            List of lowercase token strings.
        """
        if not cmdline:
            return []

        tokens: list[str] = []
        for arg in cmdline:
            # Keep the full arg as one token AND split on path separators
            tokens.append(arg.lower())
            # Split on / \\ to extract individual path components
            for part in arg.replace("\\", "/").split("/"):
                tokens.append(part.lower())

        return tokens

    def _match_libs(self, tokens: list[str]) -> list[str]:
        """
        Check a list of string tokens against all three confidence lists.

        Matching rules (applied in order):
          1. Exact match:  token == lib_name (case/separator normalised)
          2. Forward match: lib_name is a path-component within the token
             (i.e. the token, when split on path separators, contains an
             exact component equal to lib_name).  This correctly matches
             '/home/user/.ollama/bin/ollama' → 'ollama'.

        The OLD bidirectional substring rule ('token in lib') caused severe
        false positives: 'localai' matched 'LocalAppData', 'jan' matched
        'Antigravity', 'llm' matched random cmdline args, etc.

        Args:
            tokens : List of path-component strings from _extract_cmdline_tokens.

        Returns:
            List of matched library name strings (may be empty).
        """
        import re
        matched: list[str] = []
        all_libs = self.HIGH_CONF_LIBS + self.MED_CONF_LIBS + self.LOW_CONF_LIBS

        # Pre-split tokens into their path components for exact-component matching
        # tokens already contain both full paths and their path components
        # (injected by _extract_cmdline_tokens), so we use them as-is.
        token_set = {t.replace("-", "_") for t in tokens}

        for lib in all_libs:
            lib_lower = lib.lower().replace("-", "_")

            # Guard: skip very short lib names for substring matching
            # (they're prone to false positives); only match them exactly.
            short_lib = len(lib_lower) <= 3

            for token in tokens:
                token_clean = token.replace("-", "_")

                # Rule 1: exact component match
                if token_clean == lib_lower:
                    if lib not in matched:
                        matched.append(lib)
                    break

                # Rule 2: lib appears as a whole word/component inside a longer
                # token (e.g. lib='ollama' inside '/users/admin/.ollama/bin/ollama').
                # Use word-boundary regex to avoid partial collisions.
                if not short_lib and len(lib_lower) >= 4:
                    # Match lib as a complete path segment or word boundary
                    pattern = r"(?<![a-z0-9_])" + re.escape(lib_lower) + r"(?![a-z0-9_])"
                    if re.search(pattern, token_clean):
                        if lib not in matched:
                            matched.append(lib)
                        break

        return matched


    def _check_memory_maps(self, proc: psutil.Process) -> list[str]:
        """
        Inspect a process's memory-mapped files for AI library names.

        Reads the list of mapped files (shared objects, DLLs, Python .so
        extensions) and checks their paths against all library lists.

        Requires elevated privileges on most OSes; silently skips on
        AccessDenied or if memory_maps() is unsupported.

        Args:
            proc : A live psutil.Process instance.

        Returns:
            List of matched library name strings from memory maps.
        """
        try:
            maps = proc.memory_maps()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
        except (AttributeError, NotImplementedError):
            # memory_maps() not available on this platform / psutil build
            return []
        except Exception:  # noqa: BLE001
            return []

        # Flatten all mapped file paths into tokens
        tokens: list[str] = []
        for mmap in maps:
            path = getattr(mmap, "path", "") or ""
            if path:
                tokens.append(path.lower())
                for part in path.replace("\\", "/").split("/"):
                    tokens.append(part.lower())

        return self._match_libs(tokens)


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  LibraryDetector — standalone test")
    print("  Scanning running processes for AI library indicators...")
    print("=" * 60)

    detector = LibraryDetector()
    result   = detector.detect()

    print(json.dumps(result.model_dump(), indent=2))

    if result.fired:
        procs = result.evidence.get("processes", [])
        print(f"\n[!] ALERT — AI library evidence found in {len(procs)} process(es):")
        for p in procs:
            print(
                f"    PID {p['pid']:>6}  [{p['confidence']:>6}]  "
                f"{p['name']}  →  {', '.join(p['matched_libs'])}"
            )
    else:
        if result.evidence.get("processes"):
            print("\n[~] LOW confidence matches only — no alert raised.")
        else:
            print("\n[OK] No AI library indicators detected in running processes.")
