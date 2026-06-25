"""
agent/detectors/file_detector.py
---------------------------------
File-system-based detector for the Local LLM Hunter agent.

Recursively scans platform-specific directories for AI model files by
extension and size, then cross-references finds against an approved-paths
whitelist loaded from config/approved_models.json.

Detected extensions:
    .gguf        — GGUF quantised model format (llama.cpp / Ollama)
    .ggml        — Legacy GGML model format
    .safetensors — HuggingFace safe serialisation format
    .bin         — Only flagged when file size exceeds LARGE_BIN_THRESHOLD_MB

Performance target: full scan completes in under 30 seconds.
Scan depth is capped at 5 directory levels from each scan root.

Classes:
    FileDetector — main detector; exposes detect() and compute_file_hash()
"""

from __future__ import annotations

import hashlib
import json
import platform
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Project-root-relative import with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import DetectionSignal
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import DetectionSignal

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Path to the approved models config, resolved relative to the project root
_PROJECT_ROOT       = Path(__file__).resolve().parents[2]
_APPROVED_CFG_PATH  = _PROJECT_ROOT / "config" / "approved_models.json"

# Directories that must never be descended into on any OS
_ALWAYS_SKIP_DIRS: set[str] = {
    "/proc", "/dev", "/sys", "/System",
    "/System/Library", "/private/var", "/run",
    "C:\\Windows", "C:\\Windows\\System32",
}

# Maximum recursion depth from each scan root
_MAX_DEPTH = 5

# Maximum bytes read when hashing large files (50 MB)
_HASH_READ_LIMIT = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# FileDetector
# ---------------------------------------------------------------------------

class FileDetector:
    """
    Detects AI model files on the local filesystem that may indicate a
    Shadow AI / unauthorised LLM runtime is present.

    Strategy:
      1. Build a set of approved paths from config/approved_models.json
         plus hardcoded DEFAULT_APPROVED_PATHS.
      2. Recursively walk each directory in DEFAULT_SCAN_DIRS (platform-
         specific) up to _MAX_DEPTH levels deep.
      3. Flag any file whose extension is in SCAN_EXTENSIONS, or any .bin
         file larger than LARGE_BIN_THRESHOLD_MB.
      4. Skip files whose resolved path starts with an approved-path prefix.

    Attributes:
        SCAN_EXTENSIONS          : File extensions that always trigger detection.
        LARGE_BIN_THRESHOLD_MB   : Minimum size (MB) for a .bin file to be flagged.
        DEFAULT_APPROVED_PATHS   : Hardcoded paths that are never flagged.
        DEFAULT_SCAN_DIRS        : Platform-specific directories to scan.
    """

    SCAN_EXTENSIONS: list[str] = [".gguf", ".ggml", ".safetensors"]

    LARGE_BIN_THRESHOLD_MB: int = 500

    DEFAULT_APPROVED_PATHS: list[str] = [
        r"C:\AI_Approved\\",
        "/opt/ai-approved/",
    ]

    # Platform-specific scan roots
    _SCAN_DIRS_WINDOWS: list[str] = [
        r"C:\Users",
        r"C:\ProgramData",
    ]

    _SCAN_DIRS_LINUX: list[str] = [
        "/home",
        "/opt",
        "/tmp",
    ]

    # -----------------------------------------------------------------------
    # __init__
    # -----------------------------------------------------------------------

    def __init__(self) -> None:
        """
        Initialise the detector.

        Loads the approved-paths whitelist from config/approved_models.json
        (merging with DEFAULT_APPROVED_PATHS) and selects the correct set
        of scan directories for the current OS.
        """
        self._approved_paths: set[str] = self._load_approved_paths()
        self._scan_dirs: list[Path]    = self._resolve_scan_dirs()

    # -----------------------------------------------------------------------
    # detect
    # -----------------------------------------------------------------------

    def detect(self) -> DetectionSignal:
        """
        Scan the filesystem for suspicious AI model files.

        Walks each directory in _scan_dirs up to _MAX_DEPTH levels deep.
        Skips approved paths and known system directories silently.
        PermissionErrors are caught and skipped without crashing.

        Evidence fields (when fired=True):
            files_found : list of dicts, each containing:
                path        : str  — absolute path of the found file
                size_mb     : float — file size in megabytes (2 d.p.)
                extension   : str  — file extension
                modified    : str  — ISO-8601 last-modified timestamp
                folder_name : str  — immediate parent directory name
                shadow_ai_indicator : bool — True if file is in a non-approved
                                             project-style folder

        Returns:
            DetectionSignal with fired=True if any suspicious file is found.
        """
        timestamp   = datetime.now(timezone.utc).isoformat()
        files_found: list[dict[str, Any]] = []

        for scan_root in self._scan_dirs:
            if not scan_root.exists():
                continue

            self._walk_directory(
                directory  = scan_root,
                current_depth = 0,
                results    = files_found,
            )

        fired = len(files_found) > 0

        evidence: dict[str, Any] = (
            {"files_found": files_found} if fired else {}
        )

        return DetectionSignal(
            signal_name = "file_scan",
            fired       = fired,
            evidence    = evidence,
            timestamp   = timestamp,
        )

    # -----------------------------------------------------------------------
    # compute_file_hash
    # -----------------------------------------------------------------------

    def compute_file_hash(self, filepath: str) -> str:
        """
        Compute the SHA-256 hash of a file.

        For files larger than _HASH_READ_LIMIT (50 MB) only the first
        50 MB of content is hashed to keep performance acceptable.

        Args:
            filepath : Absolute or relative path to the target file.

        Returns:
            Lowercase hexadecimal SHA-256 digest string.

        Raises:
            FileNotFoundError : if the path does not point to a file.
            PermissionError   : if the file cannot be opened for reading.
        """
        path   = Path(filepath)
        hasher = hashlib.sha256()

        with path.open("rb") as fh:
            bytes_read = 0
            while True:
                chunk = fh.read(65536)  # 64 KB chunks
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_read += len(chunk)
                if bytes_read >= _HASH_READ_LIMIT:
                    # Partial hash — sufficient for identification purposes
                    break

        return hasher.hexdigest()

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _load_approved_paths(self) -> set[str]:
        """
        Build the set of approved directory path prefixes.

        Reads the 'approved_models' list from config/approved_models.json.
        The 'endpoint_tag' field is not a path, so only the hardcoded
        DEFAULT_APPROVED_PATHS plus any 'approved_directory' keys (if
        present in future schema extensions) are used as path filters.

        Returns:
            Set of normalised lowercase path prefix strings.
        """
        approved: set[str] = set()

        # Always include the hardcoded defaults
        for p in self.DEFAULT_APPROVED_PATHS:
            approved.add(p.lower())

        # Attempt to parse config/approved_models.json
        if _APPROVED_CFG_PATH.exists():
            try:
                cfg = json.loads(_APPROVED_CFG_PATH.read_text(encoding="utf-8"))
                for entry in cfg.get("approved_models", []):
                    # Support an optional 'approved_directory' field for path-
                    # level whitelisting (not in the initial schema but
                    # forward-compatible).
                    approved_dir = entry.get("approved_directory")
                    if approved_dir:
                        approved.add(str(approved_dir).lower())
            except (json.JSONDecodeError, OSError) as exc:
                warnings.warn(
                    f"[FileDetector] Could not parse approved_models.json: {exc}",
                    RuntimeWarning,
                    stacklevel=2,
                )

        return approved

    def _resolve_scan_dirs(self) -> list[Path]:
        """
        Return the correct list of scan root directories for the current OS.

        On Windows, additionally expands %APPDATA% / %LOCALAPPDATA% paths
        so user-level model caches (e.g. LM Studio) are covered.
        """
        import os

        system = platform.system()

        if system == "Windows":
            base_dirs = list(self._SCAN_DIRS_WINDOWS)

            # Add per-user AppData paths if the environment variables exist
            for env_var in ("APPDATA", "LOCALAPPDATA"):
                val = os.environ.get(env_var)
                if val:
                    base_dirs.append(val)
        else:
            # Linux / macOS
            base_dirs = list(self._SCAN_DIRS_LINUX)

        return [Path(d) for d in base_dirs]

    def _is_approved_path(self, path: Path) -> bool:
        """
        Return True if the given path falls under any approved-path prefix.

        Comparison is case-insensitive on Windows, case-sensitive on Linux.
        """
        path_str = str(path).lower() if platform.system() == "Windows" \
                   else str(path)

        for approved in self._approved_paths:
            cmp_approved = approved.lower() if platform.system() == "Windows" \
                           else approved
            if path_str.startswith(cmp_approved):
                return True

        return False

    def _is_system_dir(self, directory: Path) -> bool:
        """Return True if directory is in the always-skip set."""
        dir_str = str(directory)
        for skip in _ALWAYS_SKIP_DIRS:
            if dir_str.startswith(skip):
                return True
        return False

    def _is_shadow_ai_folder(self, file_path: Path) -> bool:
        """
        Heuristic: flag files in project-style folders that are NOT in an
        approved path as potential Shadow AI indicators.

        A folder is considered 'project-style' if its name contains common
        LLM workspace keywords.
        """
        shadow_keywords = {
            "ollama", "lmstudio", "lm-studio", "gpt4all", "jan",
            "lmdeploy", "llama", "gguf", "models", "ai-models",
            "localai", "kobold", "text-generation",
        }
        parts_lower = {p.lower() for p in file_path.parts}
        return bool(parts_lower & shadow_keywords)

    def _walk_directory(
        self,
        directory: Path,
        current_depth: int,
        results: list[dict[str, Any]],
    ) -> None:
        """
        Recursively walk a directory up to _MAX_DEPTH levels deep.

        Silently skips:
          - Directories beyond the depth cap
          - System / always-skip directories
          - Approved paths
          - Directories that raise PermissionError

        Args:
            directory     : Current directory being scanned.
            current_depth : How many levels deep we are from the scan root.
            results       : Accumulator list for matched file metadata dicts.
        """
        if current_depth > _MAX_DEPTH:
            return

        if self._is_system_dir(directory):
            return

        if self._is_approved_path(directory):
            return

        try:
            entries = list(directory.iterdir())
        except PermissionError:
            return  # Skip silently
        except OSError:
            return  # Handles broken symlinks, unmounted drives, etc.

        for entry in entries:
            try:
                if entry.is_symlink():
                    # Skip symlinks to avoid infinite loops
                    continue

                if entry.is_dir():
                    # Recurse one level deeper
                    self._walk_directory(
                        directory     = entry,
                        current_depth = current_depth + 1,
                        results       = results,
                    )

                elif entry.is_file():
                    self._evaluate_file(entry, results)

            except PermissionError:
                continue
            except OSError:
                continue

    def _evaluate_file(
        self,
        file_path: Path,
        results: list[dict[str, Any]],
    ) -> None:
        """
        Check a single file against detection rules and append to results.

        Rules:
          1. Extension in SCAN_EXTENSIONS → always flag.
          2. Extension is .bin AND size > LARGE_BIN_THRESHOLD_MB → flag.
          3. File is in an approved path → skip (never flag).
        """
        if self._is_approved_path(file_path):
            return

        ext = file_path.suffix.lower()
        flagged = False

        if ext in [e.lower() for e in self.SCAN_EXTENSIONS]:
            flagged = True
        elif ext == ".bin":
            try:
                size_bytes = file_path.stat().st_size
                if size_bytes > self.LARGE_BIN_THRESHOLD_MB * 1024 * 1024:
                    flagged = True
            except OSError:
                return

        if not flagged:
            return

        # Gather file metadata
        try:
            stat       = file_path.stat()
            size_mb    = round(stat.st_size / (1024 * 1024), 2)
            modified   = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat()
        except OSError:
            return

        results.append({
            "path":               str(file_path),
            "size_mb":            size_mb,
            "extension":          ext,
            "modified":           modified,
            "folder_name":        file_path.parent.name,
            "shadow_ai_indicator": self._is_shadow_ai_folder(file_path),
        })


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import time

    print("=" * 60)
    print("  FileDetector — standalone test")
    print(f"  Platform : {platform.system()}")
    print("  Scanning filesystem for AI model files...")
    print("=" * 60)

    t_start  = time.perf_counter()
    detector = FileDetector()
    result   = detector.detect()
    elapsed  = time.perf_counter() - t_start

    print(json.dumps(result.model_dump(), indent=2))

    print(f"\nScan completed in {elapsed:.2f}s")

    if result.fired:
        found = result.evidence.get("files_found", [])
        print(f"\n[!] ALERT — {len(found)} suspicious model file(s) detected:")
        for f in found:
            shadow = " ← Shadow AI indicator" if f.get("shadow_ai_indicator") else ""
            print(f"    {f['path']}  ({f['size_mb']} MB){shadow}")
    else:
        print("\n[OK] No suspicious AI model files detected.")
