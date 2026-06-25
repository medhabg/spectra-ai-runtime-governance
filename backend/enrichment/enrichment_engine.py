"""
backend/enrichment/enrichment_engine.py
-----------------------------------------
Static Enrichment Engine for the Local LLM Hunter agent.

After the CorrelationEngine confirms a detection, the EnrichmentEngine
cross-references the detected runtime and model against four config files
to produce a fully populated EnrichmentResult:

  Step 1 — Approval check  : Is the model in the approved whitelist?
  Step 2 — CVE check        : Does the runtime/model match a known CVE?
  Step 3 — Policy check     : Does the endpoint's department have a rule?
  Step 4 — Criticality check: Is the endpoint flagged as critical?

Config files loaded (all relative to the project root):
    config/approved_models.json
    config/known_vulnerable_models.json
    config/endpoint_config.json
    config/policy_rules.json

Classes:
    EnrichmentEngine — stateful enrichment engine with hot-reload support

Standalone test (python enrichment_engine.py):
    enrich('ollama', 'llama3.gguf', 'ENDPOINT-042') — prints EnrichmentResult.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# EnrichmentResult import with direct-run fallback
# ---------------------------------------------------------------------------
try:
    from agent.models.schemas import EnrichmentResult
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent.models.schemas import EnrichmentResult

# ---------------------------------------------------------------------------
# Config file paths (resolved relative to the project root)
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

_CFG_APPROVED_MODELS    = _PROJECT_ROOT / "config" / "approved_models.json"
_CFG_VULNERABLE_MODELS  = _PROJECT_ROOT / "config" / "known_vulnerable_models.json"
_CFG_ENDPOINT           = _PROJECT_ROOT / "config" / "endpoint_config.json"
_CFG_POLICY_RULES       = _PROJECT_ROOT / "config" / "policy_rules.json"

# Policy actions that constitute a violation when matched
_VIOLATION_ACTIONS: set[str] = {"block", "alert"}

# ---------------------------------------------------------------------------
# Runtime metadata catalogue
# Keys are lowercase match tokens (substrings of runtime name / process name).
# Each entry supplies the 6 new EnrichmentResult metadata fields.
# ---------------------------------------------------------------------------
_RUNTIME_CATALOGUE: dict[str, dict] = {
    "ollama": {
        "runtime_name": "Ollama",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [11434],
        "vendor":        "Ollama, Inc.",
        "threat_level":  "HIGH",
        "recommendation": "Investigate and enforce policy",
    },
    "lm_studio": {
        "runtime_name": "LM Studio",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [1234],
        "vendor":        "LM Studio (LMSys)",
        "threat_level":  "HIGH",
        "recommendation": "Investigate",
    },
    "lm-studio": {
        "runtime_name": "LM Studio",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [1234],
        "vendor":        "LM Studio (LMSys)",
        "threat_level":  "HIGH",
        "recommendation": "Investigate",
    },
    "gpt4all": {
        "runtime_name": "GPT4All",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [4891],
        "vendor":        "Nomic AI",
        "threat_level":  "MEDIUM",
        "recommendation": "Alert security team",
    },
    "jan": {
        "runtime_name": "Jan",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [1337],
        "vendor":        "Homebrew Research",
        "threat_level":  "MEDIUM",
        "recommendation": "Alert security team",
    },
    "lmdeploy": {
        "runtime_name": "LMDeploy",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [23333],
        "vendor":        "OpenMMLab",
        "threat_level":  "HIGH",
        "recommendation": "Block and notify user",
    },
    "llama_cpp": {
        "runtime_name": "llama.cpp",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [8080],
        "vendor":        "Community / Meta (weights)",
        "threat_level":  "HIGH",
        "recommendation": "Investigate",
    },
    "llama.cpp": {
        "runtime_name": "llama.cpp",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [8080],
        "vendor":        "Community / Meta (weights)",
        "threat_level":  "HIGH",
        "recommendation": "Investigate",
    },
    "localai": {
        "runtime_name": "LocalAI",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [8080],
        "vendor":        "go-skynet",
        "threat_level":  "HIGH",
        "recommendation": "Block and notify user",
    },
    "koboldcpp": {
        "runtime_name": "KoboldCpp",
        "risk_category": "Local LLM Runtime",
        "known_ports":   [5001],
        "vendor":        "LostRuins",
        "threat_level":  "MEDIUM",
        "recommendation": "Alert security team",
    },
    "transformers": {
        "runtime_name": "HuggingFace Transformers",
        "risk_category": "AI Library",
        "known_ports":   [],
        "vendor":        "HuggingFace",
        "threat_level":  "MEDIUM",
        "recommendation": "Review process and data handling",
    },
    "langchain": {
        "runtime_name": "LangChain",
        "risk_category": "AI Orchestration Library",
        "known_ports":   [],
        "vendor":        "LangChain AI",
        "threat_level":  "MEDIUM",
        "recommendation": "Audit LLM integrations",
    },
}


# ---------------------------------------------------------------------------
# EnrichmentEngine
# ---------------------------------------------------------------------------

class EnrichmentEngine:
    """
    Enriches a raw detection with contextual security metadata.

    The engine loads all four config files on construction and caches them
    in memory.  Call reload_configs() to pick up live changes to any config
    without restarting the agent.

    Attributes (internal):
        _approved_models    : list of approved model dicts
        _vulnerable_models  : list of known-CVE model dicts
        _endpoint_cfg       : endpoint identity / criticality dict
        _policy_rules       : list of department policy rule dicts
    """

    def __init__(self) -> None:
        """Load all config files into memory on construction."""
        self._approved_models:   list[dict[str, Any]] = []
        self._vulnerable_models: list[dict[str, Any]] = []
        self._endpoint_cfg:      dict[str, Any]       = {}
        self._policy_rules:      list[dict[str, Any]] = []

        self._load_all_configs()

    # -----------------------------------------------------------------------
    # enrich
    # -----------------------------------------------------------------------

    def enrich(
        self,
        runtime:    str,
        model_file: str | None,
        host:       str,
    ) -> EnrichmentResult:
        """
        Run all four enrichment steps for a detected runtime event.

        Args:
            runtime    : Name of the detected LLM runtime
                         (e.g. 'ollama', 'lm-studio').
            model_file : Path or filename of the detected model file.
                         May be None if no model file was found.
            host       : Hostname of the endpoint where detection occurred.
                         Currently used for logging; department/criticality
                         are read from endpoint_config.json.

        Returns:
            Fully populated EnrichmentResult.
        """
        # -- Step 1: Approval check ----------------------------------------
        model_approved = self._check_approval(runtime, model_file)

        # -- Step 2: CVE check ---------------------------------------------
        has_known_cve, cve_id = self._check_cve(runtime, model_file)

        # -- Step 3: Policy check ------------------------------------------
        policy_violated, violated_rule = self._check_policy()

        # -- Step 4: Criticality check -------------------------------------
        endpoint_critical = bool(self._endpoint_cfg.get("is_critical", False))

        # -- Step 5: Runtime catalogue lookup (new metadata fields) --------
        meta = self._lookup_runtime_metadata(runtime)

        # Build the result without the summary first, then attach it.
        # model_copy(update=...) avoids a circular construction problem:
        # summarize_enrichment() needs a populated EnrichmentResult, so we
        # construct one, generate the summary from it, then return a copy
        # with the summary field populated.
        result = EnrichmentResult(
            # Security-check fields
            model_approved    = model_approved,
            has_known_cve     = has_known_cve,
            cve_id            = cve_id,
            policy_violated   = policy_violated,
            violated_rule     = violated_rule,
            endpoint_critical = endpoint_critical,
            # Runtime-metadata fields
            runtime_name      = meta["runtime_name"],
            risk_category     = meta["risk_category"],
            known_ports       = meta["known_ports"],
            vendor            = meta["vendor"],
            threat_level      = meta["threat_level"],
            recommendation    = meta["recommendation"],
        )

        # Attach the compact short summary into the JSON result.
        # The full detailed summary is still available via summarize_enrichment().
        return result.model_copy(update={"summary": self._build_short_summary(result)})

    # -----------------------------------------------------------------------
    # reload_configs
    # -----------------------------------------------------------------------

    def reload_configs(self) -> None:
        """
        Reload all four config files from disk into memory.

        Call this method to pick up live changes to policy rules, approved
        model lists, or endpoint classification without restarting the agent.

        Emits a RuntimeWarning for any config file that fails to load, but
        does not raise — the previous in-memory data is preserved for that
        file on failure.
        """
        self._load_all_configs()

    # -----------------------------------------------------------------------
    # summarize_enrichment
    # -----------------------------------------------------------------------

    def summarize_enrichment(self, result: EnrichmentResult) -> str:
        """
        Return a single human-readable line summarising an EnrichmentResult.

        Format:
            [APPROVED|UNAPPROVED] | CVE:<id|none> | Policy:<OK|VIOLATED rule_id>
            | Endpoint:<standard|CRITICAL>

        Args:
            result : A populated EnrichmentResult instance.

        Returns:
            One-line string suitable for log output or dashboard tooltips.
        """
        approval_str  = "APPROVED"  if result.model_approved  else "UNAPPROVED"
        cve_str       = result.cve_id if result.has_known_cve  else "none"
        policy_str    = (
            f"VIOLATED {result.violated_rule}" if result.policy_violated
            else "OK"
        )
        critical_str  = "CRITICAL" if result.endpoint_critical else "standard"
        ports_str     = (
            ", ".join(str(p) for p in result.known_ports)
            if result.known_ports else "none"
        )

        return (
            f"[{approval_str}] | CVE:{cve_str} | "
            f"Policy:{policy_str} | Endpoint:{critical_str} | "
            f"Runtime:{result.runtime_name} ({result.vendor}) | "
            f"Ports:{ports_str} | Threat:{result.threat_level} | "
            f"Action:{result.recommendation}"
        )

    # -----------------------------------------------------------------------
    # Internal: config loading
    # -----------------------------------------------------------------------

    def _load_all_configs(self) -> None:
        """
        Load (or reload) all four JSON config files into instance attributes.

        Missing or malformed files emit a RuntimeWarning and leave the
        corresponding attribute at its current (or default empty) value.
        """
        self._approved_models   = self._load_json_list(
            _CFG_APPROVED_MODELS, "approved_models"
        )
        self._vulnerable_models = self._load_json_list(
            _CFG_VULNERABLE_MODELS, "known_vulnerable_models"
        )
        self._endpoint_cfg      = self._load_json_dict(
            _CFG_ENDPOINT
        )
        self._policy_rules      = self._load_json_list(
            _CFG_POLICY_RULES, "policy_rules"
        )

    def _load_json_list(self, path: Path, list_key: str) -> list[dict[str, Any]]:
        """
        Load a JSON file and return the value at the given top-level key
        as a list.  Returns an empty list on any error.

        Args:
            path     : Path to the JSON file.
            list_key : Top-level key whose value is the target list.
        """
        if not path.exists():
            warnings.warn(
                f"[EnrichmentEngine] Config file not found: {path}",
                RuntimeWarning,
                stacklevel=3,
            )
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            result = data.get(list_key, [])
            if not isinstance(result, list):
                raise ValueError(f"Expected a list at key '{list_key}'")
            return result
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            warnings.warn(
                f"[EnrichmentEngine] Failed to parse {path.name}: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            return []

    def _load_json_dict(self, path: Path) -> dict[str, Any]:
        """
        Load a JSON file and return its top-level dict.
        Returns an empty dict on any error.

        Args:
            path : Path to the JSON file.
        """
        if not path.exists():
            warnings.warn(
                f"[EnrichmentEngine] Config file not found: {path}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object at top level")
            return data
        except (json.JSONDecodeError, ValueError, OSError) as exc:
            warnings.warn(
                f"[EnrichmentEngine] Failed to parse {path.name}: {exc}",
                RuntimeWarning,
                stacklevel=3,
            )
            return {}

    # -----------------------------------------------------------------------
    # Internal: enrichment steps
    # -----------------------------------------------------------------------

    def _check_approval(
        self, runtime: str, model_file: str | None
    ) -> bool:
        """
        Step 1 — Check whether the detected model is on the approved whitelist.

        Matching strategy (case-insensitive substring):
          - The detected runtime name is compared against the 'name' field of
            each approved model entry.
          - If a model_file path is provided, the filename stem is also checked
            against the 'name' field.

        Returns:
            True if any approved model entry matches the runtime or model file.
        """
        candidates: list[str] = [runtime.lower()]

        if model_file:
            # Extract just the filename (without extension) for matching
            model_stem = Path(model_file).stem.lower()
            candidates.append(model_stem)
            # Also add the raw model_file string for full-path matching
            candidates.append(model_file.lower())

        for entry in self._approved_models:
            approved_name = str(entry.get("name", "")).lower()
            if not approved_name:
                continue
            for candidate in candidates:
                if approved_name in candidate or candidate in approved_name:
                    return True

        return False

    def _check_cve(
        self, runtime: str, model_file: str | None
    ) -> tuple[bool, str | None]:
        """
        Step 2 — Check whether the detected runtime or model matches a known CVE.

        Matching strategy (case-insensitive substring):
          - The 'model_name' field of each known-vulnerable entry is checked
            against the detected runtime name and the model_file stem.

        Returns:
            Tuple of (has_known_cve: bool, cve_id: str | None).
            cve_id is the CVE identifier string if a match is found.
        """
        candidates: list[str] = [runtime.lower()]

        if model_file:
            model_stem = Path(model_file).stem.lower()
            candidates.append(model_stem)
            candidates.append(Path(model_file).name.lower())

        for entry in self._vulnerable_models:
            vuln_name = str(entry.get("model_name", "")).lower()
            if not vuln_name:
                continue
            for candidate in candidates:
                if vuln_name in candidate or candidate in vuln_name:
                    cve_id = entry.get("cve_id") or None
                    return True, cve_id

        return False, None

    def _check_policy(self) -> tuple[bool, str | None]:
        """
        Step 3 — Check whether the endpoint's department has a violated rule.

        The endpoint department is read from endpoint_config.json.
        Each policy rule is checked for a department match; if the matched
        rule's action is 'block' or 'alert', a violation is recorded.

        Matching is case-insensitive; a rule with department='*' or
        department='all' matches every endpoint.

        Returns:
            Tuple of (policy_violated: bool, violated_rule: str | None).
            violated_rule is the rule_id of the first matching violation.
        """
        department = str(
            self._endpoint_cfg.get("department", "")
        ).lower().strip()

        for rule in self._policy_rules:
            rule_dept   = str(rule.get("department", "")).lower().strip()
            rule_action = str(rule.get("action", "")).lower().strip()
            rule_id     = rule.get("rule_id")

            # Match on exact department OR wildcard
            dept_matches = (
                rule_dept == department
                or rule_dept in ("*", "all")
            )

            if dept_matches and rule_action in _VIOLATION_ACTIONS:
                return True, str(rule_id) if rule_id else None

        return False, None

    # -----------------------------------------------------------------------
    # Internal: runtime catalogue lookup
    # -----------------------------------------------------------------------

    def _lookup_runtime_metadata(self, runtime: str) -> dict:
        """
        Look up catalogue metadata for the detected runtime name.

        Matching is case-insensitive substring against the keys of
        _RUNTIME_CATALOGUE.  The first key whose value is a substring of
        the runtime string (or vice versa) wins.

        Args:
            runtime : Detected runtime name string (e.g. 'ollama', 'lm_studio').

        Returns:
            Dict with keys: runtime_name, risk_category, known_ports, vendor,
            threat_level, recommendation.  Returns safe defaults if no match.
        """
        runtime_lower = runtime.lower().replace("-", "_")

        for key, meta in _RUNTIME_CATALOGUE.items():
            key_norm = key.lower().replace("-", "_")
            if key_norm in runtime_lower or runtime_lower in key_norm:
                return meta

        # No catalogue entry found — return safe defaults
        return {
            "runtime_name":   runtime,          # use raw detected name as fallback
            "risk_category":  "Unknown Runtime",
            "known_ports":    [],
            "vendor":         "Unknown",
            "threat_level":   "MEDIUM",          # default to medium when uncertain
            "recommendation": "Investigate",
        }

    def _build_short_summary(self, result: EnrichmentResult) -> str:
        """
        Build a compact, dashboard-friendly summary string for the JSON output.

        Format:
            "<RuntimeName> detected | <ThreatLevel> risk | <Recommendation>"

        This is intentionally shorter than summarize_enrichment() which
        produces the full detailed one-line log summary.

        Args:
            result : A populated EnrichmentResult instance.

        Returns:
            Compact single-line summary string.
        """
        # Truncate recommendation to the first sentence / clause so the
        # summary stays compact even for longer recommendation strings.
        rec = result.recommendation.split("|")[0].split(".")[0].strip()

        return f"{result.runtime_name} detected | {result.threat_level} risk | {rec}"



if __name__ == "__main__":
    print("=" * 60)
    print("  EnrichmentEngine — standalone test")
    print("  Input: runtime='ollama', model='llama3.gguf', host='ENDPOINT-042'")
    print("=" * 60)

    engine = EnrichmentEngine()

    result = engine.enrich(
        runtime    = "ollama",
        model_file = "llama3.gguf",
        host       = "ENDPOINT-042",
    )

    print("\nEnrichmentResult (JSON):")
    print(json.dumps(result.model_dump(), indent=2))

    print("\nOne-line summary:")
    print(" ", engine.summarize_enrichment(result))

    print("\nConfig snapshot:")
    print(f"  Approved models loaded   : {len(engine._approved_models)}")
    print(f"  Vulnerable models loaded : {len(engine._vulnerable_models)}")
    print(f"  Policy rules loaded      : {len(engine._policy_rules)}")
    print(f"  Endpoint dept            : {engine._endpoint_cfg.get('department', 'n/a')}")
    print(f"  Endpoint is_critical     : {engine._endpoint_cfg.get('is_critical', False)}")
