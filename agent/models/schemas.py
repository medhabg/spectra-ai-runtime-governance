"""
agent/models/schemas.py
-----------------------
Pydantic v2 data models for the Local LLM Hunter agent.

These schemas define the canonical data structures that flow through
the detection pipeline:
  - DetectionSignal  : a single fired/unfired detection check
  - AIRuntimeEvent   : the full event record when a runtime is detected
  - EnrichmentResult : output of the enrichment/scoring layer
                       (security checks + runtime metadata)
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field
from uuid import uuid4


# ---------------------------------------------------------------------------
# DetectionSignal
# ---------------------------------------------------------------------------

class DetectionSignal(BaseModel):
    """
    Represents a single detection check (signal) within a scan pass.

    Attributes:
        signal_name : Unique name identifying the signal type
                      (e.g. 'process_match', 'port_open', 'gpu_spike').
        fired       : True if the signal was triggered, False otherwise.
        evidence    : Arbitrary key/value pairs describing what was found
                      (e.g. {'pid': 1234, 'process_name': 'ollama'}).
        timestamp   : ISO-8601 UTC timestamp of when the signal was evaluated.
    """

    signal_name: str
    fired: bool
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: str


# ---------------------------------------------------------------------------
# AIRuntimeEvent
# ---------------------------------------------------------------------------

class AIRuntimeEvent(BaseModel):
    """
    Full event record produced when an unauthorized LLM runtime is detected.

    This is the primary data structure written to the SQLite database and
    forwarded to the SIEM / dashboard.

    Attributes:
        event_id            : UUID uniquely identifying this detection event.
        host                : Hostname of the endpoint where detection occurred.
        runtime             : Name of the detected LLM runtime
                              (e.g. 'ollama', 'lm-studio', 'gpt4all').
        model_file          : Path to the detected model file, if found.
        port_detected       : TCP port the runtime API was found listening on.
        gpu_spike           : True if an abnormal GPU utilisation spike was observed.
        lib_match           : List of runtime-linked libraries matched by the scanner.
        risk_score          : Aggregated risk level: LOW | MEDIUM | HIGH | CRITICAL.
        timestamp           : ISO-8601 UTC timestamp of the detection.
        user_id             : OS user account under which the runtime process runs.
        department          : Organisational department of the endpoint owner.
        approval_status     : 'approved' | 'unapproved' | 'pending'.
        policy_violation    : True if this detection violates a department policy rule.
        vuln_flag           : True if the detected model matches a known CVE entry.
        signals_fired       : Map of signal_name → fired (bool) for this event.
        signal_count        : Total number of signals that fired (True) in this event.
        endpoint_criticality: True if the endpoint is classified as critical infrastructure.
    """

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    host: str
    runtime: str
    model_file: str | None = None
    port_detected: int | None = None
    gpu_spike: bool = False
    lib_match: list[str] = Field(default_factory=list)
    risk_score: str  # LOW | MEDIUM | HIGH | CRITICAL
    timestamp: str
    user_id: str
    department: str
    approval_status: str  # approved | unapproved | pending
    policy_violation: bool = False
    vuln_flag: bool = False
    signals_fired: dict[str, bool] = Field(default_factory=dict)
    signal_count: int = 0
    endpoint_criticality: bool = False


# ---------------------------------------------------------------------------
# EnrichmentResult
# ---------------------------------------------------------------------------

class EnrichmentResult(BaseModel):
    """
    Output produced by the enrichment layer after evaluating a raw detection.

    The enrichment layer cross-references the detected runtime/model against:
      - The approved models whitelist (approved_models.json)
      - The known vulnerable models catalogue (known_vulnerable_models.json)
      - The department policy rules (policy_rules.json)
      - The endpoint criticality flag (endpoint_config.json)
    It also attaches static runtime-catalogue metadata for the detected runtime.

    Security-check fields:
        model_approved    : True if the detected model appears in the whitelist.
        has_known_cve     : True if the model matches a known CVE entry.
        cve_id            : CVE identifier string, if has_known_cve is True.
        policy_violated   : True if the detection violates a department rule.
        violated_rule     : rule_id of the matched policy rule, if violated.
        endpoint_critical : True if the endpoint is flagged as critical.

    Runtime-metadata fields (populated from the internal runtime catalogue):
        runtime_name      : Canonical display name of the detected runtime
                            (e.g. 'llama.cpp', 'LM Studio').
        risk_category     : Human-readable category label
                            (e.g. 'Local LLM Runtime').
        known_ports       : List of well-known TCP ports for this runtime.
        vendor            : Organisation or project that publishes the runtime.
        threat_level      : Inherent threat level of the runtime as catalogued:
                            LOW | MEDIUM | HIGH | CRITICAL.
        recommendation    : Short recommended action string
                            (e.g. 'Investigate', 'Block immediately').
    """

    # -- Security-check fields ----------------------------------------------
    model_approved: bool = False
    has_known_cve: bool = False
    cve_id: str | None = None
    policy_violated: bool = False
    violated_rule: str | None = None
    endpoint_critical: bool = False

    # -- Runtime-metadata fields --------------------------------------------
    runtime_name: str = "Unknown"
    risk_category: str = "Unknown"
    known_ports: list[int] = Field(default_factory=list)
    vendor: str = "Unknown"
    threat_level: str = "MEDIUM"           # LOW | MEDIUM | HIGH | CRITICAL
    recommendation: str = "Review manually"

    # -- Human-readable one-line summary (populated by EnrichmentEngine) ----
    summary: str = ""
