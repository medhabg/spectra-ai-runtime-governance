"""
tests/conftest.py — shared pytest fixtures for Local LLM Hunter.
"""
from __future__ import annotations
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from agent.models.schemas import AIRuntimeEvent, EnrichmentResult
from database import db as _db


@pytest.fixture(scope="session")
def project_root() -> Path:
    return _PROJECT_ROOT


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Redirect all DB ops to a fresh temp file — applied to ALL tests."""
    test_db = str(tmp_path / "test.db")
    monkeypatch.setattr(_db, "DB_PATH", test_db)
    _db.init_db()
    yield test_db


@pytest.fixture
def sample_event() -> AIRuntimeEvent:
    return AIRuntimeEvent(
        host="TEST-HOST-01", runtime="Ollama", model_file="llama3.gguf",
        port_detected=11434, gpu_spike=False, lib_match=["ollama"],
        risk_score="HIGH", timestamp=datetime.now(timezone.utc).isoformat(),
        user_id="test-user", department="engineering",
        approval_status="unapproved", policy_violation=True, vuln_flag=False,
        signals_fired={"port": True, "file": True, "library": False, "gpu": False},
        signal_count=2, endpoint_criticality=False,
    )


@pytest.fixture
def sample_enrichment() -> EnrichmentResult:
    return EnrichmentResult(
        model_approved=False, has_known_cve=False, cve_id=None,
        policy_violated=False, violated_rule=None, endpoint_critical=False,
        runtime_name="Ollama", risk_category="Local LLM Runtime",
        known_ports=[11434], vendor="Ollama, Inc.", threat_level="HIGH",
        recommendation="Investigate", summary="Ollama detected | HIGH risk | Investigate",
    )
