# SPECTRA - Security Platform for Endpoint Compliance, Tracking & Runtime Analysis

## Project Summary

SPECTRA (Local LLM Hunter) is an endpoint-level Shadow AI detection and governance platform. It is designed to detect, classify, risk-score, and govern unauthorised local LLM runtimes deployed on corporate endpoints without organisational knowledge or approval.

SPECTRA is built on a multi-signal detection architecture that leverages:

- **psutil and pynvml** for real-time endpoint telemetry (ports, processes, files, GPU).
- **SQLite** for normalised event persistence with full audit trail.
- **FastAPI REST API** for programmatic access with API-key authentication.
- **Streamlit Dashboard** for a 7-tab governance interface with DPDP/GDPR compliance tracking.
- **Elasticsearch + Kibana** for SIEM integration with CEF and JSON event export.

## Problem Statement

Local LLM runtimes such as Ollama, LM Studio, GPT4All, and llama.cpp allow employees to run AI models entirely on their work laptops, binding to localhost, consuming zero egress bandwidth, and generating zero network security alerts. Enterprise firewalls, DLP systems, and cloud access brokers are architecturally blind to this activity. This creates Shadow AI: undetected, unaudited AI processing that violates GDPR Article 30 (records of processing) and India's DPDP Act Section 8 (data fiduciary obligations).

## Core Capabilities

- **Multi-Signal Detection:** 5 independent detectors (Port, SBOM, File, Network, GPU) executing concurrently with weighted scoring (max score: 10).
- **Corroboration Threshold:** Minimum 2 signals must fire before any runtime is classified MEDIUM or above, keeping the false-positive rate below 5%.
- **Weighted Risk Scoring:** Transparent formula producing 4 risk bands: LOW (monitor), MEDIUM (alert), HIGH (block), CRITICAL (isolate).
- **Policy Engine:** 4 configurable policies with editable score thresholds and signal conditions, supporting automated governance enforcement.
- **7-Tab Governance Dashboard:** Overview, Detection, Alerts, Inventory, Compliance, Policies, and SIEM Integration tabs with SOC Notification Center.
- **DPDP/GDPR Compliance Tracking:** Per-control regulatory readiness with exportable audit evidence packages, compliance reports, and incident response logs.
- **SIEM Integration:** Vendor-agnostic CEF and JSON export to Elasticsearch with automatic JSONL flat-file fallback guaranteeing zero silent event loss.
- **Alert Lifecycle Management:** Open, Acknowledged, Escalated, Resolved workflow with analyst assignment and timestamp tracking.

## System Architecture

SPECTRA is designed as a five-layer, event-driven detection system:

- **Detection Layer:** Five concurrent detectors (PortDetector, LibraryDetector, FileDetector, GPUDetector, NetworkAnalyser) producing binary signals with evidence.
- **Correlation and Enrichment Layer:** Weighted signal fusion, two-signal corroboration threshold, policy database cross-reference, and CVE enrichment.
- **Risk and Governance Layer:** Risk classification (LOW/MEDIUM/HIGH/CRITICAL) with automated policy action dispatch.
- **Persistence and API Layer:** SQLite database (5 normalised tables), FastAPI REST backend, and SIEM Exporter forwarding events to Elasticsearch.
- **Presentation Layer:** 7-tab Streamlit SPECTRA dashboard and Kibana forensic timeline analysis.

## Repository Structure

```
spectra-ai-runtime-governance/
├── agent/                  # Detection agent core
│   ├── detectors/          # 5 detection modules (port, library, file, gpu, network)
│   ├── orchestrator.py     # Pipeline orchestrator (run_full_scan)
│   ├── correlation_engine.py
│   ├── enrichment_engine.py
│   ├── risk_scorer.py
│   ├── event_writer.py
│   ├── alerter.py
│   └── siem_exporter.py
├── backend/                # FastAPI REST API
│   ├── api.py              # Route handlers (/events, /alerts, /inventory, /scan/trigger)
│   └── auth.py             # API-key authentication
├── config/                 # Configuration files
│   └── siem_config.json
├── dashboard/              # Streamlit governance UI (7 tabs + SOC Notification)
│   ├── app.py
│   └── charts.py
├── database/               # SQLite persistence
│   ├── db.py               # Database operations layer
│   ├── schema.sql          # 5-table normalised schema
│   └── seed_demo.py        # Demo data seeder (13 events, 30 alerts, 4 endpoints)
├── tests/                  # pytest test suite (60 tests, 94% coverage)
├── docs/                   # Documentation
├── logs/                   # Runtime logs and JSONL fallback
├── requirements.txt
├── _scan.py                # Quick scan entry point
├── run_tests.sh            # Linux test runner
└── run_tests.bat           # Windows test runner
```

## Target LLM Runtimes

| Runtime | Default Port | Detection Signals |
|---------|-------------|-------------------|
| Ollama | 11434 | PORT, SBOM |
| LM Studio | 1234 | PORT, FILE, SBOM |
| GPT4All | 4891 | PORT, FILE |
| Jan | 1337 | PORT, FILE |
| LMDeploy | 23333 | PORT, FILE, GPU |
| llama.cpp | 8080 | PORT, SBOM |
| KoboldCpp | 5001 | PORT |
| LocalAI | 8080 | PORT, SBOM |

## Dashboard Capabilities

- **Overview Tab:** 4 KPI cards (Total Runtimes, Unapproved, Active Alerts, Compliance Score), Risk Detection Analytics, Top Risk Runtime, Compliance Readiness, Governance Status banner, Operational Health panel.
- **Detection Tab:** Monitored endpoints, 5 detection signals with scoring weights, searchable Detection Events table, Trigger Scan button.
- **Alerts Tab:** 4-stage lifecycle (Open, Acknowledged, Escalated, Resolved), per-alert analyst assignment, Acknowledge/Escalate/Resolve workflow buttons.
- **Inventory Tab:** Runtime catalogue with version, port, GPU usage, model file paths, Approved/Unapproved status, Export SBOM.
- **Compliance Tab:** DPDP Act and GDPR Article 30 per-control tracking, regulatory readiness percentages, Full Compliance Report / Audit Evidence Package / Incident Response Log exports.
- **Policies Tab:** 4 configurable policies (LOW/MED/HIGH/CRIT) with editable thresholds, signal conditions, and enable/disable toggles.
- **SIEM Tab:** Elasticsearch health status, CEF/JSON export statistics, Kibana integration, export timeline chart, recent SIEM exports table.
- **SOC Notification Center:** Incident report creation with severity dropdown, notification channels (Email, Slack, MS Teams, PagerDuty), affected systems, and response timeline.

## Testing Coverage

- **Unit Testing:** 60/60 pytest test cases passing with 94% code coverage across 8 modules.
- **Functional Testing:** 12 test cases covering detection, false-positive validation, SIEM export, dashboard accuracy, alert lifecycle, and CSV export.
- **Live Detection:** Ollama v0.1.44 physically installed and detected with 3/4 signals firing, classified as HIGH risk in 742 ms.
- **SIEM Validation:** 126 events exported to Elasticsearch at 99.2% success rate with 3.2-second indexing latency.
- **Performance Benchmarks:** 620 ms average scan latency, 2.0% false-positive rate, 100% detection across all 8 runtimes.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/medhabg/spectra-ai-runtime-governance.git
cd spectra-ai-runtime-governance
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Seed demo database
python database/seed_demo.py

# Start dashboard
streamlit run dashboard/app.py

# Start API server
uvicorn backend.api:app --host 0.0.0.0 --port 8000

# Run detection scan
python _scan.py

# Start Elasticsearch + Kibana (optional)
docker-compose up -d

# Run tests
pytest tests/ -v --cov=agent --cov=backend
```

## Compliance Frameworks

SPECTRA aligns with:
- **DPDP Act, 2023** (Section 8: Obligations of Data Fiduciaries)
- **GDPR** (Article 30: Records of Processing Activities)
- **NIST AI RMF** (Map, Measure, Manage, Govern functions)
- **ISO/IEC 42001** (AI Management System requirements)

## Recommended Next Steps

1. Fleet deployment with PostgreSQL and centralised collection across hundreds of endpoints.
2. ML-based anomaly detection on GPU usage patterns to identify unknown runtimes.
3. Integration with EDR platforms (CrowdStrike Falcon) for SOC workflow compatibility.
4. Real-time model content analysis for DLP-style governance at the inference layer.
5. Cloud-native deployment via Kubernetes for production enterprise environments.

## Author

**Medha** - MSc Cybersecurity, REVA Academy for Corporate Excellence (RACE), REVA University

Capstone Project under the guidance of Dr. J B Simha, CTO of ABIBA Systems.
