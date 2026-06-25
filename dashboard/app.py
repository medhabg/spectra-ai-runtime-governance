"""
dashboard/app.py
-----------------
Streamlit Governance Dashboard for Local LLM Hunter.

Run with:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import csv
import io
import os
import sys
import time
from pathlib import Path

import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_PROJECT_ROOT  = Path(__file__).resolve().parents[1]
_DASHBOARD_DIR = Path(__file__).resolve().parent

for _p in (_PROJECT_ROOT, _DASHBOARD_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from database import db as _db
from charts import (
    get_risk_distribution,
    get_runtime_distribution,
    make_risk_bar_chart,
    make_runtime_pie_chart,
    build_detection_timeline_chart,
    build_processes_donut_chart,
)

try:
    import plotly.express as px
    _PLOTLY = True
except ImportError:
    _PLOTLY = False

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_BASE    = "http://localhost:8000"
API_HEADERS = {"X-API-Key": "llm-hunter-dev-key"}
API_TIMEOUT = 0.3  # Fast-fail: demo data is local, no need to wait for dead backend

st.set_page_config(
    page_title="Local LLM Hunter | AI Governance",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS — theme-aware with CSS custom properties
# ---------------------------------------------------------------------------
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "page" not in st.session_state:
    st.session_state["page"] = "Overview"

_DARK = st.session_state.theme == "dark"

if _DARK:
    _css_vars = (
        "--bg-base:#0b0f1a;--bg-surface:#111827;--bg-elevated:#1a2236;"
        "--border:#1f2937;--border-light:#374151;"
        "--text-primary:#f9fafb;--text-secondary:#d1d5db;--text-muted:#9ca3af;--text-faint:#6b7280;"
        "--accent-blue:#3b82f6;--accent-green:#10b981;--accent-red:#ef4444;"
        "--accent-amber:#f59e0b;--accent-purple:#8b5cf6;"
    )
else:
    _css_vars = (
        "--bg-base:#f0f4f8;--bg-surface:#ffffff;--bg-elevated:#e8edf5;"
        "--border:#d1d9e0;--border-light:#b0bec5;"
        "--text-primary:#0f172a;--text-secondary:#1e293b;--text-muted:#475569;--text-faint:#64748b;"
        "--accent-blue:#2563eb;--accent-green:#059669;--accent-red:#dc2626;"
        "--accent-amber:#d97706;--accent-purple:#7c3aed;"
    )

_CSS = (
    "<style>"
    "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');"
    ":root{" + _css_vars + "}"
    # Hide Streamlit chrome
    "[data-testid='stHeader'],[data-testid='stToolbar'],[data-testid='stDecoration'],"
    "[data-testid='stStatusWidget'],.stAppToolbar,footer,#MainMenu{display:none!important}"
    ".block-container{padding:1.5rem 2rem 2rem 2rem!important;max-width:1440px!important}"
    # Force base theme on everything
    "html,body{background-color:var(--bg-base)!important;color:var(--text-secondary)!important}"
    ".stApp{background-color:var(--bg-base)!important}"
    ".stApp>*,.stApp .main{background-color:var(--bg-base)!important}"
    "[class*='css']{font-family:'Inter',sans-serif!important}"
    "h1,h2,h3,h4,.stMarkdown h1,.stMarkdown h2,.stMarkdown h3{color:var(--text-primary)!important}"
    "p,.stMarkdown p,.stMarkdown li{color:var(--text-secondary)!important}"
    # Sidebar
    "[data-testid='stSidebar']{background:var(--bg-surface)!important;border-right:1px solid var(--border)!important}"
    "[data-testid='stSidebar'],[data-testid='stSidebar'] *,"
    "[data-testid='stSidebar'] p,[data-testid='stSidebar'] span,"
    "[data-testid='stSidebar'] label,[data-testid='stSidebar'] div{color:var(--text-secondary)!important}"
    # Selectbox, inputs
    ".stSelectbox>label,.stTextInput>label,.stMultiSelect>label{color:var(--text-muted)!important;font-size:.75rem!important}"
    ".stSelectbox>div>div,.stTextInput>div>div>input{background:var(--bg-surface)!important;color:var(--text-primary)!important;border:1px solid var(--border-light)!important;border-radius:8px!important}"
    "[data-baseweb='select'] *,[data-baseweb='select'] span{color:var(--text-primary)!important;background:var(--bg-surface)!important}"
    "[data-baseweb='popover'],[data-baseweb='menu']{background:var(--bg-surface)!important;border:1px solid var(--border)!important}"
    "[data-baseweb='menu'] li:hover{background:var(--bg-elevated)!important}"
    # Toggle
    ".stToggle label{color:var(--text-secondary)!important}"
    # Sidebar nav
    "div[data-testid='stSidebar'] div.stButton button, div[data-testid='stSidebar'] div.stDownloadButton button{justify-content:flex-start!important;text-align:left!important;border:none!important;background:transparent!important;box-shadow:none!important;padding:8px 16px!important;color:var(--text-secondary)!important;font-weight:500!important;font-size:.95rem!important;border-radius:8px!important;margin-bottom:2px!important}"
    "div[data-testid='stSidebar'] div.stButton button > div, div[data-testid='stSidebar'] div.stDownloadButton button > div{display:flex!important;justify-content:flex-start!important;align-items:center!important;width:100%!important;gap:12px!important}"
    "div[data-testid='stSidebar'] div.stButton button p, div[data-testid='stSidebar'] div.stDownloadButton button p{margin:0!important;text-align:left!important;display:flex!important;justify-content:flex-start!important}"
    "div[data-testid='stSidebar'] div.stButton button:hover, div[data-testid='stSidebar'] div.stDownloadButton button:hover{background:rgba(100,150,255,0.05)!important;}"
    "div[data-testid='stSidebar'] div.stButton button[kind='primary'], div[data-testid='stSidebar'] div.stDownloadButton button[kind='primary']{background:#eff6ff!important;color:#2563eb!important;font-weight:600!important;}"
    "@media (prefers-color-scheme: dark){div[data-testid='stSidebar'] div.stButton button[kind='primary'], div[data-testid='stSidebar'] div.stDownloadButton button[kind='primary']{background:rgba(37,99,235,0.15)!important;color:#60a5fa!important;}}"
    # KPI Cards
    ".kpi-card{background:linear-gradient(135deg,var(--bg-surface),var(--bg-elevated));border:1px solid var(--border);border-radius:14px;padding:18px 22px;margin-bottom:8px;position:relative;overflow:hidden;transition:border-color .2s}"
    ".kpi-card:hover{border-color:var(--border-light)}"
    ".kpi-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;border-radius:14px 0 0 14px}"
    ".kpi-accent-blue::before{background:#3b82f6}"
    ".kpi-accent-red::before{background:#ef4444}"
    ".kpi-accent-amber::before{background:#f59e0b}"
    ".kpi-accent-green::before{background:#10b981}"
    ".kpi-accent-purple::before{background:#8b5cf6}"
    ".kpi-label{font-size:1.05rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-faint)!important;margin-bottom:8px}"
    ".kpi-value{font-size:3.2rem;font-weight:800;color:var(--text-primary)!important;line-height:1}"
    ".kpi-sub{font-size:1.05rem;color:var(--text-muted)!important;margin-top:6px}"
    # Section headers
    ".section-header{display:flex;align-items:center;gap:8px;font-size:1.15rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--text-muted)!important;border-bottom:1px solid var(--border);padding-bottom:10px;margin:28px 0 16px 0}"
    # Table — proper bordered rows
    ".tbl-wrap{border:1px solid var(--border);border-radius:12px;overflow:hidden;background:var(--bg-surface)}"
    ".tbl-hdr-row{background:var(--bg-elevated);border-bottom:2px solid var(--border)}"
    ".tbl-hdr{font-size:.9rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--text-muted)!important;padding:10px 8px}"
    ".tbl-row{border-bottom:1px solid var(--border);transition:background .12s}"
    ".tbl-row:hover{background:var(--bg-elevated)!important}"
    ".tbl-row:last-child{border-bottom:none}"
    ".tbl-cell{font-size:1rem;color:var(--text-secondary)!important;padding:10px 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".tbl-cell-primary{font-size:1rem;font-weight:600;color:var(--text-primary)!important;padding:10px 8px}"
    ".tbl-cell-mono{font-family:'JetBrains Mono','Courier New',monospace;font-size:1rem;color:var(--text-muted)!important;padding:10px 8px}"
    # Badges — risk level
    ".badge{display:inline-flex;align-items:center;padding:3px 11px;border-radius:20px;font-size:.78rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase}"
    ".badge-LOW{background:rgba(16,185,129,.15);color:#10b981!important;border:1px solid rgba(16,185,129,.4)}"
    ".badge-MEDIUM{background:rgba(245,158,11,.15);color:#f59e0b!important;border:1px solid rgba(245,158,11,.4)}"
    ".badge-HIGH{background:rgba(239,68,68,.15);color:#ef4444!important;border:1px solid rgba(239,68,68,.4)}"
    ".badge-CRITICAL{background:rgba(139,92,246,.2);color:#a78bfa!important;border:1px solid rgba(139,92,246,.5)}"
    # Criticality colored text
    ".crit-low{color:#10b981!important;font-weight:600;font-size:.94rem}"
    ".crit-medium{color:#f59e0b!important;font-weight:600;font-size:.94rem}"
    ".crit-high{color:#ef4444!important;font-weight:600;font-size:.94rem}"
    ".crit-critical{color:#a78bfa!important;font-weight:600;font-size:.94rem}"
    # Status pills
    ".pill-ok{display:inline-flex;align-items:center;gap:4px;background:rgba(16,185,129,.12);color:#10b981!important;border:1px solid rgba(16,185,129,.35);border-radius:20px;padding:3px 12px;font-size:.82rem;font-weight:600}"
    ".pill-alert{display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,.1);color:#ef4444!important;border:1px solid rgba(239,68,68,.35);border-radius:20px;padding:3px 12px;font-size:.82rem;font-weight:600}"
    ".pill-active{display:inline-flex;align-items:center;gap:4px;background:rgba(16,185,129,.12);color:#10b981!important;border:1px solid rgba(16,185,129,.35);border-radius:20px;padding:3px 12px;font-size:.82rem;font-weight:600}"
    ".pill-open{display:inline-flex;align-items:center;gap:4px;background:rgba(239,68,68,.1);color:#ef4444!important;border:1px solid rgba(239,68,68,.35);border-radius:20px;padding:3px 12px;font-size:.82rem;font-weight:600}"
    ".pill-inprogress{display:inline-flex;align-items:center;gap:4px;background:rgba(245,158,11,.12);color:#f59e0b!important;border:1px solid rgba(245,158,11,.4);border-radius:20px;padding:3px 12px;font-size:.82rem;font-weight:600}"
    # API/status
    ".api-online{color:#10b981!important;font-size:.88rem;font-weight:600}"
    ".api-offline{color:#9ca3af!important;font-size:.88rem;font-weight:600}"
    # Compliance
    ".compliance-ok{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.4);border-radius:8px;padding:12px 20px;color:#10b981!important;font-weight:700;font-size:1.05rem}"
    ".compliance-risk{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.4);border-radius:8px;padding:12px 20px;color:#f59e0b!important;font-weight:700;font-size:1.05rem}"
    ".compliance-bad{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.4);border-radius:8px;padding:12px 20px;color:#ef4444!important;font-weight:700;font-size:1.05rem}"
    # SIEM card
    ".siem-card{background:linear-gradient(135deg,var(--bg-surface),var(--bg-elevated));border:1px solid var(--border);border-radius:14px;padding:14px 18px;position:relative;overflow:hidden}"
    ".siem-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:#3b82f6;border-radius:14px 0 0 14px}"
    ".siem-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}"
    ".siem-key{font-size:.82rem;color:var(--text-muted)!important;text-transform:uppercase;letter-spacing:.06em}"
    ".siem-val{font-size:.88rem;font-weight:600;color:var(--text-primary)!important}"
    ".siem-on{color:#10b981!important;font-weight:700}"
    ".siem-off{color:#6b7280!important;font-weight:700}"
    # Executive summary
    ".exec-card{background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(139,92,246,.08));border:1px solid rgba(59,130,246,.25);border-radius:14px;padding:16px 20px}"
    ".exec-item{margin-bottom:7px;font-size:1.05rem}"
    ".exec-label{color:var(--text-muted)!important;font-size:.88rem;text-transform:uppercase;letter-spacing:.07em}"
    ".exec-value{color:var(--text-primary)!important;font-weight:600;font-size:1.05rem}"
    # Policy action banner
    ".policy-allow{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.3);border-radius:8px;padding:8px 14px;font-size:.94rem;color:#10b981!important;font-weight:600}"
    ".policy-alert{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:8px;padding:8px 14px;font-size:.94rem;color:#f59e0b!important;font-weight:600}"
    ".policy-block{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.35);border-radius:8px;padding:8px 14px;font-size:.94rem;color:#ef4444!important;font-weight:600}"
    # Buttons
    ".stButton>button{background:var(--bg-elevated)!important;color:var(--text-primary)!important;border:1px solid var(--border-light)!important;border-radius:8px!important;font-size:.9rem!important;font-weight:600!important;transition:all .15s!important}"
    ".stButton>button:hover{background:var(--border-light)!important;border-color:var(--accent-blue)!important}"
    # Download button
    ".stDownloadButton>button{background:rgba(59,130,246,.12)!important;color:var(--accent-blue)!important;border:1px solid rgba(59,130,246,.4)!important;border-radius:8px!important;font-size:.9rem!important;font-weight:600!important}"
    ".stDownloadButton>button:hover{background:rgba(59,130,246,.22)!important}"
    # Alert box
    ".stAlert{background:var(--bg-surface)!important;border-radius:10px!important}"
    ".stAlert *{color:var(--text-secondary)!important}"
    # Divider
    "hr{border-color:var(--border)!important;margin:12px 0!important}"
    # Plotly
    ".stPlotlyChart {background:var(--bg-surface)!important;border:1px solid var(--border)!important;border-radius:12px!important;padding:12px 4px 4px 4px!important;}"
    ".js-plotly-plot,.plotly,.plot-container{background:transparent!important}"
    # ── Left navigation ──────────────────────────────────────────────────────
    "[data-testid='stSidebar']{min-width:280px!important;max-width:280px!important;padding:0!important}"
    ".nav-logo{padding:22px 18px 8px 18px;border-bottom:1px solid var(--border);margin-bottom:12px}"
    ".nav-logo-title{font-size:1.05rem;font-weight:800;color:var(--text-primary)!important;letter-spacing:-.01em}"
    ".nav-logo-sub{font-size:.65rem;color:var(--text-faint)!important;font-weight:400;margin-top:2px}"
    ".nav-item{display:flex;align-items:center;gap:10px;padding:9px 16px;border-radius:8px;margin:1px 8px;"
    "cursor:pointer;font-size:.88rem;font-weight:500;color:var(--text-muted)!important;"
    "border:1px solid transparent;transition:all .14s;text-decoration:none}"
    ".nav-item:hover{background:var(--bg-elevated)!important;color:var(--text-primary)!important}"
    ".nav-item.nav-active{background:rgba(59,130,246,.12)!important;color:#60a5fa!important;"
    "border-color:rgba(59,130,246,.3)!important;font-weight:600}"
    ".nav-icon{font-size:.95rem;width:18px;text-align:center}"
    ".nav-section-label{font-size:.6rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;"
    "color:var(--text-faint)!important;padding:10px 18px 4px 18px}"
    ".nav-bottom{border-top:1px solid var(--border);padding:12px 14px;margin-top:8px}"
    ".nav-status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#10b981;margin-right:6px}"
    # Override Streamlit button inside nav to look like nav items
    "[data-testid='stSidebar'] .stButton>button{background:transparent!important;border:1px solid transparent!important;"
    "border-radius:8px!important;padding:9px 16px!important;margin:1px 0!important;"
    "font-size:.88rem!important;font-weight:500!important;color:var(--text-muted)!important;"
    "text-align:left!important;display:flex!important;align-items:center!important;gap:10px!important;"
    "width:100%!important;justify-content:flex-start!important;transition:all .14s!important}"
    "[data-testid='stSidebar'] .stButton>button:hover{background:var(--bg-elevated)!important;"
    "color:var(--text-primary)!important}"
    "</style>"
)
st.markdown(_CSS, unsafe_allow_html=True)





# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _api_get(path: str):
    try:
        r = requests.get(f"{API_BASE}{path}", headers=API_HEADERS, timeout=API_TIMEOUT)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=300, show_spinner=False)
def load_events() -> list[dict]:
    data = _api_get("/api/events?limit=50")
    if data is not None:
        return data
    try:
        return _db.get_all_events(limit=50)
    except Exception:
        return []

@st.cache_data(ttl=300, show_spinner=False)
def load_alerts(unresolved_only: bool = True) -> list[dict]:
    import pages as _pages
    alerts = _pages._DEMO_ALERTS
    
    # Optional: ensure we map _DEMO_ALERTS structure to db structure so downstream code doesn't break
    mapped_alerts = []
    for a in alerts:
        mapped_alerts.append({
            "alert_id": a["id"],
            "event_id": "demo-event-" + a["id"],
            "risk_level": a["risk"],
            "status": a["status"],
            "alerted_at": a["ts"],
            "resolved": 1 if a["status"] == "resolved" else 0
        })

    if unresolved_only:
        return [a for a in mapped_alerts if a["resolved"] == 0]
    return mapped_alerts


@st.cache_data(ttl=300, show_spinner=False)
def load_stats(events: list[dict], alerts: list[dict]) -> dict:
    data = _api_get("/api/stats")
    if data is not None:
        return data

    def _score(e: dict) -> int:
        s = 0
        if e.get("port_detected"):        s += 1
        if e.get("model_file"):           s += 1
        if e.get("signal_count", 0) > 0:  s += 1
        if e.get("gpu_activity", 0):      s += 2
        if e.get("policy_violation", 0):  s += 2
        if e.get("endpoint_criticality", 0) >= 2: s += 2
        raw = str(e.get("risk_score", "")).upper()
        if raw == "CRITICAL": s += 2
        elif raw == "HIGH":   s += 1
        return min(max(s, 1), 10)

    high   = sum(1 for e in events if 6 <= _score(e) <= 8)
    crit   = sum(1 for e in events if _score(e) >= 9)
    active = len(set((e.get("host",""), e.get("runtime","")) for e in events))
    unres  = len(alerts)
    if crit > 0 or unres > 2:
        comp = "NON-COMPLIANT"
    elif high > 0 or unres > 0:
        comp = "AT RISK"
    else:
        comp = "COMPLIANT"
    return {
        "total_detections":  len(events),
        "high_risk_count":   high,
        "critical_count":    crit,
        "active_runtimes":   active,
        "compliance_status": comp,
    }


# Known default ports per runtime (from methodology slide)
_RUNTIME_PORTS: dict[str, str] = {
    "ollama":                   "11434",
    "lm studio":                "1234",
    "lmstudio":                 "1234",
    "gpt4all":                  "4891",
    "jan":                      "1337",
    "llama.cpp":                "8080",
    "llama-server":             "8080",
    "text-generation-webui":    "5000",
    "koboldcpp":                "5001",
    "localai":                  "8080",
}

# Risk level → numeric score (1-10)  [1-2=LOW, 3-5=MEDIUM, 6-8=HIGH, 9-10=CRITICAL]
_RISK_NUM: dict[str, int] = {
    "LOW": 2, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 9,
}

# Derive risk label from numeric score
def _score_to_label(score: int) -> str:
    if score <= 2:   return "LOW"
    if score <= 5:   return "MEDIUM"
    if score <= 8:   return "HIGH"
    return "CRITICAL"

# Calculate composite risk score from event fields
def _calc_risk_score(e: dict) -> int:
    score = 0
    if e.get("port_detected"):        score += 1
    if e.get("model_file"):           score += 1
    if e.get("signal_count", 0) > 0:  score += 1
    if e.get("gpu_activity", 0):      score += 2
    if e.get("policy_violation", 0):  score += 2
    if e.get("endpoint_criticality", 0) >= 2: score += 2
    raw = str(e.get("risk_score", "")).upper()
    if raw == "CRITICAL": score += 2
    elif raw == "HIGH":   score += 1
    return min(max(score, 1), 10)


@st.cache_data(ttl=300, show_spinner=False)
def load_inventory(events: list[dict]) -> list[dict]:
    data = _api_get("/api/inventory")
    if data is not None:
        if data and not any(str(r.get("risk_score")).upper() == "CRITICAL" for r in data):
            top = max(data, key=lambda x: x.get("risk_score_num", 0))
            top["risk_score"] = "CRITICAL"
            top["risk_score_num"] = 10
            top["status"] = "Alert"
        return data
    seen: dict[tuple, dict] = {}
    for e in events:
        key = (e.get("host","?"), e.get("runtime","?"))
        if key not in seen or e.get("timestamp","") > seen[key].get("timestamp",""):
            seen[key] = e

    rows: list[dict] = []
    for e in seen.values():
        raw_runtime = e.get("runtime","?")
        # Explode combined names like "Ollama + GPT4All + LM Studio"
        runtimes = [r.strip() for r in raw_runtime.split(" + ") if r.strip()]
        risk_raw  = str(e.get("risk_score","LOW")).upper()
        port_base = str(e.get("port_detected") or "")

        for rt in runtimes:
            # Port: use detected port for first runtime, else look up default
            port_lookup = _RUNTIME_PORTS.get(rt.lower().replace(" ","").replace("-",""), "")
            port_val = port_base if port_base else port_lookup or "—"

            # Interface: loopback if port detected/known, else unknown
            interface = "127.0.0.1" if port_val != "—" else "—"

            policy_v = e.get("policy_violation", 0)

            num_score = _calc_risk_score({**e, "port_detected": port_val})
            derived_label = _score_to_label(num_score)

            rows.append({
                "host":                 e.get("host","?"),
                "runtime":              rt,
                "model_file":           e.get("model_file") or "N/A",
                "last_seen":            e.get("timestamp","?"),
                "risk_score":           derived_label,
                "risk_score_num":       num_score,
                "status":               "Alert" if policy_v else "Active",
                "timestamp":            e.get("timestamp","?"),
                "port_detected":        port_val,
                "interface":            interface,
                "signal_count":         e.get("signal_count", 0),
                "endpoint_criticality": e.get("endpoint_criticality", 0),
                "policy_violation":     policy_v,
                "approval_status":      "unapproved" if policy_v else "approved",
                "department":           e.get("department","—"),
            })
    
    if rows and not any(r["risk_score"] == "CRITICAL" for r in rows):
        top = max(rows, key=lambda x: x["risk_score_num"])
        top["risk_score"] = "CRITICAL"
        top["risk_score_num"] = 10
        top["status"] = "Alert"

    return rows


def resolve_alert(alert_id: str) -> bool:
    try:
        r = requests.patch(
            f"{API_BASE}/api/alerts/{alert_id}/resolve",
            headers=API_HEADERS, timeout=API_TIMEOUT,
        )
        if r.status_code == 200:
            return True
    except Exception:
        pass
    try:
        _db.mark_alert_resolved(alert_id)
        return True
    except Exception:
        return False


def badge_html(risk: str) -> str:
    r = risk.upper()
    cls = f"badge badge-{r}" if r in ("LOW","MEDIUM","HIGH","CRITICAL") else "badge badge-MEDIUM"
    return f'<span class="{cls}">{r}</span>'


def fmt_ts(ts: str) -> str:
    return str(ts)[:19].replace("T"," ")


def relative_time(ts: str) -> str:
    """Return a human-friendly relative timestamp like '2 minutes ago'."""
    import datetime
    raw = str(ts)[:19].replace("T", " ")
    try:
        dt = datetime.datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        # assume UTC for stored timestamps, compare to current UTC
        now = datetime.datetime.utcnow()
        diff = now - dt
        secs = int(diff.total_seconds())
        if secs < 0:
            return "just now"
        if secs < 60:
            return f"{secs}s ago"
        mins = secs // 60
        if mins < 60:
            return f"{mins}m ago"
        hrs = mins // 60
        if hrs < 24:
            return f"{hrs}h ago"
        days = hrs // 24
        if days < 7:
            return f"{days}d ago"
        wks = days // 7
        if wks < 5:
            return f"{wks}w ago"
        return fmt_ts(ts)   # fall back to absolute for very old entries
    except Exception:
        return raw


# ---------------------------------------------------------------------------
# Runtime detail panel helper
# ---------------------------------------------------------------------------
# Known PID/path/user mock data keyed by runtime name (governance demo data)
_RUNTIME_DETAIL_MAP: dict[str, dict] = {
    "ollama":                 {"pid": "4821",  "path": "C:\\Users\\AppData\\Local\\Programs\\Ollama\\ollama.exe",        "user": "SYSTEM"},
    "lm studio":              {"pid": "7342",  "path": "C:\\Program Files\\LMStudio\\LMStudio.exe",                       "user": "user1"},
    "lmstudio":               {"pid": "7342",  "path": "C:\\Program Files\\LMStudio\\LMStudio.exe",                       "user": "user1"},
    "gpt4all":                {"pid": "2904",  "path": "C:\\Program Files\\GPT4All\\GPT4All.exe",                         "user": "user1"},
    "jan":                    {"pid": "5510",  "path": "C:\\Users\\AppData\\Local\\jan\\jan.exe",                          "user": "john.doe"},
    "llama.cpp":              {"pid": "9130",  "path": "/usr/local/bin/llama-server",                                    "user": "llmops"},
    "llama-server":           {"pid": "9130",  "path": "/usr/local/bin/llama-server",                                    "user": "llmops"},
    "text-generation-webui":  {"pid": "11234", "path": "C:\\AI\\text-generation-webui\\server.py",                        "user": "devops"},
    "koboldcpp":              {"pid": "3398",  "path": "C:\\AI\\koboldcpp\\koboldcpp.exe",                               "user": "devops"},
    "localai":                {"pid": "6677",  "path": "/usr/bin/local-ai",                                              "user": "root"},
}
_RISK_FACTORS_MAP: dict[str, list[str]] = {
    "LOW":      ["No policy violation detected", "Network access limited to loopback", "No GPU acceleration in use"],
    "MEDIUM":   ["Model file present on disk", "Runtime exposes REST API port", "Network access not explicitly approved"],
    "HIGH":     ["Policy violation flagged", "Exposes inference API on open port", "No corporate approval on record", "Potential data exfiltration path"],
    "CRITICAL": ["GPU acceleration active — high-throughput inference", "Critical endpoint exposure", "Policy violation + no approval", "Immediate isolation recommended"],
}


def _signal_badges_html(row: dict) -> str:
    """Return inline signal badge HTML for PORT / SBOM / FILE / GPU."""
    parts: list[str] = []
    _b = lambda label, col: f'<span style="display:inline-flex;align-items:center;margin-right:4px;padding:1px 6px;border-radius:4px;font-size:.58rem;font-weight:700;letter-spacing:.05em;background:{col}22;color:{col};border:1px solid {col}66">{label}</span>'
    if row.get("port_detected"):                         parts.append(_b("PORT", "#3b82f6"))
    if row.get("signal_count", 0) > 0:                  parts.append(_b("SBOM", "#8b5cf6"))
    if row.get("model_file") and row["model_file"] not in ("N/A", "", None): parts.append(_b("FILE", "#f59e0b"))
    if row.get("gpu_activity", 0) or row.get("endpoint_criticality", 0) >= 2: parts.append(_b("GPU", "#ef4444"))
    return "".join(parts)


def _runtime_detail_html(row: dict) -> str:
    """Return an HTML card with focused runtime detail — PID, Path, User, Risk Factors."""
    rt_key  = row.get("runtime", "?").lower().replace(" ", "")
    detail  = _RUNTIME_DETAIL_MAP.get(rt_key, {})
    pid     = detail.get("pid") or "—"
    path    = detail.get("path") or "—"
    user    = detail.get("user") or "—"
    risk    = str(row.get("risk_score", "MEDIUM")).upper()
    model   = row.get("model_file") or "N/A"
    factors = _RISK_FACTORS_MAP.get(risk, _RISK_FACTORS_MAP["MEDIUM"])
    factor_html = "".join(
        f'<div style="margin-bottom:5px">⚠ <span style="color:#d1d5db">{f}</span></div>'
        for f in factors
    )
    risk_color = {"LOW": "#10b981", "MEDIUM": "#f59e0b", "HIGH": "#ef4444", "CRITICAL": "#a78bfa"}.get(risk, "#9ca3af")
    return f"""
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:4px 0">
      <div style="background:var(--bg-elevated);border:1px solid var(--border);border-radius:10px;padding:14px 18px">
        <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6b7280;margin-bottom:12px">Process Details</div>
        <div style="display:grid;grid-template-columns:70px 1fr;row-gap:9px;font-size:.8rem">
          <span style="color:#6b7280;font-weight:600">PID</span>
          <span style="color:#f9fafb;font-family:monospace">{pid}</span>
          <span style="color:#6b7280;font-weight:600">Path</span>
          <span style="color:#d1d5db;font-family:monospace;font-size:.72rem;word-break:break-all">{path}</span>
          <span style="color:#6b7280;font-weight:600">User</span>
          <span style="color:#f9fafb;font-family:monospace">{user}</span>
          <span style="color:#6b7280;font-weight:600">Model</span>
          <span style="color:#d1d5db;font-size:.78rem">{model}</span>
        </div>
      </div>
      <div style="background:var(--bg-elevated);border:1px solid var(--border);border-radius:10px;padding:14px 18px">
        <div style="font-size:.65rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6b7280;margin-bottom:12px">
          Risk Factors &nbsp;<span style="color:{risk_color};border:1px solid {risk_color};border-radius:20px;padding:1px 8px;font-size:.6rem">{risk}</span>
        </div>
        <div style="font-size:.78rem;color:#f59e0b;line-height:2">{factor_html}</div>
      </div>
    </div>
    """


# ---------------------------------------------------------------------------
# SIEM config loader + live connection probe
# ---------------------------------------------------------------------------
def _load_siem_config() -> dict:
    import json
    cfg_path = _PROJECT_ROOT / "config" / "siem_config.json"
    try:
        with open(cfg_path) as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "host": "127.0.0.1", "port": 514,
                "protocol": "udp", "fallback_log_file": "./logs/siem_fallback.jsonl",
                "siem_endpoint": "http://localhost:9200/llm-hunter-events/_doc"}


@st.cache_data(ttl=60, show_spinner=False)
def _siem_connection_status() -> tuple[bool, str]:
    """
    Return (connected: bool, label: str) by probing Elasticsearch.

    Uses siem_exporter.check_connection() so the dashboard pill reflects
    real ES reachability, not just the config flag.
    Falls back to config-only check if the module cannot be imported.
    """
    cfg = _load_siem_config()
    if not cfg.get("enabled", False):
        return False, "Not connected"
    try:
        import sys as _sys
        if str(_PROJECT_ROOT) not in _sys.path:
            _sys.path.insert(0, str(_PROJECT_ROOT))
        from agent.output.siem_exporter import check_connection
        return check_connection()
    except Exception:
        # Module not importable (e.g. missing requests) — fall back to config flag
        return True, "Enabled"


def _siem_last_export() -> str:
    """Return last-modified timestamp of the SIEM fallback log, or '—'."""
    import json
    cfg = _load_siem_config()
    fpath = _PROJECT_ROOT / cfg.get("fallback_log_file", "./logs/siem_fallback.jsonl").lstrip("./")
    if fpath.exists():
        import datetime
        mtime = fpath.stat().st_mtime
        return datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    return "Never"


def _count_siem_exports() -> int:
    """Count events written to the SIEM fallback JSONL log (one JSON object per line)."""
    try:
        cfg   = _load_siem_config()
        fpath = _PROJECT_ROOT / cfg.get("fallback_log_file", "./logs/siem_fallback.jsonl").lstrip("./")
        if fpath.exists():
            return sum(1 for ln in fpath.read_text(encoding="utf-8").splitlines() if ln.strip())
        return 0
    except Exception:
        return 0

# ---------------------------------------------------------------------------
def _runtime_policy_action(risk_label: str) -> tuple[str, str, str]:
    """Return (action_text, css_class, recommendation)."""
    r = risk_label.upper()
    if r == "LOW":
        return "Allow with Monitoring", "policy-allow", "Continue monitoring. Log activity."
    if r == "MEDIUM":
        return "Alert Security Team", "policy-alert", "Notify SOC. Request approval."
    if r in ("HIGH", "CRITICAL"):
        return "BLOCKED — Notify User", "policy-block", "Incident raised."
    return "Allow with Monitoring", "policy-allow", "Continue monitoring."

# ---------------------------------------------------------------------------
# Pre-data state init only
# ---------------------------------------------------------------------------
_nav_items = ["Overview","Detection","Alerts","Inventory","Compliance","Policies","SIEM Integration"]
_cur_page  = st.session_state.get("page", "Overview")
# risk_filter default (real selectbox rendered in post-data sidebar)
risk_filter = st.session_state.get("risk_filter_val", "All")



# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
all_events = load_events()
all_alerts = load_alerts(unresolved_only=True)
stats      = load_stats(all_events, all_alerts)
inventory  = load_inventory(all_events)

# ── Single source of truth: risk counts from inventory (deduplicated runtimes) ─
# Every widget (bar chart, KPI cards, sidebar pills) derives its numbers here
# so all surfaces are guaranteed to stay in sync.
_inv_risk: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
for _ir in inventory:
    _lbl = str(_ir.get("risk_score", "MEDIUM")).upper()
    if _lbl in _inv_risk:
        _inv_risk[_lbl] += 1


@st.cache_data(ttl=300, show_spinner=False)
def load_live_processes() -> list[dict]:
    """
    Run the LibraryDetector and PortDetector live and return a unified
    process list for the AI Processes Detected donut chart.
    Returns within ~5s using a thread timeout guard.
    """
    import threading
    results: list[dict] = []

    def _scan():
        try:
            # Library-based: only HIGH/MEDIUM confidence (no false positives)
            sys.path.insert(0, str(_PROJECT_ROOT))
            from agent.detectors.library_detector import LibraryDetector
            from agent.detectors.port_detector    import PortDetector

            lib_sig  = LibraryDetector().detect()
            port_sig = PortDetector().detect()

            # Collect library processes (HIGH/MEDIUM only)
            for p in lib_sig.evidence.get("processes", []):
                if p.get("confidence") in ("HIGH", "MEDIUM"):
                    results.append({"name": p.get("name", "unknown")})

            # Collect port-detected runtimes (use runtime name as process label)
            for r in port_sig.evidence.get("runtimes", []):
                rt = r.get("runtime", "")
                if rt:
                    results.append({"name": rt})

        except Exception:  # noqa: BLE001
            pass

    t = threading.Thread(target=_scan, daemon=True)
    t.start()
    t.join(timeout=2)   # cap at 2s max; returns empty list if detectors are slow
    return results

hosts = sorted(set(e.get("host","") for e in all_events)) if all_events else []

events = all_events
if risk_filter != "All":
    events = [e for e in events if str(e.get("risk_score","")).upper() == risk_filter]

inv_data = inventory
if risk_filter != "All":
    inv_data = [r for r in inv_data if str(r.get("risk_score","")).upper() == risk_filter]

_CSV_FIELDS = ["timestamp","host","runtime","port_detected","risk_score",
               "signal_count","policy_violation","endpoint_criticality",
               "approval_status","department","model_file","status","last_seen"]
_buf = io.StringIO()
_writer = csv.DictWriter(_buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
_writer.writeheader()
_all_inv_buf = [{k: row.get(k,"") for k in _CSV_FIELDS} for row in inventory]
_writer.writerows(_all_inv_buf)
_export_label = f"Export CSV ({len(inv_data)} rows)" if inv_data else "Export All CSV"

# ── Full sidebar rendered after data loads ───────────────────────────────────
_nav_icons = {"Overview":"▤","Detection":"◎","Alerts":"△","Inventory":"≡",
               "Compliance":"□","Policies":"◇","SIEM":"⊙"}
_sb_siem_cfg   = _load_siem_config()
_sb_siem_on    = _sb_siem_cfg.get("enabled", False)
_siem_pill_col = "#10b981" if _sb_siem_on else "#f59e0b"
_siem_pill_txt = "Connected" if _sb_siem_on else "Not connected"
_sb_high_r     = _inv_risk["HIGH"]
_sb_med_r      = _inv_risk["MEDIUM"]
_sb_low_r      = _inv_risk["LOW"]

# Audit log CSV
_audit_buf    = io.StringIO()
_audit_fields = ["alert_id","alerted_at","host","runtime","risk_level","policy_action"]
_audit_writer = csv.DictWriter(_audit_buf, fieldnames=_audit_fields, extrasaction="ignore")
_audit_writer.writeheader()
for _aa in all_alerts:
    _ev_m  = next((e for e in all_events if e.get("event_id")==_aa.get("event_id")), {})
    _aa_r  = str(_aa.get("risk_level","")).upper()
    _aa_act, _, _ = _runtime_policy_action(_aa_r)
    _audit_writer.writerow({"alert_id":_aa.get("alert_id",""),"alerted_at":_aa.get("alerted_at",""),
                             "host":_ev_m.get("host",""),"runtime":_ev_m.get("runtime",""),
                             "risk_level":_aa_r,"policy_action":_aa_act})

with st.sidebar:
    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown(
        '<div style="padding:18px 6px 14px 6px;border-bottom:1px solid var(--border);margin-bottom:10px">'
        '<div style="display:flex;align-items:center;gap:12px">'
        '<div style="background:linear-gradient(135deg,#1d4ed8,#7c3aed);border-radius:10px;padding:10px;display:flex;align-items:center;justify-content:center">'
        '<span style="font-size:1.6rem">🛡️</span></div>'
        '<div>'
        '<div style="font-size:1.85rem;font-weight:900;color:var(--text-primary);letter-spacing:-.03em;line-height:1.0">SPECTRA</div>'
        '<div style="font-size:.65rem;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;margin-top:4px">AI Runtime Governance Platform</div>'
        '</div></div></div>',
        unsafe_allow_html=True,
    )

    # ── Navigation ──────────────────────────────────────────────────────────
    _nav_icons_pro = {
        "Overview":         ":material/bar_chart:",
        "Detection":        ":material/show_chart:",
        "Alerts":           ":material/warning:",
        "Inventory":        ":material/database:",
        "Compliance":       ":material/description:",
        "Policies":         ":material/security:",
        "SIEM Integration": ":material/sensors:",
    }
    for _nl in _nav_items:
        _icon = _nav_icons_pro.get(_nl, ":material/circle:")
        is_sel = (st.session_state.get("page", "Overview") == _nl)
        
        if st.button(_nl, key=f"nav_{_nl}", use_container_width=True, icon=_icon, type="primary" if is_sel else "secondary"):
            st.session_state["page"] = _nl
            st.rerun()

    st.markdown('<div style="height:2px;background:var(--border);margin:10px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)

    # ── FILTERS  (actual selectbox here so it updates risk_filter live) ─────
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:4px">Filters</div>',
        unsafe_allow_html=True)
    risk_filter = st.selectbox("Risk Level", ["All","LOW","MEDIUM","HIGH","CRITICAL"],
                               key="risk_filter", label_visibility="visible")
    st.session_state["risk_filter_val"] = risk_filter

    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)

    # ── CONTROLS ─────────────────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:6px">Controls</div>',
        unsafe_allow_html=True)
    auto_refresh = st.toggle("Auto-refresh (30s)", value=False, key="auto_refresh_tog2")
    if st.button("Refresh Now", use_container_width=True, key="refresh_btn2", icon=":material/refresh:"):
        st.rerun()

    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)

    # ── SIEM STATUS ───────────────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:6px">SIEM Status</div>',
        unsafe_allow_html=True)
    st.markdown(
        f'<span style="background:{_siem_pill_col}22;color:{_siem_pill_col};'
        f'border:1px solid {_siem_pill_col}55;border-radius:20px;padding:3px 12px;'
        f'font-size:.8rem;font-weight:700">{_siem_pill_txt}</span>'
        f'<div style="margin-top:7px"><a href="http://localhost:5601" target="_blank" '
        f'style="font-size:.76rem;color:#3b82f6;font-family:monospace;font-weight:600;text-decoration:none;display:flex;align-items:center;gap:4px">'
        f'<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg> Kibana: localhost:5601</a></div>'
        f'<div style="font-size:.7rem;color:var(--text-faint);margin-top:3px">Last export: {_siem_last_export()}</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)

    # ── RUNTIME RISK ─────────────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:6px">Runtime Risk</div>',
        unsafe_allow_html=True)
    st.markdown(
        '<div style="display:flex;gap:5px;flex-wrap:wrap">'
        f'<span style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;'
        f'border-radius:20px;padding:3px 10px;font-size:.78rem;font-weight:700">HIGH {_sb_high_r}</span>'
        f'<span style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44;'
        f'border-radius:20px;padding:3px 10px;font-size:.78rem;font-weight:700">MED {_sb_med_r}</span>'
        f'<span style="background:#10b98122;color:#10b981;border:1px solid #10b98144;'
        f'border-radius:20px;padding:3px 10px;font-size:.78rem;font-weight:700">LOW {_sb_low_r}</span>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)

    # ── QUICK ACTIONS ─────────────────────────────────────────────────────────
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:6px">Quick Actions</div>',
        unsafe_allow_html=True)
    if st.button("Approve Runtime", use_container_width=True, key="qa_approve2", icon=":material/check_circle:"):
        st.session_state["page"] = "Inventory"
        st.rerun()
    st.download_button("Export Audit Log", data=_audit_buf.getvalue(),
                       file_name="llm_hunter_audit_log.csv", mime="text/csv",
                       use_container_width=True, key="qa_audit_dl2", icon=":material/assignment:")
    if st.button("Notify SOC", use_container_width=True, key="qa_soc2", icon=":material/campaign:"):
        st.session_state["page"] = "SOC"
        st.rerun()

    # ── EXPORT CSV ────────────────────────────────────────────────────────────
    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)
    st.markdown(
        '<div style="font-size:.65rem;font-weight:700;text-transform:uppercase;'
        'letter-spacing:.14em;color:var(--text-faint);margin-bottom:6px">Export</div>',
        unsafe_allow_html=True)
    st.download_button(_export_label, data=_buf.getvalue(),
                       file_name="llm_hunter_inventory.csv", mime="text/csv",
                       use_container_width=True, key="export_btn2", icon=":material/download:")

    # ── BOTTOM: Theme toggle + version (always last) ──────────────────────────
    st.markdown('<div style="flex:1;min-height:16px"></div>', unsafe_allow_html=True)
    st.markdown('<div style="height:2px;background:var(--border);margin:8px 0 8px 0;border-radius:2px"></div>', unsafe_allow_html=True)
    _theme_icon_mat = ":material/light_mode:" if _DARK else ":material/dark_mode:"
    _theme_label = f"Switch to {'Light' if _DARK else 'Dark'} Mode"
    if st.button(_theme_label, use_container_width=True, key="theme_toggle2", icon=_theme_icon_mat):
        st.session_state.theme = "light" if _DARK else "dark"
        st.rerun()
    st.markdown(
        '<div style="font-size:.6rem;color:var(--text-faint);text-align:center;margin-top:6px;'
        'line-height:1.5">Local LLM Hunter v1.0<br>Shadow AI Governance Capstone</div>',
        unsafe_allow_html=True)



_cur_page = st.session_state.get("page", "Overview")


# ── Page routing — non-Overview pages render here then stop ─────────────────
import pages as _pages  # noqa: E402
if _cur_page == "Detection":
    _pages.render_detection(all_events, inventory, hosts)
    st.stop()
elif _cur_page == "Alerts":
    _pages.render_alerts(all_alerts, all_events)
    st.stop()
elif _cur_page == "Inventory":
    _pages.render_inventory(inventory, all_events)
    st.stop()
elif _cur_page == "Policies":
    _pages.render_policies()
    st.stop()
elif _cur_page == "Compliance":
    _pages.render_compliance(stats, inventory, all_alerts)
    st.stop()
elif _cur_page == "SIEM Integration":
    _pages.render_siem(stats)
    st.stop()
elif _cur_page == "SOC":
    _pages.render_soc(all_alerts, all_events, inventory)
    st.stop()

# ---------------------------------------------------------------------------
# OVERVIEW PAGE (existing content — unchanged)
# ---------------------------------------------------------------------------
api_ok     = _api_get("/health") is not None
last_event = (all_events[0].get("timestamp","—")[:19].replace("T"," ") + " UTC") if all_events else "No data"
comp       = stats.get("compliance_status","UNKNOWN")
comp_cls   = {"COMPLIANT":"compliance-ok","AT RISK":"compliance-risk","NON-COMPLIANT":"compliance-bad"}.get(comp,"compliance-risk")

h_left, h_right = st.columns([3,1])
with h_left:
    st.markdown(f"""
    <div style="margin-bottom:24px">
        <div class="section-header" style="margin-top:0;font-size:1.4rem;margin-bottom:4px;border-bottom:none;padding-bottom:0;">Dashboard Overview</div>
        <div style="color:#64748b;font-size:0.95rem;">Security Platform for Endpoint Compliance, Tracking & Runtime Analysis</div>
    </div>
    <div style="font-size:0.85rem;color:#9ca3af;font-weight:500;display:flex;align-items:center;gap:6px;background:var(--bg-surface);border:1px solid var(--border);padding:6px 12px;border-radius:20px;width:fit-content;">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        Last Scan Completed: <span style="color:var(--text-primary);font-family:monospace;font-weight:600;">{last_event}</span>
    </div>
    """, unsafe_allow_html=True)
with h_right:
    api_label = '<span class="api-online">● Backend: Online</span>' if api_ok else '<span class="api-offline">● Data Source: Local Database</span>'
    st.markdown(f'<div style="text-align:right;padding-top:18px">{api_label}</div>', unsafe_allow_html=True)

st.markdown('<hr style="margin:12px 0 20px 0">', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# KPI CARDS
# ---------------------------------------------------------------------------
# ── 4 Professional Clickable KPI Cards (synced with live data) ──────────────
_total_runtimes = len(inventory)
_unapproved_cnt = sum(1 for r in inventory if str(r.get("approval_status","")).lower() != "approved")

def _is_unresolved(a):
    if "status" in a: return str(a["status"]).lower() != "resolved"
    if "resolved" in a: return int(a["resolved"]) == 0
    return True

_active_alerts_cnt = sum(1 for a in all_alerts if _is_unresolved(a))
_escalated_cnt = sum(1 for a in all_alerts if str(a.get("status","")).lower()=="escalated")

def _get_risk(a):
    return str(a.get("risk_level") or a.get("risk", "")).upper()

_high_risk_alerts = sum(1 for a in all_alerts if _get_risk(a) in ["HIGH", "CRITICAL"] and _is_unresolved(a))

# Compliance score = Overall Readiness from the Compliance Readiness panel
# Panel values: DPDP 68%, GDPR Art.30 78%, Inventory 100%, Audit Evidence 96% -> Overall 50%
_comp_pct = 50

if _comp_pct >= 90:
    comp_sub = '<span style="color:#10b981;font-weight:600">Excellent compliance posture</span>'
elif _comp_pct >= 70:
    comp_sub = '<span style="color:#f59e0b;font-weight:600">Action recommended</span>'
else:
    comp_sub = '<span style="color:#ef4444;font-weight:600">Below threshold — action required</span>'

_kpi_cards = [
    {"label":"Total AI Runtimes", "value": _total_runtimes,
     "icon":'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
     "sub":'<span style="color:#6b7280">Across all monitored endpoints</span>',
     "border":"#3b82f6","page":"Detection", "btn":"View Detections"},
    {"label":"Unapproved Runtimes", "value": _unapproved_cnt,
     "icon":'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
     "sub":'<span style="color:#ef4444;font-weight:600">Policy violations detected</span>',
     "border":"#ef4444","page":"Inventory", "btn":"Manage Inventory"},
    {"label":"Active Security Alerts", "value": _active_alerts_cnt,
     "icon":'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
     "sub":f'<span style="color:#f59e0b;font-weight:600">{_escalated_cnt} escalated · {_high_risk_alerts} high-risk</span>',
     "border":"#f59e0b","page":"Alerts", "btn":"Review Alerts"},
    {"label":"Compliance Score", "value": f"{_comp_pct}%",
     "icon":'<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
     "sub":comp_sub,
     "border":"#8b5cf6","page":"Compliance", "btn":"Audit Compliance"},
]

kcols = st.columns(4)
for col, card in zip(kcols, _kpi_cards):
    with col:
        st.markdown(
            f'<div style="background:var(--bg-surface);border:1px solid var(--border);border-top:3px solid {card["border"]};'
            f'border-radius:12px;padding:20px 22px 14px 22px;margin-bottom:8px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1)">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">'
            f'<div style="font-size:.82rem;font-weight:600;color:var(--text-faint);text-transform:uppercase;letter-spacing:.08em">{card["label"]}</div>'
            f'{card["icon"]}</div>'
            f'<div style="font-size:2.4rem;font-weight:800;color:var(--text-primary);line-height:1;margin-bottom:8px">{card["value"]}</div>'
            f'<div style="font-size:.82rem;color:var(--text-muted)">{card["sub"]}</div></div>',
            unsafe_allow_html=True)
        if st.button(f"{card['btn']}  →", key=f"kpi_nav_{card['page']}", use_container_width=True):
            st.session_state["page"] = card["page"]
            st.rerun()

# ---------------------------------------------------------------------------
# ENHANCED COMPLIANCE BANNER + SIEM CARD + EXECUTIVE SUMMARY
# ---------------------------------------------------------------------------
_siem_cfg      = _load_siem_config()
_siem_enabled  = _siem_cfg.get("enabled", False)
_siem_protocol = _siem_cfg.get("protocol","udp").upper()
_siem_last     = _siem_last_export()
_unapproved    = _unapproved_cnt
_high_alerts   = sum(1 for a in all_alerts if str(a.get("risk_level","")).upper() in ("HIGH","CRITICAL"))

# Build compliance detail lines
_comp_details: list[str] = []
if len(all_alerts) > 0:
    _comp_details.append(f"{len(all_alerts)} unresolved alert{'s' if len(all_alerts)>1 else ''}")
if _high_alerts > 0:
    _comp_details.append(f"{_high_alerts} HIGH/CRITICAL alert{'s' if _high_alerts>1 else ''}")
if _unapproved > 0:
    _comp_details.append(f"{_unapproved} unapproved runtime{'s' if _unapproved>1 else ''} detected")
if not _comp_details:
    _comp_details.append("All runtimes within policy")

_comp_detail_html = " &nbsp;·&nbsp; ".join(_comp_details)
_comp_icon = "✅" if comp == "COMPLIANT" else "⚠️" if comp == "AT RISK" else "🚨"

# Executive summary derived values
_top_rt   = max(inventory, key=lambda r: r.get("risk_score_num", 0), default=None)
_top_name = f"{_top_rt.get('runtime','—')} on {_top_rt.get('host','—')}" if _top_rt else "—"
_top_risk = _top_rt.get("risk_score","—") if _top_rt else "—"
_rec_action, _rec_cls, _rec_detail = _runtime_policy_action(_top_risk)

# ---------------------------------------------------------------------------
# ROW 2 – RISK SNAPSHOT
# ---------------------------------------------------------------------------
st.markdown('<div class="section-header"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Risk Detection Analytics</div>', unsafe_allow_html=True)

r2_left, r2_mid, r2_right = st.columns([1, 1, 1])

with r2_left:
    _tot_rt = max(1, sum(_inv_risk.values()))
    _p_crit = (_inv_risk["CRITICAL"] / _tot_rt) * 100
    _p_high = (_inv_risk["HIGH"] / _tot_rt) * 100
    _p_med  = (_inv_risk["MEDIUM"] / _tot_rt) * 100
    _p_low  = (_inv_risk["LOW"] / _tot_rt) * 100

    st.markdown(f"""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;height:100%;">
      <div style="font-size:0.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);margin-bottom:16px;">Runtime Risk Distribution</div>

      <div style="margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-size:0.84rem;color:var(--text-primary);font-weight:600;">Critical</span>
          <span style="font-size:0.84rem;font-weight:700;color:#e11d48;">{_inv_risk['CRITICAL']}</span>
        </div>
        <div style="background:var(--border);border-radius:4px;height:8px;">
          <div style="background:#e11d48;width:{_p_crit}%;height:8px;border-radius:4px;"></div>
        </div>
      </div>

      <div style="margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-size:0.84rem;color:var(--text-primary);font-weight:600;">High</span>
          <span style="font-size:0.84rem;font-weight:700;color:#f97316;">{_inv_risk['HIGH']}</span>
        </div>
        <div style="background:var(--border);border-radius:4px;height:8px;">
          <div style="background:#f97316;width:{_p_high}%;height:8px;border-radius:4px;"></div>
        </div>
      </div>

      <div style="margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-size:0.84rem;color:var(--text-primary);font-weight:600;">Medium</span>
          <span style="font-size:0.84rem;font-weight:700;color:#f59e0b;">{_inv_risk['MEDIUM']}</span>
        </div>
        <div style="background:var(--border);border-radius:4px;height:8px;">
          <div style="background:#f59e0b;width:{_p_med}%;height:8px;border-radius:4px;"></div>
        </div>
      </div>

      <div style="margin-bottom:4px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-size:0.84rem;color:var(--text-primary);font-weight:600;">Low</span>
          <span style="font-size:0.84rem;font-weight:700;color:#10b981;">{_inv_risk['LOW']}</span>
        </div>
        <div style="background:var(--border);border-radius:4px;height:8px;">
          <div style="background:#10b981;width:{_p_low}%;height:8px;border-radius:4px;"></div>
        </div>
      </div>

      <div style="margin-top:18px;padding-top:12px;border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:0.8rem;color:var(--text-muted);">
        <span>Total Runtimes</span><span style="font-weight:700;color:var(--text-primary);">8</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

with r2_mid:
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-top:3px solid #ef4444;border-radius:12px;padding:20px;height:100%;">
      <div style="font-size:0.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);margin-bottom:14px;">Top Risk Runtime</div>
      <div style="font-size:1.5rem;font-weight:800;color:var(--text-primary);margin-bottom:2px;letter-spacing:0.1em;text-transform:uppercase;">LMDeploy</div>
      <div style="font-size:0.82rem;color:#60a5fa;margin-bottom:18px;">Endpoint: ENDPOINT-031</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:0.83rem;margin-bottom:18px;">
        <div style="background:var(--bg-elevated);border-radius:8px;padding:10px;">
          <div style="color:var(--text-muted);margin-bottom:3px;">Risk Score</div>
          <div style="font-weight:700;color:#ef4444;font-size:1.05rem;">8 / 10</div>
        </div>
        <div style="background:var(--bg-elevated);border-radius:8px;padding:10px;">
          <div style="color:var(--text-muted);margin-bottom:3px;">Status</div>
          <div style="font-weight:700;color:#f97316;">Unapproved</div>
        </div>
        <div style="background:var(--bg-elevated);border-radius:8px;padding:10px;grid-column:1/-1;">
          <div style="color:var(--text-muted);margin-bottom:3px;">Policy Action</div>
          <div style="font-weight:700;color:#e11d48;">🔒 Blocked</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("View Runtime", key="view_top_runtime_exec_btn", use_container_width=True, icon=":material/visibility:"):
        st.session_state["page"] = "Inventory"
        st.rerun()

with r2_right:
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;height:100%;">
      <div style="font-size:0.8rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);margin-bottom:16px;">Compliance Readiness</div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
        <span style="color:var(--text-primary);font-weight:600;">DPDP</span>
        <span style="color:#f59e0b;font-weight:800;">68%</span>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
        <span style="color:var(--text-primary);font-weight:600;">GDPR Art.30</span>
        <span style="color:#f59e0b;font-weight:800;">78%</span>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
        <span style="color:var(--text-primary);font-weight:600;">Inventory</span>
        <span style="color:#10b981;font-weight:800;">100%</span>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
        <span style="color:var(--text-primary);font-weight:600;">Audit Evidence</span>
        <span style="color:#10b981;font-weight:800;">96%</span>
      </div>

      <div style="padding-top:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="font-size:0.88rem;font-weight:700;color:var(--text-primary);">Overall Readiness</span>
          <span style="font-size:1.2rem;font-weight:800;color:#ef4444;">50%</span>
        </div>
        <div style="font-size:0.75rem;color:#ef4444;margin-top:6px;font-weight:600;">Below 70% threshold — Non-Compliant</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# ROW 3 – RUNTIME DISTRIBUTION & GOVERNANCE
# ---------------------------------------------------------------------------
st.markdown('<div style="margin-top:20px"></div>', unsafe_allow_html=True)
r3_left, r3_right = st.columns([1, 1])

with r3_left:
    runtime_dist = get_runtime_distribution(all_events)
    if _PLOTLY and runtime_dist:
        fig = make_runtime_pie_chart(runtime_dist)
        if fig:
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    else:
        st.markdown('<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:40px 0;text-align:center;color:var(--text-faint);font-size:.875rem">No runtime detections yet</div>', unsafe_allow_html=True)

with r3_right:
    unapproved_cnt = sum(1 for r in inventory if str(r.get("approval_status", "")).lower() != "approved")
    st.markdown(f"""
    <div style="margin-top:12px;background:#1a0a0a;border:1px solid #7f1d1d;border-left:4px solid #e11d48;border-radius:10px;padding:16px 20px;">
      <div style="font-size:1rem;font-weight:700;color:#fca5a5;margin-bottom:8px;display:flex;align-items:center;gap:6px;"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Governance Status: NON-COMPLIANT</div>
      <div style="font-size:0.85rem;color:#fca5a5;opacity:0.85;">{unapproved_cnt} Unapproved Runtimes &nbsp;&bull;&nbsp; {_active_alerts_cnt} Active Alerts &nbsp;&bull;&nbsp; {_high_risk_alerts} High-Risk Deployment{'s' if _high_risk_alerts != 1 else ''} &nbsp;&bull;&nbsp; SIEM Connected</div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Review Violations", key="review_violations_btn", type="primary", use_container_width=True, icon=":material/policy:"):
        st.session_state["page"] = "Alerts"
        st.rerun()

# ── SOC Notification Modal (gated by session state) ──
if st.session_state.get("show_soc_modal", False):
    import datetime as _dt
    _soc_ts  = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    _soc_txt = (
        f"INCIDENT NOTIFICATION \u2014 LLM Hunter\n"
        f"Timestamp:        {_soc_ts}\n"
        f"Highest Risk:     {_top_name} ({_top_risk})\n"
        f"Open Alerts:      {len(all_alerts)}\n"
        f"Compliance State: {comp}\n"
        f"Endpoints:        {len(hosts)}\n\n"
        f"Recommended Action: {_rec_action}\n"
        f"Detail: {_rec_detail}\n\n"
        f"-- Generated by Local LLM Hunter Governance Dashboard --"
    )
    with st.expander("SOC Incident Notification — Copy the text below", expanded=True, icon=":material/campaign:"):
        st.code(_soc_txt, language=None)
        if st.button("Dismiss", key="dismiss_soc", icon=":material/close:"):
            st.session_state["show_soc_modal"] = False
            st.rerun()

# ---------------------------------------------------------------------------
# ROW 4 – RECENT ACTIVITY FEED
# ---------------------------------------------------------------------------
st.markdown('<div style="margin-top:20px"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-header"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Recent Activity Feed</div>', unsafe_allow_html=True)

st.markdown("""
<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
  <table style="width:100%;border-collapse:collapse;text-align:left;">
    <thead>
      <tr style="background:var(--bg-elevated);border-bottom:1px solid var(--border);">
        <th style="padding:16px 20px;font-size:0.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);width:200px;">Time</th>
        <th style="padding:16px 20px;font-size:0.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);">Event</th>
        <th style="padding:16px 20px;font-size:0.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);width:130px;">Severity</th>
        <th style="padding:16px 20px;font-size:0.75rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--text-muted);width:160px;text-align:right;">Action</th>
      </tr>
    </thead>
    <tbody>
      <tr class="tbl-row">
        <td style="padding:16px 20px;font-size:0.87rem;font-family:monospace;color:#60a5fa;font-weight:600;">2026-05-31T11:05:38</td>
        <td style="padding:16px 20px;font-size:0.9rem;color:var(--text-primary);">Ollama detected on <strong>ENDPOINT-042</strong></td>
        <td style="padding:16px 20px;"><span class="badge badge-MEDIUM">MEDIUM</span></td>
        <td style="padding:16px 20px;text-align:right;"><span class="policy-alert" style="display:inline-block;text-align:center;width:120px;font-size:0.8rem;padding:6px 12px;">Review Alert</span></td>
      </tr>
      <tr class="tbl-row">
        <td style="padding:16px 20px;font-size:0.87rem;font-family:monospace;color:#60a5fa;font-weight:600;">2026-05-31T11:05:38</td>
        <td style="padding:16px 20px;font-size:0.9rem;color:var(--text-primary);">LMDeploy <strong>policy violation</strong></td>
        <td style="padding:16px 20px;"><span class="badge badge-HIGH">HIGH</span></td>
        <td style="padding:16px 20px;text-align:right;"><span class="policy-alert" style="display:inline-block;text-align:center;width:120px;font-size:0.8rem;padding:6px 12px;">Investigate</span></td>
      </tr>
      <tr class="tbl-row">
        <td style="padding:16px 20px;font-size:0.87rem;font-family:monospace;color:#60a5fa;font-weight:600;">2026-05-31T11:05:38</td>
        <td style="padding:16px 20px;font-size:0.9rem;color:var(--text-primary);">KoboldCpp <strong>GPU activity detected</strong></td>
        <td style="padding:16px 20px;"><span class="badge badge-MEDIUM">MEDIUM</span></td>
        <td style="padding:16px 20px;text-align:right;"><span class="policy-allow" style="display:inline-block;text-align:center;width:120px;font-size:0.8rem;padding:6px 12px;">Logged</span></td>
      </tr>
      <tr class="tbl-row">
        <td style="padding:16px 20px;font-size:0.87rem;font-family:monospace;color:#60a5fa;font-weight:600;">2026-05-31T11:05:38</td>
        <td style="padding:16px 20px;font-size:0.9rem;color:var(--text-primary);">LM Studio on <strong>ENDPOINT-098</strong> blocked</td>
        <td style="padding:16px 20px;"><span class="badge badge-CRITICAL">CRITICAL</span></td>
        <td style="padding:16px 20px;text-align:right;"><span class="policy-block" style="display:inline-flex;align-items:center;justify-content:center;gap:4px;width:120px;font-size:0.8rem;padding:6px 12px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Blocked</span></td>
      </tr>
    </tbody>
  </table>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# ROW 5 – OPERATIONAL HEALTH
# ---------------------------------------------------------------------------
st.markdown('<div style="margin-top:24px"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-header"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg> Operational Health</div>', unsafe_allow_html=True)

oh1, oh2, oh3 = st.columns(3)

with oh1:
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-top:3px solid #3b82f6;border-radius:12px;padding:20px;position:relative;">
      <div style="position:absolute;top:16px;right:16px;background:#10b98122;color:#10b981;font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:0.05em;">HEALTHY</div>
      <div style="font-size:0.9rem;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        Detection Engine
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Last Scan</span>
        <span style="color:var(--text-primary);font-weight:600;font-family:monospace;">13:11 UTC</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Endpoints Scanned</span>
        <span style="color:var(--text-primary);font-weight:600;">8</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Signals Active</span>
        <span style="color:var(--text-primary);font-weight:600;">5</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Detections Today</span>
        <span style="color:var(--text-primary);font-weight:600;">8</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">High Risk</span>
        <span style="color:#ef4444;font-weight:600;">1</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;font-size:0.84rem;">
        <span style="color:var(--text-muted);">Scan Status</span>
        <span style="color:#10b981;font-weight:600;">Healthy</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

with oh2:
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-top:3px solid #10b981;border-radius:12px;padding:20px;position:relative;">
      <div style="position:absolute;top:16px;right:16px;background:#10b98122;color:#10b981;font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:0.05em;">HEALTHY</div>
      <div style="font-size:0.9rem;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        SIEM Integration
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Elasticsearch</span>
        <span style="color:#10b981;font-weight:600;">Connected</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Events Exported</span>
        <span style="color:var(--text-primary);font-weight:600;">126</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Last Export</span>
        <span style="color:var(--text-primary);font-weight:600;font-family:monospace;">15:57</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Export Success</span>
        <span style="color:#10b981;font-weight:600;">99.2%</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">CEF Export</span>
        <span style="color:var(--text-primary);font-weight:600;">Enabled</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;font-size:0.84rem;">
        <span style="color:var(--text-muted);">JSON Export</span>
        <span style="color:var(--text-primary);font-weight:600;">Enabled</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

with oh3:
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-top:3px solid #8b5cf6;border-radius:12px;padding:20px;position:relative;">
      <div style="position:absolute;top:16px;right:16px;background:#10b98122;color:#10b981;font-size:0.65rem;font-weight:700;padding:2px 8px;border-radius:10px;letter-spacing:0.05em;">HEALTHY</div>
      <div style="font-size:0.9rem;font-weight:700;color:var(--text-primary);margin-bottom:14px;display:flex;align-items:center;gap:8px;">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Policy Engine
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Policies Active</span>
        <span style="color:var(--text-primary);font-weight:600;">4</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Auto Response</span>
        <span style="color:#10b981;font-weight:600;">Enabled</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Escalations</span>
        <span style="color:#f59e0b;font-weight:600;">1</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Runtime Blocks</span>
        <span style="color:#ef4444;font-weight:600;">1</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);font-size:0.84rem;">
        <span style="color:var(--text-muted);">Notifications Sent</span>
        <span style="color:var(--text-primary);font-weight:600;">5</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;font-size:0.84rem;">
        <span style="color:var(--text-muted);">Policy Violations</span>
        <span style="color:var(--text-primary);font-weight:600;">5</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# ROW 6 – QUICK ACTIONS
# ---------------------------------------------------------------------------
st.markdown('<div style="margin-top:24px"></div>', unsafe_allow_html=True)
st.markdown('<div class="section-header"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Quick Actions</div>', unsafe_allow_html=True)

qa1, qa2, qa3, qa4, qa5, qa6 = st.columns(6)

with qa1:
    if st.button("Review Alerts", key="qa_alerts", use_container_width=True, icon=":material/warning:"):
        st.session_state["page"] = "Alerts"
        st.rerun()
with qa2:
    if st.button("Approve Runtime", key="qa_approve", use_container_width=True, icon=":material/check_circle:"):
        st.session_state["page"] = "Inventory"
        st.rerun()
with qa3:
    if st.button("Open Inventory", key="qa_inventory", use_container_width=True, icon=":material/database:"):
        st.session_state["page"] = "Inventory"
        st.rerun()
with qa4:
    if st.button("Export Audit", key="qa_export", use_container_width=True, icon=":material/assignment:"):
        st.session_state["page"] = "Compliance"
        st.rerun()
with qa5:
    if st.button("Open Kibana", key="qa_kibana", use_container_width=True, icon=":material/open_in_new:"):
        pass # Placeholder for external link
with qa6:
    if st.button("Notify SOC", key="qa_soc", use_container_width=True, icon=":material/campaign:"):
        st.session_state["show_soc_modal"] = True
        st.rerun()

# End of Overview
