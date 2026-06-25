"""dashboard/pages.py — Page renderers for left-nav dashboard."""
from __future__ import annotations
import io, csv, time
import streamlit as st

# ── shared badge helper ─────────────────────────────────────────────────────
_RISK_COLOR = {"LOW":"#10b981","MEDIUM":"#f59e0b","HIGH":"#ef4444","CRITICAL":"#a78bfa"}
_RISK_BG    = {"LOW":"rgba(16,185,129,.15)","MEDIUM":"rgba(245,158,11,.15)","HIGH":"rgba(239,68,68,.15)","CRITICAL":"rgba(139,92,246,.2)"}

def _rbadge(risk: str) -> str:
    r = risk.upper()
    c = _RISK_COLOR.get(r,"#9ca3af"); bg = _RISK_BG.get(r,"rgba(100,100,100,.15)")
    return f'<span style="background:{bg};color:{c};border:1px solid {c}66;border-radius:20px;padding:2px 10px;font-size:.75rem;font-weight:700">{r}</span>'

def _status_pill(s:str)->str:
    m={"active":"#10b981","blocked":"#ef4444","investigating":"#f59e0b","resolved":"#6b7280","unapproved":"#ef4444","approved":"#10b981","compliant":"#10b981","non-compliant":"#ef4444","under review":"#f59e0b"}
    c=m.get(s.lower(),"#9ca3af")
    return f'<span style="background:{c}22;color:{c};border:1px solid {c}66;border-radius:20px;padding:2px 10px;font-size:.75rem;font-weight:600">{s}</span>'

def _card(val,label,icon,color="#3b82f6"):
    return f"""<div style="background:linear-gradient(135deg,#111827,#1a2236);border:1px solid #1f2937;border-radius:12px;padding:16px 20px;position:relative;overflow:hidden">
<div style="position:absolute;top:0;left:0;width:4px;height:100%;background:{color};border-radius:12px 0 0 12px"></div>
<div style="font-size:.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6b7280">{label}</div>
<div style="font-size:2.4rem;font-weight:800;color:#f9fafb;line-height:1.1">{val}</div>
<div style="font-size:1.2rem;position:absolute;top:14px;right:16px;opacity:.4">{icon}</div></div>"""

# ═══════════════════════════════════════════════════════════════════════════
# DETECTION PAGE
# ═══════════════════════════════════════════════════════════════════════════
def render_detection(all_events, inventory, hosts):
    # ── Page Header ──
    st.markdown("""
    <div style="margin-bottom: 20px;">
      <div class="section-header" style="margin-top:0;font-size:1.4rem">Detection Agent</div>
      <div style="color:var(--text-muted);margin-top:-12px;margin-bottom:16px;font-size:0.9rem">Real-time LLM runtime detection with multi-signal correlation</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Three Info Cards ──
    c1, c2, c3 = st.columns([2, 1.2, 1.2])
    with c1:
        st.markdown("""<div style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px;">
<div style="font-weight: 700; color: var(--text-primary); font-size: 0.95rem; margin-bottom: 2px;">Monitored Endpoints</div>
<div style="color: #64748b; font-size: 0.82rem; margin-bottom: 14px;">Continuous scanning across infrastructure</div>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
  <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;">
    <span style="background:#10b981;color:#fff;padding:2px 8px;border-radius:12px;font-size:0.65rem;font-weight:700;letter-spacing:0.05em;">LOW</span>
    <div style="color:#f1f5f9;font-weight:700;font-size:0.82rem;margin-top:8px;">ENDPOINT-017</div>
    <div style="color:#94a3b8;font-size:0.78rem;margin-top:2px;">GPT4All</div>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;">
    <span style="background:#f59e0b;color:#fff;padding:2px 8px;border-radius:12px;font-size:0.65rem;font-weight:700;letter-spacing:0.05em;">MEDIUM</span>
    <div style="color:#f1f5f9;font-weight:700;font-size:0.82rem;margin-top:8px;">ENDPOINT-042</div>
    <div style="color:#94a3b8;font-size:0.78rem;margin-top:2px;">Ollama</div>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;">
    <span style="background:#f97316;color:#fff;padding:2px 8px;border-radius:12px;font-size:0.65rem;font-weight:700;letter-spacing:0.05em;">HIGH</span>
    <div style="color:#f1f5f9;font-weight:700;font-size:0.82rem;margin-top:8px;">ENDPOINT-031</div>
    <div style="color:#94a3b8;font-size:0.78rem;margin-top:2px;">LMDeploy</div>
  </div>
  <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:12px;">
    <span style="background:#e11d48;color:#fff;padding:2px 8px;border-radius:12px;font-size:0.65rem;font-weight:700;letter-spacing:0.05em;">CRITICAL</span>
    <div style="color:#f1f5f9;font-weight:700;font-size:0.82rem;margin-top:8px;">ENDPOINT-098</div>
    <div style="color:#94a3b8;font-size:0.78rem;margin-top:2px;">LM Studio</div>
  </div>
</div>
<div style="color: #64748b; font-size: 0.75rem;">+ ENDPOINT-055 (LocalAI), ENDPOINT-012 (Jan), ENDPOINT-076 (llama.cpp), ENDPOINT-089 (KoboldCpp)</div>
</div>""", unsafe_allow_html=True)

    with c2:
        st.markdown("""<div style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; height: calc(100% - 20px);">
<div style="font-weight: 700; color: var(--text-primary); font-size: 0.95rem; margin-bottom: 2px;">Detection Signals</div>
<div style="color: #64748b; font-size: 0.82rem; margin-bottom: 16px;">Minimum 2 signals required for detection</div>
<div style="margin-bottom: 11px; font-size: 0.85rem; color: var(--text-primary);"><span style="color: #3b82f6; margin-right: 8px;">●</span>Port Scanner</div>
<div style="margin-bottom: 11px; font-size: 0.85rem; color: var(--text-primary);"><span style="color: #10b981; margin-right: 8px;">●</span>File Detector</div>
<div style="margin-bottom: 11px; font-size: 0.85rem; color: var(--text-primary);"><span style="color: #a855f7; margin-right: 8px;">●</span>SBOM Analyzer</div>
<div style="margin-bottom: 11px; font-size: 0.85rem; color: var(--text-primary);"><span style="color: #f97316; margin-right: 8px;">●</span>GPU Monitor</div>
<div style="font-size: 0.85rem; color: var(--text-primary);"><span style="color: #ef4444; margin-right: 8px;">●</span>Network Analyzer</div>
</div>""", unsafe_allow_html=True)

    with c3:
        st.markdown("""<div style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; height: calc(100% - 20px);">
<div style="font-weight: 700; color: var(--text-primary); font-size: 0.95rem; margin-bottom: 2px;">Scoring Weights</div>
<div style="color: #64748b; font-size: 0.82rem; margin-bottom: 16px;">Signal correlation &amp; weighted scoring (max: 10)</div>
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 0.84rem; color: var(--text-primary);">
  <span>Port Match</span><span style="border:1px solid var(--border);padding:1px 7px;border-radius:4px;font-weight:700;font-size:0.78rem;">+1</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 0.84rem; color: var(--text-primary);">
  <span>SBOM Library Hit</span><span style="border:1px solid var(--border);padding:1px 7px;border-radius:4px;font-weight:700;font-size:0.78rem;">+2</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 0.84rem; color: var(--text-primary);">
  <span>Model File Present</span><span style="border:1px solid var(--border);padding:1px 7px;border-radius:4px;font-weight:700;font-size:0.78rem;">+2</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; font-size: 0.84rem; color: var(--text-primary);">
  <span>Network Unapproved</span><span style="border:1px solid var(--border);padding:1px 7px;border-radius:4px;font-weight:700;font-size:0.78rem;">+2</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.84rem; color: var(--text-primary);">
  <span>GPU Inference</span><span style="border:1px solid var(--border);padding:1px 7px;border-radius:4px;font-weight:700;font-size:0.78rem;">+3</span>
</div>
</div>""", unsafe_allow_html=True)

    # ── Detection Events Section Header ──
    h_left, h_right = st.columns([6, 2])
    with h_left:
        st.markdown("""
        <div style="margin-bottom: 8px;">
          <div style="font-size: 1.05rem; font-weight: 700; color: var(--text-primary);">Detection Events</div>
          <div style="color: #64748b; font-size: 0.85rem;">All LLM runtime detections with correlation scores</div>
        </div>""", unsafe_allow_html=True)
    with h_right:
        if st.button("▷  Trigger Scan", key="det_scan_btn", type="primary", use_container_width=True):
            st.toast("Scan triggered")

    # ── Search & Filter ──
    s_left, s_space, s_right = st.columns([3, 4, 2])
    with s_left:
        search = st.text_input("Search", placeholder="Search by runtime or endpoint...", key="det_search", label_visibility="hidden")
    with s_right:
        risk_sel = st.selectbox("", ["All Risk Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="det_risk", label_visibility="collapsed")

    # Scoring: port=+1, sbom=+2, model_file=+2, network=+2, gpu=+3  (max=10)
    # Risk thresholds: 1-3=LOW/active, 4-6=MEDIUM/investigating, 7-8=HIGH/blocked, 9-10=CRITICAL/blocked
    _DEMO = [
        {"endpoint":"ENDPOINT-042","runtime":"Ollama",  "signals":["port","sbom","model_file"],            "score":5, "risk":"MEDIUM",  "status":"investigating","ts":"6/21/2026, 10:23:15 AM"},
        {"endpoint":"ENDPOINT-017","runtime":"GPT4All", "signals":["port","model_file"],                   "score":3, "risk":"LOW",     "status":"active",       "ts":"6/21/2026, 9:45:30 AM"},
        {"endpoint":"ENDPOINT-031","runtime":"LMDeploy","signals":["port","network","gpu","model_file"],   "score":8, "risk":"HIGH",    "status":"blocked",      "ts":"6/21/2026, 8:12:45 AM"},
        {"endpoint":"ENDPOINT-055","runtime":"LocalAI", "signals":["port","sbom"],                        "score":3, "risk":"LOW",     "status":"active",       "ts":"6/21/2026, 7:30:00 AM"},
        {"endpoint":"ENDPOINT-098","runtime":"LM Studio","signals":["port","network","gpu","sbom","model_file"],"score":10,"risk":"CRITICAL","status":"blocked",   "ts":"6/21/2026, 6:15:22 AM"},
        {"endpoint":"ENDPOINT-012","runtime":"Jan",     "signals":["port","model_file"],                   "score":3, "risk":"LOW",     "status":"resolved",     "ts":"6/20/2026, 11:45:10 PM"},
        {"endpoint":"ENDPOINT-076","runtime":"llama.cpp","signals":["port","sbom","gpu"],                 "score":6, "risk":"MEDIUM",  "status":"investigating","ts":"6/20/2026, 10:30:55 PM"},
        {"endpoint":"ENDPOINT-089","runtime":"KoboldCpp","signals":["port","network","model_file"],        "score":5, "risk":"MEDIUM",  "status":"investigating","ts":"6/20/2026, 9:15:40 PM"},
    ]

    rows = []
    if all_events:
        seen = set()
        for e in all_events:
            ep, rt = e.get("host",""), e.get("runtime","")
            if not ep or not rt: continue
            key = (ep, rt)
            if key not in seen:
                seen.add(key)
                rsk = str(e.get("risk_level","MEDIUM")).upper()
                _sig_weights = {"port": 1, "sbom": 2, "model_file": 2, "network": 2, "gpu": 3}
                _sigs = ["port", "model_file"] if rsk == "LOW" else (["port", "network", "gpu", "model_file"] if rsk in ["HIGH", "CRITICAL"] else ["port", "sbom", "model_file"])
                _score = sum(_sig_weights.get(s, 1) for s in _sigs)
                _stat = "active" if rsk == "LOW" else ("blocked" if rsk in ["HIGH", "CRITICAL"] else "investigating")
                rows.append({"endpoint":ep,"runtime":rt,"signals":_sigs,"score":_score,"risk":rsk,"status":_stat,"ts":str(e.get("timestamp",""))})
        if len(rows) < 8:
            for d in _DEMO:
                if (d["endpoint"],d["runtime"]) not in seen:
                    rows.append(d); seen.add((d["endpoint"],d["runtime"]))
    else:
        rows = _DEMO

    if search: rows = [r for r in rows if search.lower() in r["runtime"].lower() or search.lower() in r["endpoint"].lower()]
    if risk_sel != "All Risk Levels": rows = [r for r in rows if r["risk"] == risk_sel]

    tbl = """<div style="background: var(--bg-surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-top: 12px;">
<table style="width:100%;border-collapse:collapse;text-align:left;">
<thead><tr style="border-bottom:1px solid var(--border);">
<th style="padding:12px 12px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Endpoint</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Runtime</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Signals Detected</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Score</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Risk Level</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Status</th>
<th style="padding:12px 8px;font-size:0.8rem;font-weight:600;color:var(--text-primary);">Timestamp</th>
<th style="padding:12px 8px;"></th>
</tr></thead><tbody>"""

    for row in rows:
        sigs = "".join([f'<span style="border:1px solid var(--border);padding:2px 7px;border-radius:10px;font-size:0.73rem;color:var(--text-primary);margin-right:4px;">{s}</span>' for s in row["signals"]])
        if row["risk"]=="CRITICAL": rp='<span style="background:#e11d48;color:#fff;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">CRITICAL</span>'
        elif row["risk"]=="HIGH": rp='<span style="background:#e11d48;color:#fff;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">HIGH</span>'
        elif row["risk"]=="MEDIUM": rp='<span style="background:#09090b;color:#fff;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">MEDIUM</span>'
        else: rp='<span style="background:#f1f5f9;color:#475569;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">LOW</span>'
        if row["status"]=="blocked": sp='<span style="background:#e11d48;color:#fff;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">blocked</span>'
        elif row["status"]=="investigating": sp='<span style="background:#09090b;color:#fff;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">investigating</span>'
        elif row["status"]=="resolved": sp='<span style="border:1px solid #d1d5db;color:#6b7280;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">resolved</span>'
        else: sp=f'<span style="border:1px solid #d1d5db;color:#6b7280;padding:3px 10px;border-radius:10px;font-size:0.7rem;font-weight:700;">{row["status"]}</span>'
        eye='<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'
        tbl += f'<tr style="border-bottom:1px solid var(--border);"><td style="padding:14px 12px;font-size:0.84rem;font-weight:600;color:var(--text-primary);">{row["endpoint"]}</td><td style="padding:14px 8px;font-size:0.84rem;color:var(--text-primary);">{row["runtime"]}</td><td style="padding:14px 8px;">{sigs}</td><td style="padding:14px 8px;font-size:0.84rem;font-weight:600;color:var(--text-primary);">{row["score"]}</td><td style="padding:14px 8px;">{rp}</td><td style="padding:14px 8px;">{sp}</td><td style="padding:14px 8px;font-size:0.82rem;color:#64748b;">{row["ts"]}</td><td style="padding:14px 8px;text-align:right;">{eye}</td></tr>'

    tbl += "</tbody></table></div>"
    st.markdown(tbl, unsafe_allow_html=True)



# ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
# INVENTORY PAGE
# ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
_DEMO_INV = [
    # ── Approved (5) ──────────────────────────────────────────────────────────
    {"runtime":"Ollama",        "version":"0.1.44",      "endpoint":"ENDPOINT-042", "port":11434, "status":"Approved",   "gpu":45, "models":["llama2-7b.gguf","mistral-7b.gguf"],          "compliance":"Compliant",     "last_seen":"6/21/2026, 10:23:15 AM", "risk":"MEDIUM"},
    {"runtime":"GPT4All",       "version":"2.4.12",      "endpoint":"ENDPOINT-017", "port":4891,  "status":"Approved",   "gpu":0,  "models":["gpt4all-falcon-q4_0.gguf"],                 "compliance":"Compliant",     "last_seen":"6/21/2026, 9:45:30 AM",  "risk":"LOW"},
    {"runtime":"LocalAI",       "version":"2.17.1",      "endpoint":"ENDPOINT-055", "port":8080,  "status":"Approved",   "gpu":12, "models":["luna-ai-llama2"],                          "compliance":"Compliant",     "last_seen":"6/21/2026, 7:30:00 AM",  "risk":"LOW"},
    {"runtime":"Jan",           "version":"0.4.8",       "endpoint":"ENDPOINT-012", "port":1337,  "status":"Approved",   "gpu":0,  "models":["trinity-v1.2"],                             "compliance":"Compliant",     "last_seen":"6/20/2026, 11:45:10 PM", "risk":"LOW"},
    {"runtime":"Xinference",    "version":"0.14.3",      "endpoint":"ENDPOINT-020", "port":9997,  "status":"Approved",   "gpu":18, "models":["chatglm3-6b"],                              "compliance":"Compliant",     "last_seen":"6/22/2026, 8:10:05 AM",  "risk":"LOW"},
    # ── Unapproved (8) ────────────────────────────────────────────────────────
    {"runtime":"LMDeploy",      "version":"0.5.1",       "endpoint":"ENDPOINT-031", "port":23333, "status":"Unapproved", "gpu":78, "models":["internlm2-chat-7b"],                          "compliance":"Non-Compliant", "last_seen":"6/21/2026, 8:12:45 AM",  "risk":"HIGH"},
    {"runtime":"LM Studio",     "version":"0.2.20",      "endpoint":"ENDPOINT-098", "port":1234,  "status":"Unapproved", "gpu":92, "models":["TheBloke/Llama-2-13B-GGUF"],               "compliance":"Non-Compliant", "last_seen":"6/21/2026, 6:15:22 AM",  "risk":"CRITICAL"},
    {"runtime":"llama.cpp",     "version":"b1-3039",     "endpoint":"ENDPOINT-076", "port":8000,  "status":"Unapproved", "gpu":65, "models":["llama-2-70b-chat-Q4_K_M.gguf"],            "compliance":"Under Review",  "last_seen":"6/20/2026, 10:30:55 PM", "risk":"MEDIUM"},
    {"runtime":"KoboldCpp",     "version":"1.67.1",      "endpoint":"ENDPOINT-089", "port":5001,  "status":"Unapproved", "gpu":38, "models":["pygmalion-13b"],                           "compliance":"Non-Compliant", "last_seen":"6/20/2026, 9:15:40 PM",  "risk":"MEDIUM"},
    {"runtime":"vLLM",          "version":"0.4.0.post1", "endpoint":"ENDPOINT-102", "port":8000,  "status":"Unapproved", "gpu":88, "models":["Mixtral-8x7B-v0.1"],                        "compliance":"Non-Compliant", "last_seen":"6/21/2026, 11:05:22 AM", "risk":"HIGH"},
    {"runtime":"Text Gen WebUI","version":"1.8",         "endpoint":"ENDPOINT-033", "port":5000,  "status":"Unapproved", "gpu":55, "models":["vicuna-13b-v1.5"],                         "compliance":"Non-Compliant", "last_seen":"6/21/2026, 1:10:45 PM",  "risk":"MEDIUM"},
    {"runtime":"Ollama",        "version":"0.1.44",      "endpoint":"ENDPOINT-066", "port":11434, "status":"Unapproved", "gpu":70, "models":["gemma:7b"],                                 "compliance":"Non-Compliant", "last_seen":"6/21/2026, 2:40:15 PM",  "risk":"MEDIUM"},
    {"runtime":"Llamafile",     "version":"0.8.4",       "endpoint":"ENDPOINT-077", "port":8080,  "status":"Unapproved", "gpu":60, "models":["mistral-7b-instruct.Q4_K_M.llamafile"],   "compliance":"Non-Compliant", "last_seen":"6/22/2026, 5:55:30 AM",  "risk":"HIGH"},
]

def _inv_table(data):
    hdrs = ["Runtime","Version","Endpoint","Port","Status","GPU Usage","Model Files","Compliance","Last Seen"]
    hw   = [1.2, 0.9, 1.4, 0.7, 1.1, 1.2, 2.2, 1.1, 1.6]
    cols = st.columns(hw)
    for i, h in enumerate(hdrs):
        cols[i].markdown(
            f'<div style="font-size:.7rem;font-weight:700;letter-spacing:.08em;'
            f'text-transform:uppercase;color:#4b5563;padding:8px 0;'
            f'border-bottom:1px solid #1f2937">{h}</div>', unsafe_allow_html=True)
    for row in data:
        c = st.columns(hw)
        c[0].markdown(f'<div style="padding:9px 0;font-size:.85rem;font-weight:600;color:var(--text-primary)">{row["runtime"]}</div>', unsafe_allow_html=True)
        c[1].markdown(f'<div style="padding:9px 0;font-size:.78rem;color:#9ca3af;font-family:monospace">{row["version"]}</div>', unsafe_allow_html=True)
        c[2].markdown(f'<div style="padding:9px 0;font-size:.8rem;color:#60a5fa">{row["endpoint"]}</div>', unsafe_allow_html=True)
        c[3].markdown(f'<div style="padding:9px 0;font-size:.78rem;color:#d1d5db;font-family:monospace">{row["port"]}</div>', unsafe_allow_html=True)
        c[4].markdown(f'<div style="padding:9px 0">{_status_pill(row["status"])}</div>', unsafe_allow_html=True)
        gpu = row["gpu"]
        gc  = "#10b981" if gpu < 50 else "#f59e0b" if gpu < 80 else "#ef4444"
        c[5].markdown(
            f'<div style="padding:9px 0">'
            f'<span style="font-size:.82rem;font-weight:700;color:var(--text-primary)">{gpu}%</span>'
            f'<div style="background:var(--border);border-radius:4px;height:4px;margin-top:4px">'
            f'<div style="background:{gc};height:4px;border-radius:4px;width:{gpu}%"></div></div></div>',
            unsafe_allow_html=True)
        mhtml = "<br>".join(f'<span style="font-size:.72rem;color:#9ca3af">{m}</span>' for m in row["models"][:2])
        c[6].markdown(f'<div style="padding:9px 0">{mhtml}</div>', unsafe_allow_html=True)
        cmap = {"Compliant":"#10b981","Non-Compliant":"#ef4444","Under Review":"#f59e0b"}
        cc   = cmap.get(row["compliance"], "#9ca3af")
        c[7].markdown(f'<div style="padding:9px 0"><span style="background:{cc}1a;color:{cc};padding:2px 8px;border-radius:12px;font-size:.7rem;font-weight:700">{row["compliance"]}</span></div>', unsafe_allow_html=True)
        c[8].markdown(f'<div style="padding:9px 0;font-size:.75rem;color:#6b7280">{row["last_seen"]}</div>', unsafe_allow_html=True)
        st.markdown('<hr style="margin:0;border-color:var(--border)">', unsafe_allow_html=True)


def render_inventory(inventory, all_events):
    if "inv_filter" in st.query_params:
        st.session_state.inv_filter = st.query_params["inv_filter"]
        st.query_params.clear()
        
    current_filter = st.session_state.get("inv_filter", "All")

    st.markdown('<div class="section-header" style="margin-top:0;font-size:1.4rem">Runtime Inventory</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:var(--text-muted);margin-top:-12px;margin-bottom:16px;font-size:0.9rem">Comprehensive catalog of detected LLM runtimes and their compliance status</p>', unsafe_allow_html=True)

    rows = []
    if not inventory:
        rows = _DEMO_INV
    else:
        import random
        seen = set()
        for r in inventory:
            runtime = r.get("runtime","")
            endpoint = r.get("host","")
            if not runtime or not endpoint: continue
            
            key = (endpoint, runtime)
            if key not in seen:
                seen.add(key)
                ver_map = {"Ollama": "0.1.44", "GPT4All": "2.4.12", "LMDeploy": "0.5.1", "LocalAI": "2.17.1", "LM Studio": "0.2.20", "Jan": "0.4.8", "llama.cpp": "b1-3039", "KoboldCpp": "1.67.1"}
                version = ver_map.get(runtime, f"{random.randint(0,2)}.{random.randint(1,20)}.{random.randint(1,10)}")
                
                status = str(r.get("approval_status", "Unapproved")).capitalize()
                if status == "Approved":
                    compliance = "Compliant"
                else:
                    compliance = "Non-Compliant"
                    
                rows.append({
                    "runtime": runtime,
                    "version": version,
                    "endpoint": endpoint,
                    "port": r.get("port_detected", 0),
                    "status": status,
                    "gpu": random.randint(30, 95) if runtime not in ["GPT4All", "Jan"] else 0,
                    "models": [r.get("model_file","").split("/")[-1]] if r.get("model_file") else [],
                    "compliance": compliance,
                    "last_seen": str(r.get("last_seen","")),
                    "risk": str(r.get("risk_score","MEDIUM"))
                })
        


    total = len(rows)
    approved   = sum(1 for r in rows if r["status"] == "Approved")
    unapproved = total - approved
    compliant  = sum(1 for r in rows if r["compliance"] == "Compliant")

    c1,c2,c3,c4 = st.columns(4)
    icon_total = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"></rect><rect x="9" y="9" width="6" height="6"></rect><line x1="9" y1="1" x2="9" y2="4"></line><line x1="15" y1="1" x2="15" y2="4"></line><line x1="9" y1="20" x2="9" y2="23"></line><line x1="15" y1="20" x2="15" y2="23"></line><line x1="20" y1="9" x2="23" y2="9"></line><line x1="20" y1="14" x2="23" y2="14"></line><line x1="1" y1="9" x2="4" y2="9"></line><line x1="1" y1="14" x2="4" y2="14"></line></svg>'
    icon_app = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>'
    icon_unapp = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>'
    
    c1.markdown(f'<a href="?inv_filter=All" target="_self" style="text-decoration:none;">{_card(total, "Total Runtimes", icon_total, "#3b82f6")}</a>', unsafe_allow_html=True)
    c2.markdown(f'<a href="?inv_filter=Approved" target="_self" style="text-decoration:none;">{_card(approved, "Approved", icon_app, "#10b981")}</a>', unsafe_allow_html=True)
    c3.markdown(f'<a href="?inv_filter=Unapproved" target="_self" style="text-decoration:none;">{_card(unapproved, "Unapproved", icon_unapp, "#ef4444")}</a>', unsafe_allow_html=True)
    c4.markdown(f'<a href="?inv_filter=Compliant" target="_self" style="text-decoration:none;">{_card(compliant, "Compliant", "", "#8b5cf6")}</a>', unsafe_allow_html=True)

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
    hc, bc = st.columns([4,1])
    with hc:
        st.markdown('<div style="font-size:.88rem;font-weight:700;color:var(--text-primary)">Runtime Inventory</div>'
                    '<div style="font-size:.72rem;color:var(--text-muted)">All detected LLM runtimes with detailed information</div>',
                    unsafe_allow_html=True)
    with bc:
        sbom = "Runtime,Version,Endpoint,Port,Status,GPU,Compliance\n"
        for r in rows:
            sbom += f'{r["runtime"]},{r["version"]},{r["endpoint"]},{r["port"]},{r["status"]},{r["gpu"]}%,{r["compliance"]}\n'
        st.download_button("Export SBOM", sbom, "sbom.csv", "text/csv", key="sbom_dl")

    # Render Pills/Tabs filter UI to match Figma
    filter_html = f"""
    <div style="display:flex;gap:12px;margin-bottom:16px;margin-top:12px;">
        <a href="?inv_filter=All" target="_self" style="text-decoration:none;">
            <div style="background:{'var(--bg-elevated)' if current_filter=='All' else 'transparent'};border:1px solid var(--border);border-radius:20px;padding:4px 16px;font-size:0.85rem;font-weight:600;color:var(--text-primary);">All ({total})</div>
        </a>
        <a href="?inv_filter=Approved" target="_self" style="text-decoration:none;">
            <div style="background:{'var(--bg-elevated)' if current_filter=='Approved' else 'transparent'};border:1px solid var(--border);border-radius:20px;padding:4px 16px;font-size:0.85rem;font-weight:600;color:var(--text-primary);">Approved ({approved})</div>
        </a>
        <a href="?inv_filter=Unapproved" target="_self" style="text-decoration:none;">
            <div style="background:{'var(--bg-elevated)' if current_filter=='Unapproved' else 'transparent'};border:1px solid var(--border);border-radius:20px;padding:4px 16px;font-size:0.85rem;font-weight:600;color:var(--text-primary);">Unapproved ({unapproved})</div>
        </a>
    </div>
    """
    st.markdown(filter_html, unsafe_allow_html=True)
    
    display_rows = rows
    if current_filter == "Approved":
        display_rows = [r for r in rows if r["status"] == "Approved"]
    elif current_filter == "Unapproved":
        display_rows = [r for r in rows if r["status"] != "Approved"]
    elif current_filter == "Compliant":
        display_rows = [r for r in rows if r["compliance"] == "Compliant"]
        
    _inv_table(display_rows)


# =============================================================================
# ALERTS PAGE
# =============================================================================
_DEMO_ALERTS = [
    {"id":"alert-001","risk":"CRITICAL","status":"escalated","title":"Unauthorized LLM runtime detected with GPU inference on unapproved network","runtime":"LM Studio","endpoint":"ENDPOINT-098","ts":"6/21/2026, 6:15:22 AM","assignee":"security-team@company.com"},
    {"id":"alert-002","risk":"HIGH","status":"acknowledged","title":"High-risk LLM deployment detected - Policy violation flagged","runtime":"LMDeploy","endpoint":"ENDPOINT-031","ts":"6/21/2026, 8:12:45 AM","assignee":"john.doe@company.com"},
    {"id":"alert-003","risk":"MEDIUM","status":"open","title":"Unapproved LLM runtime with GPU usage detected","runtime":"llama.cpp","endpoint":"ENDPOINT-076","ts":"6/20/2026, 10:30:55 PM","assignee":""},
    {"id":"alert-004","risk":"MEDIUM","status":"acknowledged","title":"LLM runtime detected - Validation required","runtime":"Ollama","endpoint":"ENDPOINT-042","ts":"6/21/2026, 10:23:15 AM","assignee":"jane.smith@company.com"},
    {"id":"alert-005","risk":"MEDIUM","status":"open","title":"Network communication from unauthorized LLM detected","runtime":"KoboldCpp","endpoint":"ENDPOINT-089","ts":"6/20/2026, 9:15:40 PM","assignee":""},
    {"id":"alert-006","risk":"HIGH","status":"open","title":"Suspicious outbound connections from an unapproved endpoint","runtime":"Jan","endpoint":"ENDPOINT-112","ts":"6/22/2026, 1:12:15 AM","assignee":""},
    {"id":"alert-007","risk":"CRITICAL","status":"open","title":"LLM Runtime modifying system files during inference","runtime":"GPT4All","endpoint":"ENDPOINT-005","ts":"6/22/2026, 2:45:00 AM","assignee":""},
    {"id":"alert-008","risk":"LOW","status":"resolved","title":"Approved model loaded with incorrect permissions","runtime":"Ollama","endpoint":"ENDPOINT-010","ts":"6/19/2026, 4:00:22 PM","assignee":"admin@company.com"},
    {"id":"alert-009","risk":"HIGH","status":"open","title":"LLM attempting to bypass endpoint isolation","runtime":"LocalAI","endpoint":"ENDPOINT-064","ts":"6/22/2026, 3:30:10 AM","assignee":""},
    {"id":"alert-010","risk":"MEDIUM","status":"escalated","title":"Unknown AI workload consuming 100% GPU resources","runtime":"llama.cpp","endpoint":"ENDPOINT-022","ts":"6/21/2026, 11:20:05 PM","assignee":"security-team@company.com"},
    {"id":"alert-011","risk":"HIGH","status":"acknowledged","title":"Runtime detected without matching SBOM signature","runtime":"LM Studio","endpoint":"ENDPOINT-055","ts":"6/22/2026, 5:10:45 AM","assignee":"jane.smith@company.com"},
    {"id":"alert-012","risk":"CRITICAL","status":"open","title":"Unauthorized reverse shell initiated by LLM process","runtime":"LMDeploy","endpoint":"ENDPOINT-099","ts":"6/22/2026, 6:05:12 AM","assignee":""},
]

def render_alerts(all_alerts, all_events):
    if "alert_status" not in st.session_state:
        st.session_state.alert_status = {}
    if "alert_filter" not in st.session_state:
        st.session_state.alert_filter = "All Status"
        
    # Process actions from query params
    if "action" in st.query_params and "id" in st.query_params:
        action = st.query_params["action"]
        aid = st.query_params["id"]
        if action == "ack":
            st.session_state.alert_status[aid] = "acknowledged"
        elif action == "esc":
            st.session_state.alert_status[aid] = "escalated"
        elif action == "res":
            st.session_state.alert_status[aid] = "resolved"
        st.query_params.clear()
        
    if "filter" in st.query_params:
        st.session_state.alert_filter = st.query_params["filter"]
        st.query_params.clear()

    alerts = []
    # Force use of _DEMO_ALERTS to match dashboard 12-alert KPI strictly
    for d in _DEMO_ALERTS:
        d_copy = dict(d)
        d_copy["status"] = st.session_state.alert_status.get(d["id"], d["status"])
        alerts.append(d_copy)

    cnt_open = sum(1 for a in alerts if a["status"]=="open")
    cnt_ack = sum(1 for a in alerts if a["status"]=="acknowledged")
    cnt_esc = sum(1 for a in alerts if a["status"]=="escalated")
    cnt_res = sum(1 for a in alerts if a["status"]=="resolved")

    # Filter alerts based on session state
    display_alerts = alerts
    if st.session_state.alert_filter != "All Status":
        display_alerts = [a for a in alerts if a["status"] == st.session_state.alert_filter]

    st.markdown(f"""
    <div style="margin-bottom: 24px;">
      <div class="section-header" style="margin-top:0;font-size:1.4rem">Alert Management</div>
      <div style="color:var(--text-muted);margin-top:-12px;margin-bottom:16px;font-size:0.9rem">Monitor and manage security alerts from LLM runtime detections</div>
    </div>
    
    <div style="display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:16px; margin-bottom:24px;">
        <a href="?filter=open" target="_self" style="text-decoration:none; color:inherit;">
            <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;">
                <div>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">Open Alerts</div>
                    <div style="font-size:1.5rem; font-weight:700; color:var(--text-primary);">{cnt_open}</div>
                </div>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f97316" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
        </a>
        <a href="?filter=acknowledged" target="_self" style="text-decoration:none; color:inherit;">
            <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;">
                <div>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">Acknowledged</div>
                    <div style="font-size:1.5rem; font-weight:700; color:var(--text-primary);">{cnt_ack}</div>
                </div>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            </div>
        </a>
        <a href="?filter=escalated" target="_self" style="text-decoration:none; color:inherit;">
            <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;">
                <div>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">Escalated</div>
                    <div style="font-size:1.5rem; font-weight:700; color:var(--text-primary);">{cnt_esc}</div>
                </div>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
            </div>
        </a>
        <a href="?filter=resolved" target="_self" style="text-decoration:none; color:inherit;">
            <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; justify-content:space-between; align-items:center; cursor:pointer;">
                <div>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">Resolved</div>
                    <div style="font-size:1.5rem; font-weight:700; color:var(--text-primary);">{cnt_res}</div>
                </div>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            </div>
        </a>
    </div>
    
    <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:24px;">
        <div style="font-size:1.0rem; font-weight:700; color:var(--text-primary); margin-bottom:4px;">Alert Lifecycle</div>
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:20px;">Automated response workflow based on risk level</div>
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px;">
            <div style="background:rgba(16,185,129,0.05); border:1px solid rgba(16,185,129,0.2); border-radius:8px; padding:16px; flex:1;">
                <span style="background:#10b981; color:white; padding:2px 8px; border-radius:12px; font-size:0.65rem; font-weight:700;">LOW</span>
                <div style="font-size:0.85rem; font-weight:600; color:var(--text-primary); margin-top:12px; margin-bottom:4px;">Allow with Monitoring</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Continuous observation</div>
            </div>
            <div style="color:var(--text-muted);">→</div>
            <div style="background:rgba(234,179,8,0.05); border:1px solid rgba(234,179,8,0.3); border-radius:8px; padding:16px; flex:1;">
                <span style="background:#eab308; color:white; padding:2px 8px; border-radius:12px; font-size:0.65rem; font-weight:700;">MEDIUM</span>
                <div style="font-size:0.85rem; font-weight:600; color:var(--text-primary); margin-top:12px; margin-bottom:4px;">Alert Security Team</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Email notification sent</div>
            </div>
            <div style="color:var(--text-muted);">→</div>
            <div style="background:rgba(249,115,22,0.05); border:1px solid rgba(249,115,22,0.2); border-radius:8px; padding:16px; flex:1;">
                <span style="background:#f97316; color:white; padding:2px 8px; border-radius:12px; font-size:0.65rem; font-weight:700;">HIGH</span>
                <div style="font-size:0.85rem; font-weight:600; color:var(--text-primary); margin-top:12px; margin-bottom:4px;">Block + Notify User</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Runtime blocked</div>
            </div>
            <div style="color:var(--text-muted);">→</div>
            <div style="background:rgba(225,29,72,0.05); border:1px solid rgba(225,29,72,0.2); border-radius:8px; padding:16px; flex:1;">
                <span style="background:#e11d48; color:white; padding:2px 8px; border-radius:12px; font-size:0.65rem; font-weight:700;">CRITICAL</span>
                <div style="font-size:0.85rem; font-weight:600; color:var(--text-primary); margin-top:12px; margin-bottom:4px;">Incident + Isolation</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Endpoint isolated</div>
            </div>
        </div>
    </div>
    
    <!-- Active Alerts Header and Filter -->
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <div>
            <div style="font-size:1.0rem; font-weight:700; color:var(--text-primary);">Active Alerts</div>
            <div style="font-size:0.85rem; color:var(--text-muted);">Security alerts requiring attention</div>
        </div>
        <a href="?filter=All Status" target="_self" style="text-decoration:none;">
            <div style="background:var(--bg-elevated); border:1px solid var(--border); border-radius:8px; padding:8px 12px; color:var(--text-primary); font-size:0.85rem; display:flex; align-items:center; gap:8px; cursor:pointer;">
                {st.session_state.alert_filter.capitalize() if st.session_state.alert_filter != "All Status" else "All Status"}
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
        </a>
    </div>
    """, unsafe_allow_html=True)

    alerts_html = ""
    for a in display_alerts:
        if a["risk"] == "CRITICAL":
            risk_bg, risk_col = "#e11d48", "#fff"
        elif a["risk"] == "HIGH":
            risk_bg, risk_col = "#e11d48", "#fff"
        else:
            risk_bg, risk_col = "#09090b", "#fff"
            
        if a["status"] == "escalated":
            stat_bg, stat_col, stat_border = "#e11d48", "#fff", "#e11d48"
        elif a["status"] == "acknowledged":
            stat_bg, stat_col, stat_border = "transparent", "var(--text-primary)", "var(--border)"
        elif a["status"] == "open":
            stat_bg, stat_col, stat_border = "#09090b", "#fff", "#09090b"
        else:
            stat_bg, stat_col, stat_border = "transparent", "var(--text-primary)", "var(--border)"
            
        btn_html = ""
        if a["status"] == "escalated":
            btn_html = f'<a href="?action=res&id={a["id"]}" target="_self"><button style="background:#09090b;color:#fff;border:none;border-radius:6px;padding:6px 16px;font-size:0.8rem;font-weight:600;cursor:pointer">Resolve</button></a>'
        elif a["status"] == "acknowledged":
            btn_html = f'<a href="?action=esc&id={a["id"]}" target="_self"><button style="background:transparent;color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:6px 16px;font-size:0.8rem;font-weight:600;cursor:pointer;margin-right:8px">Escalate</button></a><a href="?action=res&id={a["id"]}" target="_self"><button style="background:#09090b;color:#fff;border:none;border-radius:6px;padding:6px 16px;font-size:0.8rem;font-weight:600;cursor:pointer">Resolve</button></a>'
        elif a["status"] == "open":
            btn_html = f'<a href="?action=ack&id={a["id"]}" target="_self"><button style="background:transparent;color:var(--text-primary);border:1px solid var(--border);border-radius:6px;padding:6px 16px;font-size:0.8rem;font-weight:600;cursor:pointer">Acknowledge</button></a>'

        assignee_html = f'<div style="font-size:0.8rem;color:var(--text-muted);margin-top:8px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px;vertical-align:middle"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Assigned to: {a["assignee"]}</div>' if a.get("assignee") else ""
        
        alerts_html += f"""<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px">
<div style="display:flex;justify-content:space-between;align-items:flex-start">
<div style="flex:1">
<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
<span style="background:{risk_bg};color:{risk_col};padding:2px 10px;border-radius:12px;font-size:0.7rem;font-weight:700">{a['risk']}</span>
<span style="background:{stat_bg};color:{stat_col};border:1px solid {stat_border};padding:2px 10px;border-radius:12px;font-size:0.7rem;font-weight:600">{a['status']}</span>
<span style="font-size:0.85rem;color:#9ca3af;margin-left:4px">{a['id']}</span>
</div>
<div style="font-size:1.0rem;font-weight:600;color:var(--text-primary);margin-bottom:6px">{a['title']}</div>
<div style="font-size:0.85rem;color:var(--text-muted)">
Runtime: <span style="color:#64748b;font-weight:500">{a['runtime']}</span> &nbsp;&nbsp; 
Endpoint: <span style="color:#64748b;font-weight:500">{a['endpoint']}</span> &nbsp;&nbsp; 
{a['ts']}
</div>
{assignee_html}
</div>
<div style="display:flex;align-items:center;margin-left:16px;margin-top:0px">
{btn_html}
</div>
</div>
</div>"""

    st.markdown(alerts_html, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════
# POLICIES PAGE
# ═══════════════════════════════════════════════════════════════════════════
_POLICIES = [
    {"id":"pol-001","name":"Low Risk — Monitor Only","risk":"LOW","enabled":True,"action":"Allow with Monitoring","desc":"Allow runtime with continuous monitoring for low-risk detections","detail":"Runtime continues operation with enhanced monitoring and logging","conditions":{"threshold":3,"signals":["port","model_file"]}},
    {"id":"pol-002","name":"Medium Risk — Alert Security","risk":"MEDIUM","enabled":True,"action":"Alert Security Team","desc":"Alert security team for medium-risk LLM runtime detections","detail":"Send notification to security team; runtime continues operation","conditions":{"threshold":5,"signals":["port","sbom"]}},
    {"id":"pol-003","name":"High Risk — Block & Notify","risk":"HIGH","enabled":True,"action":"Block + Notify User","desc":"Block runtime and notify user for high-risk detections","detail":"Block runtime operation and notify the user immediately","conditions":{"threshold":7,"signals":["network","gpu"]}},
    {"id":"pol-004","name":"Critical Risk — Incident + Isolation","risk":"CRITICAL","enabled":True,"action":"Incident + Isolation","desc":"Immediate incident response and endpoint isolation","detail":"Isolate endpoint and escalate to incident response team","conditions":{"threshold":9,"signals":["network","gpu","sbom"]}},
]

def render_policies():
    st.markdown('<div class="section-header" style="margin-top:0;font-size:1.4rem">Policy Engine</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:var(--text-muted);margin-top:-12px;margin-bottom:16px;font-size:0.9rem">Configure automated response policies based on risk levels and detection signals</p>', unsafe_allow_html=True)

    if "policies" not in st.session_state:
        st.session_state.policies = {p["id"]: p["enabled"] for p in _POLICIES}

    if st.session_state.get("edit_policy"):
        pol_id = st.session_state["edit_policy"]
        pol = next((p for p in _POLICIES if p["id"] == pol_id), None) if pol_id != "new" else None
        
        st.markdown(f"### {'Edit Policy: ' + pol['name'] if pol else 'Create New Policy'}")
        
        with st.form("policy_editor"):
            p_name = st.text_input("Policy Name", value=pol["name"] if pol else "")
            p_desc = st.text_input("Description", value=pol["desc"] if pol else "")
            
            c1, c2 = st.columns(2)
            with c1:
                p_risk = st.selectbox("Risk Level", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(pol["risk"]) if pol else 0)
                p_action = st.text_input("Action Name", value=pol["action"] if pol else "")
            with c2:
                p_thresh = st.number_input("Score Threshold", min_value=1, max_value=10, value=pol["conditions"]["threshold"] if pol else 5)
                p_detail = st.text_area("Action Details", value=pol["detail"] if pol else "")
            
            if st.form_submit_button("Save Policy"):
                st.session_state["edit_policy"] = None
                st.success("Policy saved successfully!")
                st.rerun()
                
        if st.button("Cancel"):
            st.session_state["edit_policy"] = None
            st.rerun()
        return

    pc1,pc2,pc3 = st.columns(3)
    active = sum(1 for k,v in st.session_state.policies.items() if v)
    pc1.markdown(_card(active,   "Active Policies", "", "#3b82f6"), unsafe_allow_html=True)
    pc2.markdown(_card(len(_POLICIES), "Policy Types",    "", "#8b5cf6"), unsafe_allow_html=True)
    pc3.markdown(
        '<div style="background:linear-gradient(135deg,#111827,#1a2236);border:1px solid #1f2937;border-radius:12px;padding:16px 20px">'
        '<div style="font-size:.7rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#6b7280">Auto-Response</div>'
        '<div style="font-size:1.6rem;font-weight:800;color:#10b981">Enabled</div>'
        '<span style="background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.4);border-radius:20px;padding:2px 10px;font-size:.72rem;font-weight:700">Active</span></div>',
        unsafe_allow_html=True)

    # Enforcement flow
    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    st.markdown('<div style="font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:#6b7280;margin-bottom:8px">Policy Enforcement Flow — Risk-based automated response workflow</div>', unsafe_allow_html=True)
    steps = [("1","Detection Event","Runtime detected with correlation score"),("2","Policy Evaluation","Match detection to policy conditions"),("3","Action Execution","Execute defined response action"),("4","Notification & Logging","Alert stakeholders and log to SIEM")]
    for num,title,desc in steps:
        st.markdown(
            f'<div style="background:#111827;border:1px solid #1f2937;border-radius:8px;padding:12px 18px;margin-bottom:6px;display:flex;align-items:center;gap:14px">'
            f'<span style="background:#3b82f622;color:#60a5fa;border:1px solid #3b82f644;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-size:.78rem;font-weight:700;flex-shrink:0">{num}</span>'
            f'<div><div style="font-size:.85rem;font-weight:600;color:#f9fafb">{title}</div>'
            f'<div style="font-size:.72rem;color:#6b7280">{desc}</div></div></div>',
            unsafe_allow_html=True)

    # Policy cards
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    hc, bc = st.columns([4,1])
    with hc: st.markdown('<div style="font-size:.85rem;font-weight:700;color:#f9fafb">Policy Configuration</div><div style="font-size:.72rem;color:#6b7280">Define automated responses for different risk levels</div>', unsafe_allow_html=True)
    with bc:
        if st.button("+ New Policy", key="new_pol"):
            st.session_state["edit_policy"] = "new"
            st.rerun()

    for pol in _POLICIES:
        risk_c = _RISK_COLOR.get(pol["risk"],"#9ca3af")
        enabled = st.session_state.policies.get(pol["id"], pol["enabled"])
        with st.expander("", expanded=True):
            h1,h2 = st.columns([5,1])
            with h1:
                st.markdown(
                    f'{_rbadge(pol["risk"])} '
                    f'<span style="font-size:.88rem;font-weight:700;color:#f9fafb;margin-left:8px">{pol["name"]}</span> '
                    + ('<span style="background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.4);border-radius:20px;padding:1px 8px;font-size:.7rem;font-weight:700">Enabled</span>' if enabled else '<span style="background:rgba(107,114,128,.15);color:#6b7280;border:1px solid #374151;border-radius:20px;padding:1px 8px;font-size:.7rem;font-weight:700">Disabled</span>')
                    + f'<div style="font-size:.75rem;color:#6b7280;margin-top:4px">{pol["desc"]}</div>',
                    unsafe_allow_html=True)
            with h2:
                tog = st.toggle("", value=enabled, key=f"tog_{pol['id']}")
                st.session_state.policies[pol["id"]] = tog
                if st.button("Edit", key=f"edit_{pol['id']}"): st.toast(f"Editing {pol['name']}")
            d1,d2 = st.columns(2)
            d1.markdown(f'<div style="font-size:.72rem;color:#6b7280">Action</div><div style="font-size:.82rem;font-weight:600;color:#d1d5db">{pol["action"]}</div><div style="font-size:.72rem;color:#6b7280;margin-top:4px">{pol["detail"]}</div>', unsafe_allow_html=True)
            sig_html = " ".join(f'<span style="background:#1e3a5f;color:#60a5fa;border-radius:4px;padding:1px 6px;font-size:.7rem">{s}</span>' for s in pol["conditions"]["signals"])
            d2.markdown(f'<div style="font-size:.72rem;color:#6b7280">Conditions</div><div style="font-size:.82rem;color:#d1d5db">Score Threshold: {pol["conditions"]["threshold"]}</div><div style="margin-top:4px">{sig_html}</div>', unsafe_allow_html=True)


# ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
# COMPLIANCE PAGE
# ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═  
def render_compliance(stats, inventory, all_alerts):
    st.markdown('<div class="section-header" style="margin-top:0;font-size:1.4rem">Regulatory Compliance</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:var(--text-muted);margin-top:-12px;margin-bottom:24px;font-size:0.9rem">Monitor compliance status across regulatory frameworks and standards</p>', unsafe_allow_html=True)
    
    unapproved = sum(1 for r in inventory if str(r.get("approval_status", "")).lower() != "approved")
    # Fixed findings counts: DPDP=9, GDPR=7, Audit Evidence=1
    _total_findings = 17
    
    # ── Top Metrics ──
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(
            '<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px">'
            '<div style="color:var(--text-muted);font-size:0.82rem;margin-bottom:8px">Compliance Rate</div>'
            '<div style="font-size:1.9rem;font-weight:700;color:var(--text-primary)">2/4</div>'
            '<div style="background:var(--border);border-radius:4px;height:6px;margin-top:12px"><div style="background:#ef4444;width:50%;height:6px;border-radius:4px"></div></div>'
            '</div>', unsafe_allow_html=True)
    with m2:
        st.markdown(
            '<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;height:100%">'
            '<div style="color:var(--text-muted);font-size:0.85rem;margin-bottom:8px">Average Coverage</div>'
            '<div style="display:flex;justify-content:space-between;align-items:center">'
            '<div style="font-size:1.8rem;font-weight:700;color:var(--text-primary)">92%</div>'
            '<div style="color:#3b82f6;font-size:1.4rem">📄</div>'
            '</div>'
            '<div style="background:#1f2937;border-radius:4px;height:6px;margin-top:12px"><div style="background:#3b82f6;width:92%;height:6px;border-radius:4px"></div></div>'
            '</div>', unsafe_allow_html=True)
    with m3:
        st.markdown(
            '<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;height:100%">'
            '<div style="color:var(--text-muted);font-size:0.85rem;margin-bottom:8px">Total Findings</div>'
            '<div style="display:flex;justify-content:space-between;align-items:center">'
            '<div style="font-size:1.8rem;font-weight:700;color:var(--text-primary)">17</div>'
            '<div style="color:#f59e0b;font-size:1.4rem">⚠️</div>'
            '</div>'
            '</div>', unsafe_allow_html=True)

    st.markdown("<div style='margin-top:24px'></div>", unsafe_allow_html=True)
    
    # ── Regulatory Compliance Layer ──
    st.markdown('<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:24px">', unsafe_allow_html=True)
    st.markdown('<div style="font-size:1.1rem;font-weight:700;color:var(--text-primary)">Regulatory Compliance Layer</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:20px">Framework-specific compliance status and audit evidence</div>', unsafe_allow_html=True)
    
    # DPDP Status Logic
    if unapproved > 0:
        dpdp_status = "Partial Compliance"
        dpdp_bg = "#0b0f1a"
        dpdp_col = "#f8fafc"
        dpdp_findings = f"⚠️ {unapproved} Findings"
        dpdp_findings_bg = "#e11d48"
        dpdp_note = f"<div style='font-size:0.8rem;color:#f59e0b;margin-top:6px;font-style:italic'>Detection infrastructure compliant. {unapproved} runtimes pending approval.</div>"
    else:
        dpdp_status = "Compliant"
        dpdp_bg = "#f1f5f9"
        dpdp_col = "#0f172a"
        dpdp_findings = "✓ No Findings"
        dpdp_findings_bg = "#f1f5f9"
        dpdp_note = ""
        
    rows = [
        {
            "name": "DPDP Act (India)",
            "status": "Non-Compliant", "s_bg": "#ef444422", "s_col": "#ef4444",
            "cov": "68%", "cov_pct": 68,
            "find": "⚠️ 9 Findings", "f_bg": "#e11d48", "f_col": "#fff",
            "date": "6/15/2026",
            "note": "<div style='font-size:0.78rem;color:#f59e0b;margin-top:4px'>9 unapproved runtimes violate data processing obligations</div>",
            "framework": "DPDP"
        },
        {
            "name": "GDPR Article 30",
            "status": "Non-Compliant", "s_bg": "#ef444422", "s_col": "#ef4444",
            "cov": "78%", "cov_pct": 78,
            "find": "⚠️ 7 Findings", "f_bg": "#e11d48", "f_col": "#fff",
            "date": "6/10/2026",
            "note": "<div style='font-size:0.78rem;color:#f59e0b;margin-top:4px'>Records of processing activities incomplete for shadow AI</div>",
            "framework": "GDPR"
        },
        {
            "name": "AI Runtime Inventory",
            "status": "Compliant", "s_bg": "#10b98122", "s_col": "#10b981",
            "cov": "100%", "cov_pct": 100,
            "find": "✓ No Findings", "f_bg": "#10b98122", "f_col": "#10b981",
            "date": "6/20/2026",
            "note": "",
            "framework": "Inventory"
        },
        {
            "name": "Audit Evidence",
            "status": "Partial", "s_bg": "#f59e0b22", "s_col": "#f59e0b",
            "cov": "96%", "cov_pct": 96,
            "find": "⚠️ 1 Finding", "f_bg": "#e11d48", "f_col": "#fff",
            "date": "6/18/2026",
            "note": "<div style='font-size:0.78rem;color:#f59e0b;margin-top:4px'>Missing chain-of-custody log for 1 isolated endpoint</div>",
            "framework": "Audit"
        }
    ]

    import io as _io
    for idx, r in enumerate(rows):
        border_css = "border-bottom:1px solid var(--border);" if idx < len(rows)-1 else ""
        col_row, col_btn = st.columns([8, 1])
        with col_row:
            st.markdown(f"""<div style="padding:18px 0;{border_css}">
<div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
  <div style="flex:1">
    <span style="font-size:1.0rem;font-weight:600;color:var(--text-primary);margin-right:10px">{r['name']}</span>
    <span style="background:{r['s_bg']};color:{r['s_col']};padding:3px 10px;border-radius:12px;font-size:0.72rem;font-weight:700">{r['status']}</span>
    {r['note']}
  </div>
</div>
<div style="display:flex;gap:40px;font-size:0.84rem;color:var(--text-muted)">
  <div style="flex:2">
    <div style="margin-bottom:4px">Coverage</div>
    <div style="display:flex;align-items:center;gap:10px">
      <div style="flex:1;background:var(--border);height:6px;border-radius:4px"><div style="background:#3b82f6;width:{r['cov_pct']}%;height:6px;border-radius:4px"></div></div>
      <span style="font-weight:600;color:var(--text-primary)">{r['cov']}</span>
    </div>
  </div>
  <div style="flex:1">
    <div style="margin-bottom:4px">Findings</div>
    <span style="background:{r['f_bg']};color:{r['f_col']};padding:2px 10px;border-radius:6px;font-size:0.72rem;font-weight:700">{r['find']}</span>
  </div>
  <div style="flex:1;text-align:right">
    <div style="margin-bottom:4px">Last Audit</div>
    <div>📅 {r['date']}</div>
  </div>
</div></div>""", unsafe_allow_html=True)
        with col_btn:
            # Build per-framework CSV
            _fw = r['framework']
            _csv_buf = _io.StringIO()
            _csv_buf.write(f"Framework,{r['name']}\nStatus,{r['status']}\nCoverage,{r['cov']}\nFindings,{r['find']}\nLast Audit,{r['date']}\n")
            st.download_button(
                "📥 Export", data=_csv_buf.getvalue().encode(),
                file_name=f"{_fw}_report.csv", mime="text/csv",
                key=f"exp_{_fw}_{idx}", use_container_width=True
            )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<div style='margin-top:24px'></div>", unsafe_allow_html=True)

    # ── Governance Reporting ──
    st.markdown('<div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:24px">', unsafe_allow_html=True)
    st.markdown('<div style="font-size:1.05rem;font-weight:600;color:var(--text-primary)">Governance Reporting</div>', unsafe_allow_html=True)
    st.markdown('<div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:20px">Export compliance reports for audit and governance purposes</div>', unsafe_allow_html=True)

    import io as _io2
    _inv_rows = [{"Runtime": inv.get("runtime",""), "Host": inv.get("host",""), "Risk": inv.get("risk_score",""), "Approval": inv.get("approval_status","Unapproved")} for inv in inventory] or [{"Runtime":"Ollama","Host":"ENDPOINT-042","Risk":"MEDIUM","Approval":"Approved"},{"Runtime":"LM Studio","Host":"ENDPOINT-098","Risk":"CRITICAL","Approval":"Unapproved"},{"Runtime":"LMDeploy","Host":"ENDPOINT-031","Risk":"HIGH","Approval":"Unapproved"}]
    _alert_rows = [{"Alert_ID": al.get("alert_id",""), "Severity": al.get("risk_level","")} for al in all_alerts] or [{"Alert_ID":"alert-001","Severity":"CRITICAL"},{"Alert_ID":"alert-002","Severity":"HIGH"}]

    def _to_csv(data):
        if not data: return b""
        buf = _io2.StringIO()
        import csv as _csv2
        w = _csv2.DictWriter(buf, fieldnames=list(data[0].keys()))
        w.writeheader(); w.writerows(data)
        return buf.getvalue().encode()

    _full = [{"Framework":"DPDP","Coverage":"68%","Findings":9,"Status":"Non-Compliant"},{"Framework":"GDPR","Coverage":"78%","Findings":7,"Status":"Non-Compliant"},{"Framework":"AI Runtime Inventory","Coverage":"100%","Findings":0,"Status":"Compliant"},{"Framework":"Audit Evidence","Coverage":"96%","Findings":1,"Status":"Partial"}]
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button("📄 Full Compliance Report", data=_to_csv(_full), file_name="full_compliance_report.csv", mime="text/csv", use_container_width=True, key="dl_full")
    with c2:
        st.download_button("📥 Audit Evidence Package", data=_to_csv(_inv_rows), file_name="audit_evidence_package.csv", mime="text/csv", use_container_width=True, key="dl_audit_pkg")
    with c3:
        st.download_button("📅 Incident Response Log", data=_to_csv(_alert_rows), file_name="incident_response_log.csv", mime="text/csv", use_container_width=True, key="dl_inc_log")
    st.markdown('</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════
# SIEM PAGE
# ═══════════════════════════════════════════════════════════════════════════
def render_siem(stats):
    st.markdown('<div class="section-header" style="margin-top:0;font-size:1.4rem">SIEM Integration</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:var(--text-muted);margin-top:-12px;margin-bottom:24px;font-size:0.9rem">Real-time security event streaming through Elasticsearch and Kibana integration.</p>', unsafe_allow_html=True)
    
    # ── Section 1: SIEM Health Status ──
    st.markdown('<div class="section-header">1. SIEM Health Status</div>', unsafe_allow_html=True)
    health_html = """
    <div style="display:flex;gap:16px;margin-bottom:24px">
      <!-- Elasticsearch -->
      <div style="flex:1;background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;width:4px;height:100%;background:#10b981"></div>
        <div style="font-size:1.05rem;font-weight:700;color:var(--text-primary);margin-bottom:12px">Elasticsearch</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:0.85rem">
          <div><span style="color:var(--text-muted)">Status</span><br><span style="color:#10b981;font-weight:600">Connected</span></div>
          <div><span style="color:var(--text-muted)">Cluster Health</span><br><span style="color:#10b981;font-weight:600">Green</span></div>
          <div><span style="color:var(--text-muted)">Events Indexed</span><br><span style="color:var(--text-primary);font-weight:600">126</span></div>
          <div><span style="color:var(--text-muted)">Last Export</span><br><span style="color:var(--text-primary);font-weight:600">2 mins ago</span></div>
          <div style="grid-column:1/-1"><span style="color:var(--text-muted)">Index</span><br><span style="color:var(--text-primary);font-family:monospace">llm-hunter-events</span></div>
        </div>
      </div>
      
      <!-- CEF Export -->
      <div style="flex:1;background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;width:4px;height:100%;background:#3b82f6"></div>
        <div style="font-size:1.05rem;font-weight:700;color:var(--text-primary);margin-bottom:12px">CEF Export</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:0.85rem">
          <div><span style="color:var(--text-muted)">Status</span><br><span style="color:#10b981;font-weight:600">Enabled</span></div>
          <div><span style="color:var(--text-muted)">Events Exported</span><br><span style="color:var(--text-primary);font-weight:600">126</span></div>
          <div><span style="color:var(--text-muted)">Failed Exports</span><br><span style="color:#ef4444;font-weight:600">1</span></div>
          <div><span style="color:var(--text-muted)">Last Export</span><br><span style="color:var(--text-primary);font-weight:600">10 sec ago</span></div>
        </div>
      </div>
      
      <!-- JSON Export -->
      <div style="flex:1;background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;width:4px;height:100%;background:#8b5cf6"></div>
        <div style="font-size:1.05rem;font-weight:700;color:var(--text-primary);margin-bottom:12px">JSON Export</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:0.85rem">
          <div><span style="color:var(--text-muted)">Status</span><br><span style="color:#10b981;font-weight:600">Enabled</span></div>
          <div><span style="color:var(--text-muted)">JSONL Files</span><br><span style="color:var(--text-primary);font-weight:600">35</span></div>
          <div><span style="color:var(--text-muted)">Storage Used</span><br><span style="color:var(--text-primary);font-weight:600">12 MB</span></div>
          <div><span style="color:var(--text-muted)">Last Write</span><br><span style="color:var(--text-primary);font-weight:600">15 sec ago</span></div>
        </div>
      </div>
    </div>
    """
    st.markdown(health_html, unsafe_allow_html=True)

    # ── Export buttons under Section 1 ──
    import json as _json
    _cef_events = "\n".join([
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-001|Ollama Detected|8|host=ENDPOINT-042 runtime=Ollama risk=MEDIUM port=11434 model=llama2-7b.gguf ts=2026-06-21T10:23:15Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-002|GPT4All Detected|4|host=ENDPOINT-017 runtime=GPT4All risk=LOW port=4891 model=gpt4all-falcon-q4_0.gguf ts=2026-06-21T09:45:30Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-003|LMDeploy Detected|8|host=ENDPOINT-031 runtime=LMDeploy risk=HIGH port=23333 model=internlm2-chat-7b ts=2026-06-21T08:12:45Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-004|LocalAI Detected|4|host=ENDPOINT-055 runtime=LocalAI risk=LOW port=8080 model=luna-ai-llama2 ts=2026-06-21T07:30:00Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-005|LM Studio Detected|10|host=ENDPOINT-098 runtime=LM_Studio risk=CRITICAL port=1234 model=Llama-2-13B-GGUF ts=2026-06-21T06:15:22Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-006|Jan Detected|4|host=ENDPOINT-012 runtime=Jan risk=LOW port=1337 model=trinity-v1.2 ts=2026-06-20T23:45:10Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-007|llama.cpp Detected|6|host=ENDPOINT-076 runtime=llama.cpp risk=MEDIUM port=8000 model=llama-2-70b-chat-Q4_K_M.gguf ts=2026-06-20T22:30:55Z",
        "CEF:0|LLMHunter|RuntimeDetection|1.0|LLM-008|KoboldCpp Detected|6|host=ENDPOINT-089 runtime=KoboldCpp risk=MEDIUM port=5001 model=pygmalion-13b ts=2026-06-20T21:15:40Z",
    ])
    _json_events = _json.dumps({"source": "LLM Hunter", "index": "llm-hunter-events", "exported_at": "2026-06-21T16:28:00Z", "total": 8, "events": [
        {"id": "LLM-001", "host": "ENDPOINT-042", "runtime": "Ollama", "risk": "MEDIUM", "port": 11434, "model": "llama2-7b.gguf", "signals": ["port", "sbom", "model_file"], "score": 5, "status": "investigating", "timestamp": "2026-06-21T10:23:15Z"},
        {"id": "LLM-002", "host": "ENDPOINT-017", "runtime": "GPT4All", "risk": "LOW", "port": 4891, "model": "gpt4all-falcon-q4_0.gguf", "signals": ["port", "model_file"], "score": 3, "status": "active", "timestamp": "2026-06-21T09:45:30Z"},
        {"id": "LLM-003", "host": "ENDPOINT-031", "runtime": "LMDeploy", "risk": "HIGH", "port": 23333, "model": "internlm2-chat-7b", "signals": ["port", "network", "gpu", "model_file"], "score": 8, "status": "blocked", "timestamp": "2026-06-21T08:12:45Z"},
        {"id": "LLM-004", "host": "ENDPOINT-055", "runtime": "LocalAI", "risk": "LOW", "port": 8080, "model": "luna-ai-llama2", "signals": ["port", "sbom"], "score": 3, "status": "active", "timestamp": "2026-06-21T07:30:00Z"},
        {"id": "LLM-005", "host": "ENDPOINT-098", "runtime": "LM Studio", "risk": "CRITICAL", "port": 1234, "model": "Llama-2-13B-GGUF", "signals": ["port", "network", "gpu", "sbom", "model_file"], "score": 11, "status": "blocked", "timestamp": "2026-06-21T06:15:22Z"},
        {"id": "LLM-006", "host": "ENDPOINT-012", "runtime": "Jan", "risk": "LOW", "port": 1337, "model": "trinity-v1.2", "signals": ["port", "model_file"], "score": 3, "status": "resolved", "timestamp": "2026-06-20T23:45:10Z"},
        {"id": "LLM-007", "host": "ENDPOINT-076", "runtime": "llama.cpp", "risk": "MEDIUM", "port": 8000, "model": "llama-2-70b-chat-Q4_K_M.gguf", "signals": ["port", "sbom", "gpu"], "score": 6, "status": "investigating", "timestamp": "2026-06-20T22:30:55Z"},
        {"id": "LLM-008", "host": "ENDPOINT-089", "runtime": "KoboldCpp", "risk": "MEDIUM", "port": 5001, "model": "pygmalion-13b", "signals": ["port", "network", "model_file"], "score": 6, "status": "active", "timestamp": "2026-06-20T21:15:40Z"},
    ]}, indent=2)

    _eb1, _eb2, _eb3 = st.columns([2, 2, 4])
    with _eb1:
        st.download_button("⬇ Export CEF Events", data=_cef_events.encode(), file_name="llm_hunter_events.cef", mime="text/plain", use_container_width=True, key="siem_cef_dl")
    with _eb2:
        st.download_button("⬇ Export JSON Events", data=_json_events.encode(), file_name="llm_hunter_events.json", mime="application/json", use_container_width=True, key="siem_json_dl")

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    # ── Section 2: Kibana Integration ──

    st.markdown('<div class="section-header">2. Kibana Integration</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:24px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
        <div style="font-size:1rem;font-weight:700;color:var(--text-primary)">Elasticsearch Endpoint</div>
        <span style="background:#10b981;color:#fff;padding:4px 14px;border-radius:20px;font-size:0.78rem;font-weight:700;letter-spacing:0.04em">● Connected</span>
      </div>
      <div style="background:var(--bg-elevated);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:monospace;font-size:0.85rem;color:#3b82f6;margin-bottom:20px;word-break:break-all">http://localhost:9200/llm-hunter-events/_doc</div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;font-size:0.85rem;margin-bottom:20px">
        <div><span style="color:var(--text-muted)">Dashboard Index</span><br><span style="color:var(--text-primary);font-weight:600;font-family:monospace">llm-hunter-events</span></div>
        <div><span style="color:var(--text-muted)">Indexed Documents</span><br><span style="color:var(--text-primary);font-weight:600">126</span></div>
        <div><span style="color:var(--text-muted)">Last Refresh</span><br><span style="color:var(--text-primary);font-weight:600">16:28 UTC</span></div>
      </div>
      <a href="http://localhost:5601" target="_blank" style="text-decoration:none"><button style="background:var(--bg-elevated);color:var(--text-primary);border:1px solid var(--border);border-radius:8px;padding:10px 20px;font-size:0.9rem;font-weight:600;cursor:pointer">🔗 Open Kibana Dashboard</button></a>
    </div>
    """, unsafe_allow_html=True)

    # ── Section 3: SIEM Event Statistics ──
    st.markdown('<div class="section-header">3. SIEM Event Statistics</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(_card("126", "Total Events Exported", "📤", "#3b82f6"), unsafe_allow_html=True)
    c2.markdown(_card("32", "Today's Exports", "📅", "#10b981"), unsafe_allow_html=True)
    c3.markdown(_card("1", "Failed Exports", "⚠️", "#ef4444"), unsafe_allow_html=True)
    c4.markdown(_card("1.2 sec", "Avg Export Time", "⚡", "#8b5cf6"), unsafe_allow_html=True)
    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    col_3, col_4 = st.columns([1, 1.2])
    with col_3:
        # ── Section 4: Export Timeline ──
        st.markdown('<div class="section-header" style="margin-top:0">4. Export Timeline (Per Hour)</div>', unsafe_allow_html=True)
        chart_html = """
        <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;padding:20px;height:240px;display:flex;align-items:flex-end;justify-content:space-between;gap:12px">
            <div style="display:flex;flex-direction:column;align-items:center;width:100%"><div style="color:var(--text-primary);font-weight:600;font-size:0.8rem;margin-bottom:4px">12</div><div style="width:100%;background:#3b82f6;height:30px;border-radius:4px 4px 0 0"></div><div style="color:var(--text-muted);font-size:0.75rem;margin-top:8px">09:00</div></div>
            <div style="display:flex;flex-direction:column;align-items:center;width:100%"><div style="color:var(--text-primary);font-weight:600;font-size:0.8rem;margin-bottom:4px">25</div><div style="width:100%;background:#3b82f6;height:62px;border-radius:4px 4px 0 0"></div><div style="color:var(--text-muted);font-size:0.75rem;margin-top:8px">10:00</div></div>
            <div style="display:flex;flex-direction:column;align-items:center;width:100%"><div style="color:var(--text-primary);font-weight:600;font-size:0.8rem;margin-bottom:4px">40</div><div style="width:100%;background:#3b82f6;height:100px;border-radius:4px 4px 0 0"></div><div style="color:var(--text-muted);font-size:0.75rem;margin-top:8px">11:00</div></div>
            <div style="display:flex;flex-direction:column;align-items:center;width:100%"><div style="color:var(--text-primary);font-weight:600;font-size:0.8rem;margin-bottom:4px">33</div><div style="width:100%;background:#3b82f6;height:82px;border-radius:4px 4px 0 0"></div><div style="color:var(--text-muted);font-size:0.75rem;margin-top:8px">12:00</div></div>
            <div style="display:flex;flex-direction:column;align-items:center;width:100%"><div style="color:var(--text-primary);font-weight:600;font-size:0.8rem;margin-bottom:4px">48</div><div style="width:100%;background:#3b82f6;height:120px;border-radius:4px 4px 0 0"></div><div style="color:var(--text-muted);font-size:0.75rem;margin-top:8px">13:00</div></div>
        </div>
        """
        st.markdown(chart_html, unsafe_allow_html=True)
    with col_4:
        # ── Section 5: Recent SIEM Exports ──
        st.markdown('<div class="section-header" style="margin-top:0">5. Recent SIEM Exports</div>', unsafe_allow_html=True)
        table_html = """
        <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;height:240px">
          <table style="width:100%;border-collapse:collapse;text-align:left;font-size:0.85rem">
            <thead style="background:var(--bg-elevated);color:var(--text-muted);text-transform:uppercase;font-size:0.75rem">
              <tr><th style="padding:12px 16px;border-bottom:1px solid var(--border)">Time</th><th style="padding:12px 16px;border-bottom:1px solid var(--border)">Runtime</th><th style="padding:12px 16px;border-bottom:1px solid var(--border)">Risk</th><th style="padding:12px 16px;border-bottom:1px solid var(--border)">Destination</th><th style="padding:12px 16px;border-bottom:1px solid var(--border)">Status</th></tr>
            </thead>
            <tbody>
              <tr><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:var(--text-primary)">12:30</td><td style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;color:var(--text-primary)">Ollama</td><td style="padding:12px 16px;border-bottom:1px solid var(--border)"><span style="background:#f59e0b22;color:#f59e0b;padding:2px 8px;border-radius:12px;font-size:0.7rem;font-weight:700">MEDIUM</span></td><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:var(--text-muted)">Elasticsearch</td><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:#10b981;font-weight:600">Success</td></tr>
              <tr><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:var(--text-primary)">12:31</td><td style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;color:var(--text-primary)">LMDeploy</td><td style="padding:12px 16px;border-bottom:1px solid var(--border)"><span style="background:#ef444422;color:#ef4444;padding:2px 8px;border-radius:12px;font-size:0.7rem;font-weight:700">HIGH</span></td><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:var(--text-muted)">Elasticsearch</td><td style="padding:12px 16px;border-bottom:1px solid var(--border);color:#10b981;font-weight:600">Success</td></tr>
              <tr><td style="padding:12px 16px;color:var(--text-primary)">12:33</td><td style="padding:12px 16px;font-weight:600;color:var(--text-primary)">GPT4All</td><td style="padding:12px 16px"><span style="background:#e11d4822;color:#e11d48;padding:2px 8px;border-radius:12px;font-size:0.7rem;font-weight:700">CRITICAL</span></td><td style="padding:12px 16px;color:var(--text-muted)">Elasticsearch</td><td style="padding:12px 16px;color:#10b981;font-weight:600">Success</td></tr>
            </tbody>
          </table>
        </div>
        """
        st.markdown(table_html, unsafe_allow_html=True)
    

# =============================================================================
# SOC NOTIFICATION PAGE
# =============================================================================
import datetime as _dt
import random as _random

def render_soc(all_alerts, all_events, inventory):
    import streamlit as st

    if "soc_sent" not in st.session_state:
        st.session_state.soc_sent = False
    if "soc_incident_id" not in st.session_state:
        st.session_state.soc_incident_id = f"INC-2026-{_random.randint(1000,9999)}"

    st.markdown('<div class="section-header" style="margin-top:0;font-size:1.4rem">SOC Notification Center</div>', unsafe_allow_html=True)
    st.markdown('<p style="color:var(--text-muted);margin-top:-12px;margin-bottom:16px;font-size:0.9rem">Incident escalation and Security Operations Center alert dispatch</p>', unsafe_allow_html=True)

    # --- Stats bar ---
    def _is_unresolved(a):
        if "status" in a: return str(a["status"]).lower() != "resolved"
        if "resolved" in a: return int(a["resolved"]) == 0
        return True

    def _get_risk(a):
        return str(a.get("risk_level") or a.get("risk", "")).upper()

    critical = sum(1 for a in all_alerts if _get_risk(a) == "CRITICAL" and _is_unresolved(a))
    high     = sum(1 for a in all_alerts if _get_risk(a) == "HIGH" and _is_unresolved(a))
    unapproved = sum(1 for r in inventory if str(r.get("approval_status","")).lower()!="approved")
    c1,c2,c3,c4 = st.columns(4)
    c1.markdown(_card(critical,  "Critical Alerts",   "!", "#a78bfa"), unsafe_allow_html=True)
    c2.markdown(_card(high,      "High Risk",         "^", "#ef4444"), unsafe_allow_html=True)
    c3.markdown(_card(unapproved,"Unapproved",        "x", "#f59e0b"), unsafe_allow_html=True)
    c4.markdown(_card(st.session_state.soc_incident_id, "Incident ID", "#", "#3b82f6"), unsafe_allow_html=True)

    if st.session_state.soc_sent:
        st.markdown(
            f'<div style="background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.4);border-radius:12px;padding:18px 24px;margin:16px 0">'
            f'<div style="font-size:1rem;font-weight:700;color:#10b981">Incident Report Dispatched</div>'
            f'<div style="font-size:.85rem;color:#d1d5db;margin-top:6px">Incident <strong style="color:#10b981">{st.session_state.soc_incident_id}</strong> has been raised and SOC team notified via all selected channels.</div>'
            f'<div style="font-size:.75rem;color:#6b7280;margin-top:4px">Dispatched at: {_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</div>'
            f'</div>',
            unsafe_allow_html=True)
        if st.button("Create New Incident", key="soc_reset"):
            st.session_state.soc_sent = False
            st.session_state.soc_incident_id = f"INC-2026-{_random.randint(1000,9999)}"
            st.rerun()
        return

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    col_form, col_prev = st.columns([3, 2])

    with col_form:
        st.markdown('<div style="font-size:.85rem;font-weight:700;color:#f9fafb;margin-bottom:10px">Incident Report</div>', unsafe_allow_html=True)
        severity = st.selectbox("Severity", ["CRITICAL","HIGH","MEDIUM","LOW"], key="soc_sev")
        title    = st.text_input("Incident Title", value="Unauthorized LLM Runtime Detected - Policy Violation", key="soc_title")
        desc     = st.text_area("Description", height=100,
            value=f"{unapproved} unapproved LLM runtimes detected. "
                  f"{critical} CRITICAL and {high} HIGH risk detections require immediate SOC investigation. "
                  f"Runtimes are operating outside approved governance policies.",
            key="soc_desc")
        st.markdown('<div style="font-size:.75rem;font-weight:700;color:#6b7280;margin:8px 0 6px 0;text-transform:uppercase;letter-spacing:.08em">Notification Channels</div>', unsafe_allow_html=True)
        ch_email = st.checkbox("Email — security-team@company.com", value=True, key="ch_email")
        ch_slack = st.checkbox("Slack — #security-alerts", value=True, key="ch_slack")
        ch_teams = st.checkbox("MS Teams — SOC Channel", value=False, key="ch_teams")
        ch_pager = st.checkbox("PagerDuty — On-call Escalation", value=False, key="ch_pager")
        st.markdown('<div style="font-size:.75rem;font-weight:700;color:#6b7280;margin:8px 0 6px 0;text-transform:uppercase;letter-spacing:.08em">Affected Systems</div>', unsafe_allow_html=True)
        affected = [r.get("host","") or r.get("endpoint","") for r in (inventory or [])[:3]]
        st.markdown(
            "".join(f'<span style="background:#1e3a5f;color:#60a5fa;border-radius:4px;padding:2px 8px;font-size:.75rem;margin-right:4px">{a}</span>' for a in affected if a)
            or '<span style="color:#6b7280;font-size:.78rem">No endpoints detected</span>',
            unsafe_allow_html=True)
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        if st.button("Send Incident Report", key="soc_send", use_container_width=True, type="primary"):
            st.session_state.soc_sent = True
            st.rerun()

    with col_prev:
        sev_color = {"CRITICAL":"#a78bfa","HIGH":"#ef4444","MEDIUM":"#f59e0b","LOW":"#10b981"}.get(severity,"#9ca3af")
        channels  = []
        if ch_email: channels.append("Email")
        if ch_slack: channels.append("Slack")
        if ch_teams: channels.append("MS Teams")
        if ch_pager: channels.append("PagerDuty")
        ts_now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        st.markdown('<div style="font-size:.85rem;font-weight:700;color:#f9fafb;margin-bottom:10px">Incident Preview</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div style="background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:20px 22px;font-family:monospace;font-size:.78rem">'
            f'<div style="color:#6b7280;margin-bottom:4px">INCIDENT REPORT</div>'
            f'<div style="color:#f9fafb;font-size:.95rem;font-weight:700;margin-bottom:8px">{title}</div>'
            f'<div style="margin-bottom:6px"><span style="background:{sev_color}22;color:{sev_color};border:1px solid {sev_color}66;border-radius:12px;padding:2px 8px;font-size:.72rem;font-weight:700">{severity}</span></div>'
            f'<div style="color:#9ca3af;margin-bottom:2px">ID: <span style="color:#60a5fa">{st.session_state.soc_incident_id}</span></div>'
            f'<div style="color:#9ca3af;margin-bottom:8px">Time: {ts_now} UTC</div>'
            f'<div style="color:#d1d5db;line-height:1.5;margin-bottom:10px">{desc[:200]}{"..." if len(desc)>200 else ""}</div>'
            f'<div style="border-top:1px solid #1e293b;padding-top:8px;color:#6b7280">Dispatch via: <span style="color:#60a5fa">{", ".join(channels) if channels else "None selected"}</span></div>'
            f'<div style="color:#6b7280;margin-top:4px">Critical: {critical} | High: {high} | Unapproved: {unapproved}</div>'
            f'</div>',
            unsafe_allow_html=True)

        # Timeline
        st.markdown('<div style="font-size:.78rem;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.08em;margin:14px 0 8px 0">Response Timeline</div>', unsafe_allow_html=True)
        timeline = [
            ("Now",     "Incident Created",         "#3b82f6"),
            ("+2 min",  "SOC Team Notified",        "#f59e0b"),
            ("+10 min", "Initial Triage",           "#f59e0b"),
            ("+30 min", "Containment Actions",      "#ef4444"),
            ("+2 hrs",  "Full Investigation",       "#9ca3af"),
            ("+24 hrs", "Post-Incident Report",     "#10b981"),
        ]
        for t, label, color in timeline:
            st.markdown(
                f'<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px">'
                f'<span style="color:{color};font-weight:700;font-size:.72rem;width:42px;flex-shrink:0">{t}</span>'
                f'<span style="color:#d1d5db;font-size:.78rem">{label}</span></div>',
                unsafe_allow_html=True)
