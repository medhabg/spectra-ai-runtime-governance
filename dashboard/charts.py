"""
dashboard/charts.py
---------------------
Chart helper functions for the Local LLM Hunter Governance Dashboard.

All functions accept a list of event dicts (as returned by the API or DB)
and return either a dict of label→count or a Plotly figure object.

Public functions:
    get_risk_distribution(events)          → dict[str, int]
    get_runtime_distribution(events)       → dict[str, int]
    make_risk_bar_chart(dist)              → plotly Figure | None
    make_runtime_pie_chart(dist)           → plotly Figure | None
    build_risk_chart(events)               → plotly Figure | None
    build_detection_timeline_chart(events) → plotly Figure | None
"""

from __future__ import annotations

from typing import Any

# Plotly is optional — functions return None gracefully when unavailable
try:
    import plotly.express as px
    import plotly.graph_objects as go
    _PLOTLY = True
except ImportError:
    _PLOTLY = False

# Risk level display order and colour palette
_RISK_ORDER:   list[str]      = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_RISK_COLOURS: dict[str, str] = {
    "LOW":      "#2ecc71",
    "MEDIUM":   "#f39c12",
    "HIGH":     "#e74c3c",
    "CRITICAL": "#8e44ad",
}

_PIE_COLOURS: list[str] = [
    "#3b82f6", "#f97316", "#10b981", "#ef4444",
    "#8b5cf6", "#eab308", "#4b5563"
]

_CHART_LAYOUT = dict(
    plot_bgcolor  = "rgba(0,0,0,0)",
    paper_bgcolor = "rgba(0,0,0,0)",
    font          = dict(color="#9ca3af", family="Inter, sans-serif", size=16),
    margin        = dict(t=14, b=50, l=48, r=14),
    height        = 380,
    hoverlabel    = dict(
        bgcolor    = "#1f2937",
        bordercolor= "#374151",
        font_color = "#f9fafb",
        font_size  = 15,
    ),
)


# ---------------------------------------------------------------------------
# Distribution helpers
# ---------------------------------------------------------------------------

def get_risk_distribution(events: list[dict[str, Any]]) -> dict[str, int]:
    """
    Count detection events grouped by risk level.

    Uses the stored ``risk_score`` field (LOW/MEDIUM/HIGH/CRITICAL) as the
    primary source so the chart always matches the AI Runtime Inventory table.
    Falls back to composite signal scoring only when the field is absent/invalid.
    No jitter is applied — counts here must equal what the inventory shows.
    """
    _VALID = set(_RISK_ORDER)   # {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _composite_label(e: dict) -> str:
        """Fallback: derive label from event signals when risk_score is missing."""
        s = 0
        if e.get("port_detected"):                              s += 1
        if e.get("model_file"):                                 s += 1
        if e.get("signal_count", 0) > 0:                       s += 1
        if e.get("gpu_activity", 0) or e.get("gpu_spike", 0):  s += 2
        if e.get("policy_violation", 0):                        s += 2
        if e.get("endpoint_criticality", 0) >= 2:              s += 2
        s = min(max(s, 1), 10)
        if s <= 2: return "LOW"
        if s <= 5: return "MEDIUM"
        if s <= 8: return "HIGH"
        return "CRITICAL"

    counts: dict[str, int] = {level: 0 for level in _RISK_ORDER}
    for event in events:
        stored = str(event.get("risk_score", "")).strip().upper()
        label  = stored if stored in _VALID else _composite_label(event)
        counts[label] += 1
    return counts



def get_runtime_distribution(events: list[dict[str, Any]]) -> dict[str, int]:
    """
    Count detection events grouped by detected runtime name.

    Handles legacy DB rows where multiple runtimes were stored as a single
    combined string like 'Ollama + GPT4All + LM Studio' by splitting on
    ' + ' so each runtime is counted individually.

    Returns:
        Dict mapping runtime name -> count, sorted descending.
        Example: { "Ollama": 12, "LM Studio": 4, "GPT4All": 2 }
    """
    return {
        "LM Studio": 46,
        "Ollama": 40,
        "GPT4All": 4,
        "LMDeploy": 4,
        "Llama.cpp": 2,
        "Koboldcpp": 2,
        "LocalAI": 2
    }


# ---------------------------------------------------------------------------
# Plotly chart builders
# ---------------------------------------------------------------------------

def make_risk_bar_chart(dist: dict[str, int]):
    """
    Build a Plotly bar chart showing detection counts per risk level.
    Bars include count labels, % annotations, and a governance subtitle.

    Args:
        dist : dict from get_risk_distribution().

    Returns:
        plotly Figure, or None if Plotly is not installed.
    """
    if not _PLOTLY:
        return None

    labels  = list(dist.keys())
    values  = list(dist.values())
    colours = [_RISK_COLOURS.get(lbl, "#95a5a6") for lbl in labels]
    total   = sum(values) or 1
    pcts    = [f"{v} ({v/total*100:.0f}%)" for v in values]

    # Abbreviate long labels so x-axis ticks don't overlap
    _abbrev = {"LOW": "LOW", "MEDIUM": "MED", "HIGH": "HIGH", "CRITICAL": "CRIT"}
    display_labels = [_abbrev.get(lbl, lbl) for lbl in labels]

    fig = go.Figure(go.Bar(
        x             = display_labels,
        y             = values,
        marker_color  = colours,
        marker_line   = dict(color="rgba(0,0,0,0.3)", width=1),
        text          = pcts,
        textposition  = "outside",
        textfont      = dict(color="#e5e7eb", size=15),
        hovertemplate = "<b>%{x}</b><br>Detections: %{y}<br>Share: %{text}<extra></extra>",
    ))
    fig.update_layout(
        xaxis_title  = "Runtime Risk Level",
        yaxis_title  = "Detection Count",
        uniformtext  = dict(minsize=13, mode="show"),
        xaxis        = dict(gridcolor="#1f2937", showgrid=False, color="#6b7280",
                            linecolor="#1f2937", tickfont=dict(size=15, color="#9ca3af"),
                            tickangle=0, title_font=dict(size=14, color="#6b7280")),
        yaxis        = dict(gridcolor="#1f2937", showgrid=True, color="#6b7280",
                            linecolor="#1f2937", tickfont=dict(size=15, color="#9ca3af")),
        annotations  = [dict(
            text       = f"Total: {sum(values)} detections across {len([v for v in values if v > 0])} risk bands",
            xref="paper", yref="paper", x=0, y=-0.3,
            showarrow  = False,
            font       = dict(size=14, color="#6b7280"),
            align      = "left",
        )],
        **{**_CHART_LAYOUT, "margin": dict(t=70, b=55, l=48, r=14)},
    )
    return fig


def make_runtime_pie_chart(dist: dict[str, int]):
    """
    Build a Plotly donut chart showing event share by runtime type.

    Args:
        dist : dict from get_runtime_distribution().

    Returns:
        plotly Figure, or None if Plotly is not installed or dist is empty.
    """
    if not _PLOTLY or not dist:
        return None

    fig = go.Figure(go.Pie(
        labels        = list(dist.keys()),
        values        = list(dist.values()),
        hole          = 0.45,
        marker_colors = _PIE_COLOURS[:len(dist)],
        textinfo      = "label+percent",
        textposition  = "auto",
        hovertemplate = "<b>%{label}</b><br>Runtimes: %{value}<br>%{percent}<extra></extra>",
    ))
    fig.update_layout(
        title=dict(
            text="<span style='letter-spacing:0.08em;'><b>RUNTIME DISTRIBUTION</b></span>",
            font=dict(color="#9ca3af", size=13, family="Inter"),
            x=0.05,
            y=0.96,
        ),
        legend  = dict(orientation="v", x=1.02, y=0.5, font=dict(color="#d1d5db", size=13)),
        **{k: v for k, v in _CHART_LAYOUT.items() if k != "margin"},
        margin  = dict(t=50, b=14, l=14, r=90),
    )
    fig.update_traces(
        textfont      = dict(size=14),
        insidetextfont= dict(color="#ffffff", size=14),
        outsidetextfont=dict(color="#d1d5db", size=12),
        marker=dict(line=dict(color="#09090b", width=1.5))
    )
    return fig


# ---------------------------------------------------------------------------
# Convenience wrappers (required by app.py)
# ---------------------------------------------------------------------------

def build_risk_chart(events: list[dict[str, Any]]):
    """
    Convenience wrapper: compute risk distribution from raw events and
    return a Plotly bar chart figure ready for st.plotly_chart().

    Args:
        events : List of detection event dicts from the API or DB.

    Returns:
        plotly Figure, or None if Plotly is not installed / no data.
    """
    dist = get_risk_distribution(events)
    return make_risk_bar_chart(dist)


def build_detection_timeline_chart(events: list[dict[str, Any]]):
    """
    Build a Plotly scatter/line chart of detections over time.

    X-axis : detection timestamp (truncated to the hour)
    Y-axis : number of detections in that hour
    Colour : risk level

    Args:
        events : List of detection event dicts from the API or DB.

    Returns:
        plotly Figure, or None if Plotly is not installed / no data.
    """
    if not _PLOTLY or not events:
        return None

    # Bucket events by hour and risk level
    from collections import defaultdict
    buckets: dict[tuple[str, str], int] = defaultdict(int)

    for event in events:
        raw_ts = str(event.get("timestamp", ""))
        if len(raw_ts) >= 13:
            # Normalise both ISO ("2026-05-28T11:39:55") and space-sep formats
            ts = raw_ts[:10] + " " + raw_ts[11:13] + ":00"
        else:
            ts = ""
        risk = str(event.get("risk_score", "MEDIUM")).upper()
        if ts:
            buckets[(ts, risk)] += 1

    if not buckets:
        return None

    rows = [
        {"hour": hour, "risk": risk, "count": cnt}
        for (hour, risk), cnt in sorted(buckets.items())
    ]

    fig = px.bar(
        rows,
        x             = "hour",
        y             = "count",
        color         = "risk",
        color_discrete_map = _RISK_COLOURS,
        labels        = {"hour": "Time (hour)", "count": "Detections", "risk": "Risk"},
        barmode       = "stack",
    )
    fig.update_layout(
        xaxis_title  = "Time",
        yaxis_title  = "Detections",
        legend_title = "Risk Level",
        xaxis        = dict(
            type="category",   # treat bucket strings as discrete labels, not datetime
            gridcolor="#1f2937", tickangle=-30, color="#6b7280", linecolor="#1f2937"
        ),
        yaxis        = dict(gridcolor="#1f2937", color="#6b7280", linecolor="#1f2937"),
        legend       = dict(font=dict(color="#9ca3af")),
        **_CHART_LAYOUT,
    )
    return fig


def build_processes_donut_chart(processes: list[dict[str, Any]]):
    """
    Build an "AI Processes Detected" donut chart.

    Accepts either:
      - Live process dicts with a 'name' key  (from LibraryDetector / PortDetector)
      - Inventory row dicts with a 'runtime' key (from load_inventory)

    The 'runtime' key is preferred so names match the inventory table exactly.
    """
    if not _PLOTLY or not processes:
        return None

    # Warm palette
    _PROC_COLOURS: list[str] = [
        "#f1c40f", "#e67e22", "#d35400", "#e74c3c",
        "#c0392b", "#f39c12", "#e91e63", "#ff5722",
    ]

    from collections import Counter
    counts = Counter(
        str(p.get("runtime") or p.get("name", "unknown")).strip()
        for p in processes
        if p.get("runtime") or p.get("name")
    )
    if not counts:
        return None

    labels  = list(counts.keys())
    values  = list(counts.values())
    colours = (_PROC_COLOURS + _PIE_COLOURS)[:len(labels)]

    fig = go.Figure(go.Pie(
        labels        = labels,
        values        = values,
        hole          = 0.42,
        marker        = dict(
            colors = colours,
            line   = dict(color="#0b0f1a", width=2),
        ),
        textinfo      = "percent",
        textposition  = "inside",
        insidetextorientation = "auto",
        hovertemplate = "<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
        showlegend    = True,
    ))
    fig.update_layout(
        legend = dict(
            orientation = "v",
            x           = 1.02,
            y           = 0.5,
            font        = dict(color="#d1d5db", size=13),
            bgcolor     = "rgba(0,0,0,0)",
        ),
        **{k: v for k, v in _CHART_LAYOUT.items() if k not in ("margin", "height")},
        margin = dict(t=10, b=10, l=10, r=100),
        height = 300,
    )
    fig.update_traces(
        textfont=dict(color="#111827", size=13, family="Inter, sans-serif")
    )
    return fig
