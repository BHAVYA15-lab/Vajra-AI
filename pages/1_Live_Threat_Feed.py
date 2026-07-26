import os
import sys
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, "utils"))

from theme import inject_theme, render_header, render_pipeline_strip
from data_loader import get_pipeline_data, record_analyst_feedback, load_analyst_feedback

st.set_page_config(
    page_title="Vajra AI | Live Threat Feed",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_theme()
render_header(title="Vajra AI | Live Threat Feed", subtitle="Cascade Pipeline · MITRE ATT&CK Mapping · Risk vs Confidence · Analyst Feedback")
render_pipeline_strip(active_step=5)

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

# ------------------------------------------------------------------------------
# SUMMARY METRIC PANEL & DEMO NOTE
# ------------------------------------------------------------------------------
total_events = len(df_scored)
flagged_anomalies = len(df_scored[df_scored["risk_score"] >= 65])
alert_rate = (flagged_anomalies / total_events) * 100.0

normal_mask = (df_scored["label"] == "normal")
total_normals = normal_mask.sum()
false_positives = len(df_scored[normal_mask & (df_scored["risk_score"] >= 65)])
fp_rate = (false_positives / total_normals) * 100.0 if total_normals > 0 else 0.0

df_fb = load_analyst_feedback()

m_col1, m_col2, m_col3, m_col4 = st.columns(4)

with m_col1:
    st.markdown(f"""
    <div class="stat-card blue">
        <div class="stat-label">Total Events Processed</div>
        <div class="stat-value">{total_events:,}</div>
        <div class="stat-sub">30-day access log stream</div>
    </div>
    """, unsafe_allow_html=True)

with m_col2:
    st.markdown(f"""
    <div class="stat-card yellow">
        <div class="stat-label">Overall Alert Rate</div>
        <div class="stat-value">{alert_rate:.2f}%</div>
        <div class="stat-sub">{flagged_anomalies:,} High-Risk sessions (Risk ≥ 65)</div>
    </div>
    """, unsafe_allow_html=True)

with m_col3:
    st.markdown(f"""
    <div class="stat-card green">
        <div class="stat-label">Ground-Truth FPR</div>
        <div class="stat-value">{fp_rate:.3f}%</div>
        <div class="stat-sub">False alarm rate on normal traffic</div>
    </div>
    """, unsafe_allow_html=True)

with m_col4:
    st.markdown(f"""
    <div class="stat-card red">
        <div class="stat-label">Analyst Triaged Count</div>
        <div class="stat-value">{len(df_fb):,}</div>
        <div class="stat-sub">Human feedback responses recorded</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("""
<div class="demo-note-box">
    💡 <b>[DEMO ONLY NOTE]</b>: Ground-truth FPR (<b>0.025%</b>) is calculated against synthetic ground-truth labels. 
    In a real production SOC deployment, ground truth is unknown and FPR can only be estimated via human analyst feedback.
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ------------------------------------------------------------------------------
# FILTER BAR & COLD-START TOGGLE
# ------------------------------------------------------------------------------
f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([1.5, 1.5, 1.5, 1.5, 1.2])

entity_types = ["ALL"] + sorted(df_scored["entity_type"].unique().tolist())
selected_etype = f_col1.selectbox("Filter Entity Type", entity_types)

risk_levels = ["ALL", "CRITICAL (85+)", "HIGH (65-84)", "MEDIUM (45-64)", "LOW (<45)"]
selected_risk = f_col2.selectbox("Filter Risk Level", risk_levels)

attack_cats = ["ALL"] + sorted(df_scored["predicted_attack"].unique().tolist())
selected_attack = f_col3.selectbox("Filter Predicted Threat", attack_cats)

search_entity = f_col4.text_input("Search Entity / IP / MITRE ID", "")
only_cold_start = f_col5.checkbox("Cold-Start Only ❄️", value=False, help="Filter to show only brand-new entities using peer fallback")

# Apply Filtering
df_filtered = df_scored.copy()

if selected_etype != "ALL":
    df_filtered = df_filtered[df_filtered["entity_type"] == selected_etype]

if selected_risk == "CRITICAL (85+)":
    df_filtered = df_filtered[df_filtered["risk_score"] >= 85]
elif selected_risk == "HIGH (65-84)":
    df_filtered = df_filtered[(df_filtered["risk_score"] >= 65) & (df_filtered["risk_score"] < 85)]
elif selected_risk == "MEDIUM (45-64)":
    df_filtered = df_filtered[(df_filtered["risk_score"] >= 45) & (df_filtered["risk_score"] < 65)]
elif selected_risk == "LOW (<45)":
    df_filtered = df_filtered[df_filtered["risk_score"] < 45]

if selected_attack != "ALL":
    df_filtered = df_filtered[df_filtered["predicted_attack"] == selected_attack]

if search_entity:
    df_filtered = df_filtered[
        df_filtered["entity_id"].str.contains(search_entity, case=False) |
        df_filtered["source_ip"].str.contains(search_entity, case=False) |
        df_filtered["mitre_technique_id"].str.contains(search_entity, case=False)
    ]

if only_cold_start:
    df_filtered = df_filtered[df_filtered["is_cold_start"] == 1.0]

# Ranked by Risk Score Descending by Default
df_filtered = df_filtered.sort_values(by="risk_score", ascending=False).reset_index(drop=True)

# ------------------------------------------------------------------------------
# LIVE MONITORING MODE TOGGLE
# Real-time streaming simulation: progressively reveals events sorted by arrival
# time, mimicking how alerts would surface from a live Kafka/syslog queue.
# ------------------------------------------------------------------------------
st.markdown("---")
lm_left, lm_right = st.columns([3, 1])

with lm_left:
    live_mode = st.toggle(
        "🔴 LIVE Monitoring Mode — stream events as they arrive",
        value=st.session_state.get("live_mode", False),
        help="Simulates real-time event streaming by revealing sessions progressively, "
             "sorted by timestamp, at a pace of 25 events per 2-second refresh."
    )
    st.session_state["live_mode"] = live_mode

with lm_right:
    if live_mode:
        if st.button("⏹ Reset Stream", help="Restart stream from beginning"):
            st.session_state["stream_cursor"] = 0
            st.session_state["stream_paused"] = False
            st.rerun()
        paused = st.session_state.get("stream_paused", False)
        if st.button("⏸ Pause" if not paused else "▶ Resume"):
            st.session_state["stream_paused"] = not paused
            st.rerun()

if live_mode:
    # Sort ALL scored events by timestamp (arrival order), not risk score
    df_stream_base = df_scored.sort_values("timestamp", ascending=True).reset_index(drop=True)
    EVENTS_PER_TICK = 25   # events revealed per 2-second refresh
    REFRESH_SECS = 2

    if "stream_cursor" not in st.session_state:
        st.session_state["stream_cursor"] = EVENTS_PER_TICK

    cursor = st.session_state["stream_cursor"]
    total = len(df_stream_base)
    paused = st.session_state.get("stream_paused", False)

    # Apply same user filters on the streaming slice
    df_live_slice = df_stream_base.iloc[:cursor].copy()
    if selected_etype != "ALL":
        df_live_slice = df_live_slice[df_live_slice["entity_type"] == selected_etype]
    if selected_risk == "CRITICAL (85+)":
        df_live_slice = df_live_slice[df_live_slice["risk_score"] >= 85]
    elif selected_risk == "HIGH (65-84)":
        df_live_slice = df_live_slice[(df_live_slice["risk_score"] >= 65) & (df_live_slice["risk_score"] < 85)]
    elif selected_risk == "MEDIUM (45-64)":
        df_live_slice = df_live_slice[(df_live_slice["risk_score"] >= 45) & (df_live_slice["risk_score"] < 65)]
    elif selected_risk == "LOW (<45)":
        df_live_slice = df_live_slice[df_live_slice["risk_score"] < 45]
    if selected_attack != "ALL":
        df_live_slice = df_live_slice[df_live_slice["predicted_attack"] == selected_attack]
    if search_entity:
        df_live_slice = df_live_slice[
            df_live_slice["entity_id"].str.contains(search_entity, case=False) |
            df_live_slice["source_ip"].str.contains(search_entity, case=False) |
            df_live_slice["mitre_technique_id"].str.contains(search_entity, case=False)
        ]
    if only_cold_start:
        df_live_slice = df_live_slice[df_live_slice["is_cold_start"] == 1.0]

    # Ranked by risk score within the streamed window
    df_live_ranked = df_live_slice.sort_values("risk_score", ascending=False)

    pct_complete = min(cursor / total * 100, 100.0)
    progress_label = (
        f"🔴 LIVE &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Streamed: **{cursor:,}** / **{total:,}** events &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Alerts visible: **{len(df_live_ranked):,}** &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Progress: **{pct_complete:.1f}%** &nbsp;&nbsp;"
        + ("&nbsp;&nbsp;⏸ PAUSED" if paused else "")
    )
    st.markdown(f"""<div style='background: linear-gradient(90deg,#1a0a0a,#2a1010); border:1px solid #ff4444;
        border-radius:8px; padding:10px 16px; margin:8px 0; font-size:0.9rem;'>{progress_label}</div>""",
        unsafe_allow_html=True)
    st.progress(pct_complete / 100.0)

    # Show the streaming alert table (arrival-time sorted, then risk-ranked within window)
    st.subheader(f"📡 Live Event Stream — {cursor:,} events ingested, {len(df_live_ranked):,} alerts surfaced")
    disp_cols_live = [
        "log_id", "timestamp", "entity_id", "entity_type",
        "risk_score", "confidence_score", "severity_label",
        "predicted_attack", "mitre_technique_id", "explanation_summary",
        "is_cold_start"
    ]
    st.dataframe(df_live_ranked[disp_cols_live].head(100), height=300)

    # Advance cursor on next rerun (auto-refresh while not paused and not done)
    if not paused and cursor < total:
        st.session_state["stream_cursor"] = min(cursor + EVENTS_PER_TICK, total)
        import time
        time.sleep(REFRESH_SECS)
        st.rerun()
    elif cursor >= total and not paused:
        st.success(f"✅ Stream complete — all {total:,} events processed. Toggle off LIVE mode to return to full static view.")

    st.markdown("---")
    # In live mode, skip the static table below — the stream IS the table
    df_filtered = df_live_ranked   # keep df_filtered consistent for triage inspector
else:
    st.session_state["stream_cursor"] = 0   # reset cursor when live mode is off

# Header & Download Button Row (static mode only shown when not in live mode)
if not st.session_state.get("live_mode", False):
    head_c1, head_c2 = st.columns([3, 1])
    with head_c1:
        st.subheader(f"📋 Live Threat Stream ({len(df_filtered):,} matching sessions)")
    with head_c2:
        csv_data = df_filtered.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Alerts (CSV)",
            data=csv_data,
            file_name="flagged_threat_alerts.csv",
            mime="text/csv",
            help="Export current filtered threat view for shift handoff or incident reports."
        )

    disp_cols = [
        "log_id", "timestamp", "entity_id", "entity_type",
        "risk_score", "confidence_score", "severity_label",
        "predicted_attack", "mitre_technique_id", "explanation_summary",
        "geo_location", "resource_accessed", "is_cold_start"
    ]
    st.dataframe(
        df_filtered[disp_cols].head(100),
        use_container_width=True,
        height=320
    )

st.markdown("---")


# ------------------------------------------------------------------------------
# INTERACTIVE SOC ANALYST TRIAGE CARD INSPECTOR
# ------------------------------------------------------------------------------
st.subheader("🕵️ Interactive SOC Analyst Triage Inspector")

if len(df_filtered) > 0:
    selected_log_id = st.selectbox(
        "Select Log ID to Inspect & Triage:",
        df_filtered["log_id"].head(50).tolist()
    )
    
    target_row = df_filtered[df_filtered["log_id"] == selected_log_id].iloc[0]
    orig_idx = df_scored[df_scored["log_id"] == selected_log_id].index[0]
    feat_dict = df_features.iloc[orig_idx].to_dict()

    report_data = explainer.explain_log(
        target_row, feat_dict, target_row["raw_anom_score"], target_row["predicted_attack"]
    )

    t_col1, t_col2 = st.columns([1.2, 1.8])

    with t_col1:
        st.markdown(f"### Log #{target_row['log_id']} Technical Details")
        st.markdown(f"**Entity ID:** `{target_row['entity_id']}` ({target_row['entity_type']})")
        st.markdown(f"**Timestamp:** `{target_row['timestamp']}`")
        st.markdown(f"**Source IP / Geo:** `{target_row['source_ip']}` ({target_row['geo_location']})")
        st.markdown(f"**Resource Accessed:** `{target_row['resource_accessed']}`")
        st.markdown(f"**Auth Method:** `{target_row['auth_method']}` (Duration: {target_row['session_duration']}s)")

        if target_row.get("is_physics_impossible_travel", 0) > 0:
            st.error(f"⚡ **PHYSICS RULE TRIGGERED**: Implied velocity **{target_row['implied_velocity_kmh']:.0f} km/h** exceeds flight threshold (900 km/h)!")

        # Side-by-Side Risk vs Model Confidence Metrics
        rc_c1, rc_c2 = st.columns(2)
        with rc_c1:
            st.metric(
                label="Risk Score (Severity/Impact)",
                value=f"{report_data['risk_score']} / 100",
                delta=f"{report_data['severity_label']}",
                help="How severe if real (Impact-weighted)"
            )
        with rc_c2:
            st.metric(
                label="Model Confidence (Probability)",
                value=f"{report_data['confidence_score']:.1f}%",
                delta="predict_proba max",
                help="How sure the model is of the predicted category"
            )

        # Risk Score Gauge Chart
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=report_data["risk_score"],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "SOC Risk Score (0-100)"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#4f7cff"},
                'steps': [
                    {'range': [0, 45], 'color': "#22d3a4"},
                    {'range': [45, 65], 'color': "#f5a623"},
                    {'range': [65, 85], 'color': "#d19a66"},
                    {'range': [85, 100], 'color': "#ff4757"}
                ]
            }
        ))
        fig_gauge.update_layout(height=190, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="#0f1219", font=dict(color="#ffffff"))
        st.plotly_chart(fig_gauge, use_container_width=True)

    with t_col2:
        # MITRE ATT&CK Badge & Threat Name
        mitre_info = report_data["mitre_info"]
        st.markdown(f"""
        <div style="background:var(--bg3); border:1px solid var(--border2); padding:12px 16px; border-radius:8px; margin-bottom:12px;">
            <div style="font-size:11px; color:var(--text3); font-weight:700; letter-spacing:1px; text-transform:uppercase;">
                🛡️ MITRE ATT&CK FRAMEWORK MAPPING
            </div>
            <div style="font-size:16px; font-weight:800; color:var(--accent); font-family:var(--mono); margin-top:2px;">
                {mitre_info['technique_id']} — {mitre_info['technique_name']}
            </div>
            <div style="font-size:12px; color:var(--text2); margin-top:4px;">
                <strong>Tactic:</strong> {mitre_info['tactic_name']} ({mitre_info['tactic_id']}) | <em>{mitre_info['description']}</em>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### 📊 SHAP Feature Attribution (Why Flagged)")
        top_drivers = report_data["top_drivers"]
        max_score = max([d["score"] for d in top_drivers]) if top_drivers else 1.0
        
        shap_html = '<div class="shap-bars">'
        for drv in top_drivers:
            w_pct = int((drv["score"] / (max_score + 1e-9)) * 100)
            dname = drv.get("name", drv.get("feature", "").replace("_", " ").title())
            shap_html += f"""
            <div class="shap-row">
                <div class="shap-name">{dname}</div>
                <div class="shap-bar-container">
                    <div class="shap-bar positive" style="width:{w_pct}%;">↑ {drv['score']:.2f}</div>
                </div>
                <div class="shap-pct">{w_pct}%</div>
            </div>
            """
        shap_html += '</div>'
        st.markdown(shap_html, unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)

        # AI Explanation & Actionable Remediation Checklist
        st.markdown(f"""
        <div class="ai-explanation-card">
            <div class="ai-explanation-header">
                <div class="ai-badge">AI GENERATED</div>
                <div style="font-size:11px; color:var(--text3);">Natural Language Threat Analysis</div>
            </div>
            <div class="ai-explanation-text">
                Log event <strong>#{target_row['log_id']}</strong> on <code>{target_row['entity_id']}</code> is classified as 
                <span class="risk-badge {target_row['severity_label']}">{target_row['severity_label']} RISK</span> 
                (Confidence: <strong>{target_row['confidence_score']:.1f}%</strong>) with threat category 
                <strong>{report_data['predicted_attack'].upper()}</strong>. 
                Primary anomaly drivers include {top_drivers[0]['summary'] if len(top_drivers)>0 else 'baseline deviations'}.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("#### ⚡ Actionable SOC Remediation Checklist:")
        for action in mitre_info["recommended_actions"]:
            st.write(f"- {action}")

        # Human-in-the-Loop Action Buttons
        st.markdown("### 🤝 Human-in-the-Loop Analyst Response")
        b_col1, b_col2 = st.columns(2)
        
        if b_col1.button("✅ Confirm Threat", key=f"confirm_{selected_log_id}"):
            record_analyst_feedback(selected_log_id, target_row['entity_id'], report_data['predicted_attack'], report_data['risk_score'], "CONFIRMED")
            st.success(f"Log #{selected_log_id} recorded as CONFIRMED THREAT.")
            st.rerun()

        if b_col2.button("❌ Dismiss as False Positive", key=f"dismiss_{selected_log_id}"):
            record_analyst_feedback(selected_log_id, target_row['entity_id'], report_data['predicted_attack'], report_data['risk_score'], "DISMISSED")
            st.warning(f"Log #{selected_log_id} recorded as DISMISSED FALSE POSITIVE.")
            st.rerun()

    st.markdown("---")

    # --------------------------------------------------------------------------
    # THREAT TIMELINE VIEW: PRECEDING EVENT SEQUENCE (LAST 15 SESSIONS)
    # --------------------------------------------------------------------------
    selected_eid = target_row['entity_id']
    st.subheader(f"⏱️ Chronological Threat Build-Up Timeline for Entity: `{selected_eid}` (Last 15 Sessions)")
    st.caption("Reconstructs the chronological sequence of events leading up to the flagged alert so analysts can see the build-up.")

    df_history = df_scored[df_scored["entity_id"] == selected_eid].sort_values("timestamp", ascending=False).head(15)
    
    # Chronological timeline table with explicit flag status & confidence
    df_history_disp = df_history.copy()
    df_history_disp["flag_status"] = df_history_disp["risk_score"].apply(lambda r: "🔴 FLAGGED ANOMALY" if r >= 65 else ("🟡 SUSPICIOUS" if r >= 45 else "🟢 NORMAL SESSION"))
    
    hist_cols = [
        "log_id", "timestamp", "flag_status", "risk_score", "confidence_score",
        "predicted_attack", "mitre_technique_id", "resource_accessed", 
        "geo_location", "session_duration", "auth_method"
    ]
    st.dataframe(df_history_disp[hist_cols], use_container_width=True, height=260)
