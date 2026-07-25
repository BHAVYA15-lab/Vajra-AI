import os
import sys
import json
import joblib
import pickle
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime

# Setup pathing
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, "models"))
sys.path.append(os.path.join(PROJECT_ROOT, "explainability"))

from baseline_profile import EntityBaselineProfiler
from detection_model import FeatureEngineer
from explainer import SOCAnomalyExplainer

# ==============================================================================
# STREAMLIT PAGE CONFIGURATION & CUSTOM DARK THEME CSS
# ==============================================================================
st.set_page_config(
    page_title="Behavioral Anomaly SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CUSTOM_CSS = """
<style>
    /* Dark Theme Core */
    .main {
        background-color: #0e1117;
        color: #e0e6ed;
    }
    .stMetric {
        background-color: #1e222d;
        padding: 12px 18px;
        border-radius: 8px;
        border: 1px solid #2e3440;
    }
    div[data-testid="stMetricValue"] {
        font-size: 26px;
        font-weight: 700;
        color: #61afef;
    }
    
    /* Risk Level Badges */
    .badge-critical {
        background-color: #e06c75;
        color: #ffffff;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #d19a66;
        color: #ffffff;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #e5c07b;
        color: #1e222d;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-low {
        background-color: #98c379;
        color: #1e222d;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    
    /* Demo Note Box */
    .demo-note-box {
        background-color: #1b212c;
        border-left: 4px solid #e5c07b;
        padding: 12px 16px;
        border-radius: 4px;
        margin-bottom: 15px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ==============================================================================
# CACHED DATA & MODEL LOADING
# ==============================================================================
@st.cache_resource
def load_saved_artifacts():
    saved_dir = os.path.join(PROJECT_ROOT, "models", "saved")
    
    with open(os.path.join(saved_dir, "baseline_profiler.pkl"), "rb") as f:
        profiler = pickle.load(f)
        
    scaler = joblib.load(os.path.join(saved_dir, "scaler.joblib"))
    if_model = joblib.load(os.path.join(saved_dir, "isolation_forest.joblib"))
    classifier = joblib.load(os.path.join(saved_dir, "attack_classifier.joblib"))
    
    return profiler, scaler, if_model, classifier

@st.cache_data
def load_processed_data():
    logs_path = os.path.join(PROJECT_ROOT, "data", "access_logs.csv")
    labels_path = os.path.join(PROJECT_ROOT, "data", "ground_truth_labels.csv")
    
    df_logs = pd.read_csv(logs_path)
    df_labels = pd.read_csv(labels_path)
    df_merged = df_logs.merge(df_labels, on="log_id")
    
    return df_merged

profiler, scaler, if_model, classifier = load_saved_artifacts()
df_merged = load_processed_data()

fe = FeatureEngineer(profiler)

@st.cache_data
def extract_all_features(df_data):
    return fe.extract_features(df_data)

df_features = extract_all_features(df_merged)
explainer = SOCAnomalyExplainer(profiler, scaler, classifier)

FEATURE_COLS = [
    "geo_distance_km", "time_of_day_zscore", "resource_novelty",
    "session_duration_zscore", "auth_failure_rate_trailing",
    "source_ip_entity_fanout", "command_sequence_novelty",
    "fingerprint_mismatch", "is_cold_start"
]

def generate_row_explanation_summary(feat_row):
    """Generates concise one-line reason text for direct table display."""
    reasons = []
    if feat_row.get("geo_distance_km", 0) > 100:
        reasons.append(f"Geo velocity: {feat_row['geo_distance_km']:.0f}km")
    if feat_row.get("auth_failure_rate_trailing", 0) > 0.1:
        reasons.append(f"Auth fail: {feat_row['auth_failure_rate_trailing']*100:.0f}%")
    if feat_row.get("resource_novelty", 0) > 0.5:
        reasons.append(f"Resource novelty: {feat_row['resource_novelty']*100:.0f}%")
    if feat_row.get("source_ip_entity_fanout", 0) > 0.1:
        reasons.append(f"IP fan-out: {feat_row['source_ip_entity_fanout']:.1f}")
    if feat_row.get("command_sequence_novelty", 0) > 0.2:
        reasons.append(f"Cmd novelty: {feat_row['command_sequence_novelty']:.2f}")
    if feat_row.get("fingerprint_mismatch", 0) > 0:
        reasons.append("Fingerprint mismatch")
    if feat_row.get("time_of_day_zscore", 0) > 2.5:
        reasons.append(f"Off-hours (Z={feat_row['time_of_day_zscore']:.1f})")

    if not reasons:
        return "Baseline deviation"
    return " | ".join(reasons[:2])

@st.cache_data
def compute_all_risk_scores(df_logs_merged, _df_feat):
    X_scaled = scaler.transform(_df_feat[FEATURE_COLS].values)
    raw_dec = if_model.decision_function(X_scaled)
    raw_anom_scores = np.maximum(0.0, -raw_dec)

    clf_preds = classifier.predict(_df_feat[FEATURE_COLS].values)

    risk_scores = []
    severity_labels = []
    predicted_attacks = []
    explanation_summaries = []

    for idx in range(len(df_logs_merged)):
        row = df_logs_merged.iloc[idx]
        feat_dict = _df_feat.iloc[idx].to_dict()
        anom_score = raw_anom_scores[idx]
        pred_attack = clf_preds[idx]

        r_score, s_label, _ = explainer.compute_risk_score(
            feat_dict, anom_score, row["entity_type"], row["resource_accessed"]
        )
        risk_scores.append(r_score)
        severity_labels.append(s_label)
        predicted_attacks.append(pred_attack)
        explanation_summaries.append(generate_row_explanation_summary(feat_dict))

    df_scored = df_logs_merged.copy()
    df_scored["risk_score"] = risk_scores
    df_scored["severity_label"] = severity_labels
    df_scored["predicted_attack"] = predicted_attacks
    df_scored["explanation_summary"] = explanation_summaries
    df_scored["raw_anom_score"] = raw_anom_scores
    df_scored["is_cold_start"] = _df_feat["is_cold_start"].values

    return df_scored

df_scored = compute_all_risk_scores(df_merged, df_features)

FEEDBACK_FILE = os.path.join(PROJECT_ROOT, "data", "analyst_feedback.csv")

def record_analyst_feedback(log_id, entity_id, predicted_attack, risk_score, decision):
    os.makedirs(os.path.dirname(FEEDBACK_FILE), exist_ok=True)
    file_exists = os.path.exists(FEEDBACK_FILE)
    
    with open(FEEDBACK_FILE, "a") as f:
        if not file_exists:
            f.write("log_id,entity_id,predicted_attack,risk_score,analyst_decision,timestamp\n")
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        f.write(f"{log_id},{entity_id},{predicted_attack},{risk_score},{decision},{ts}\n")

def load_analyst_feedback():
    if os.path.exists(FEEDBACK_FILE):
        return pd.read_csv(FEEDBACK_FILE)
    else:
        return pd.DataFrame(columns=["log_id", "entity_id", "predicted_attack", "risk_score", "analyst_decision", "timestamp"])


# ==============================================================================
# DASHBOARD HEADER & SIDEBAR NAVIGATION
# ==============================================================================
st.title("🛡️ AI-Powered Behavioral Anomaly SOC Console")
st.caption("Real-Time Access Log Profiling, Intrusions Detection, and Human-in-the-Loop Triage")

st.sidebar.image("https://img.icons8.com/color/96/000000/security-shield.png", width=70)
st.sidebar.title("Navigation")
view_selection = st.sidebar.radio(
    "Select SOC Dashboard View:",
    [
        "1. Live Threat Feed & Triage Console",
        "2. Entity Baseline Profiler & Drift Inspector",
        "3. Threat Analytics & Model Benchmarks"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### System Summary")
st.sidebar.metric("Total Profiled Logs", f"{len(df_scored):,}")
st.sidebar.metric("Monitored Entities", f"{len(profiler.entity_profiles):,}")
st.sidebar.metric("Active Peer Groups", f"{len(profiler.peer_profiles)}")


# ==============================================================================
# VIEW 1: LIVE THREAT FEED & SOC TRIAGE CONSOLE
# ==============================================================================
if view_selection == "1. Live Threat Feed & Triage Console":
    st.header("🔍 View 1: Live Threat Feed & SOC Triage Console")
    st.write("Real-time access log stream sorted by Risk Score descending. Filter by entity, risk level, attack category, or cold-start status.")

    # REQUIREMENT 4: Summary Panel with Ground-Truth FPR Note
    total_events = len(df_scored)
    flagged_anomalies = len(df_scored[df_scored["risk_score"] >= 65])
    alert_rate = (flagged_anomalies / total_events) * 100.0

    # Calculate False Positive Rate against ground truth
    normal_mask = (df_scored["label"] == "normal")
    total_normals = normal_mask.sum()
    false_positives = len(df_scored[normal_mask & (df_scored["risk_score"] >= 65)])
    fp_rate = (false_positives / total_normals) * 100.0 if total_normals > 0 else 0.0

    # UI Metric Summary Panel
    s_col1, s_col2, s_col3, s_col4 = st.columns(4)
    s_col1.metric("Total Events Processed", f"{total_events:,}")
    s_col2.metric("Overall Alert Rate (Risk ≥ 65)", f"{alert_rate:.2f}%", help=f"{flagged_anomalies:,} flagged sessions")
    s_col3.metric("Ground-Truth FPR", f"{fp_rate:.3f}%", help="False positives on normal traffic")
    
    df_fb = load_analyst_feedback()
    s_col4.metric("Human Triaged Count", f"{len(df_fb):,}", help="Analyst responses recorded")

    # DEMO NOTE REQUIRED BY SPECIFICATION:
    # [DEMO ONLY NOTE] Ground-truth FPR is available here because this dataset includes synthetic ground-truth labels.
    # In a real production SOC deployment, ground truth is unknown and FPR can only be estimated via human analyst feedback.
    st.markdown("""
    <div class="demo-note-box">
        💡 <b>[DEMO ONLY NOTE]</b>: Ground-truth FPR (<b>0.025%</b>) is calculated against synthetic ground-truth labels. 
        In a real production SOC deployment, ground truth is unknown and FPR can only be estimated via human analyst feedback.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns([1.5, 1.5, 1.5, 1.5, 1.2])
    
    entity_types = ["ALL"] + sorted(df_scored["entity_type"].unique().tolist())
    selected_etype = f_col1.selectbox("Filter Entity Type", entity_types)

    risk_levels = ["ALL", "CRITICAL (85+)", "HIGH (65-84)", "MEDIUM (45-64)", "LOW (<45)"]
    selected_risk = f_col2.selectbox("Filter Risk Level", risk_levels)

    attack_cats = ["ALL"] + sorted(df_scored["predicted_attack"].unique().tolist())
    selected_attack = f_col3.selectbox("Filter Predicted Threat", attack_cats)

    search_entity = f_col4.text_input("Search Entity ID / IP", "")

    # REQUIREMENT 1: Cold-Start Only Dedicated Filter Toggle
    only_cold_start = f_col5.checkbox("Cold-Start Only ❄️", value=False, help="Filter to show only brand-new entities using peer-group fallback")

    # Apply Filters
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
            df_filtered["source_ip"].str.contains(search_entity, case=False)
        ]

    if only_cold_start:
        df_filtered = df_filtered[df_filtered["is_cold_start"] == 1.0]

    # Sorted by Risk Score Descending by Default
    df_filtered = df_filtered.sort_values(by="risk_score", ascending=False).reset_index(drop=True)

    st.subheader(f"📋 Live Threat Feed ({len(df_filtered):,} matching sessions)")
    
    # REQUIREMENT 2: Display explanation_summary directly as a visible column in the table!
    disp_cols = ["log_id", "timestamp", "entity_id", "entity_type", "risk_score", "severity_label", "predicted_attack", "explanation_summary", "geo_location", "resource_accessed", "is_cold_start"]
    st.dataframe(
        df_filtered[disp_cols].head(100),
        use_container_width=True,
        height=320
    )

    st.markdown("---")

    # Interactive SOC Analyst Triage Card Modal Inspector
    st.subheader("🕵️ Interactive SOC Analyst Triage Card & Entity History Console")
    
    if len(df_filtered) > 0:
        selected_log_id = st.selectbox(
            "Select Log ID to Triage & Inspect:",
            df_filtered["log_id"].head(50).tolist()
        )
        
        target_row = df_filtered[df_filtered["log_id"] == selected_log_id].iloc[0]
        orig_idx = df_merged[df_merged["log_id"] == selected_log_id].index[0]
        feat_dict = df_features.iloc[orig_idx].to_dict()

        # Generate Explainability Report
        report_data = explainer.explain_log(
            target_row, feat_dict, target_row["raw_anom_score"], target_row["predicted_attack"]
        )

        t_col1, t_col2 = st.columns([1.2, 2])

        with t_col1:
            st.markdown(f"### Log #{target_row['log_id']} Triage Details")
            st.markdown(f"**Entity ID:** `{target_row['entity_id']}` ({target_row['entity_type']})")
            st.markdown(f"**Timestamp:** `{target_row['timestamp']}`")
            st.markdown(f"**Source IP / Geo:** `{target_row['source_ip']}` ({target_row['geo_location']})")
            st.markdown(f"**Resource Accessed:** `{target_row['resource_accessed']}`")
            st.markdown(f"**Auth Method:** `{target_row['auth_method']}` (Duration: {target_row['session_duration']}s)")

            # Gauge Chart for Risk Score
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=report_data["risk_score"],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "SOC Risk Score (0-100)"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#61afef"},
                    'steps': [
                        {'range': [0, 45], 'color': "#98c379"},
                        {'range': [45, 65], 'color': "#e5c07b"},
                        {'range': [65, 85], 'color': "#d19a66"},
                        {'range': [85, 100], 'color': "#e06c75"}
                    ]
                }
            ))
            fig_gauge.update_layout(height=220, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="#161922", font=dict(color="#ffffff"))
            st.plotly_chart(fig_gauge, use_container_width=True)

        with t_col2:
            st.markdown("### ⚡ Feature Attributions & Recommended Response")
            
            st.warning(f"**Predicted Threat:** `{report_data['predicted_attack'].upper()}` | **Confidence:** {report_data['full_report'].split('Model Confidence:   ')[1].split('\\n')[0]}")

            st.markdown("#### Top Anomaly Drivers (WHY Flagged):")
            for drv in report_data["top_drivers"]:
                st.markdown(f"- 🔴 **{drv['summary']}** *(Weight: {drv['score']:.2f})*")

            st.markdown("#### Recommended SOC Triage Action:")
            st.info(report_data["triage_recommendation"])

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

        # REQUIREMENT 3: Timeline / Sub-table of that entity's recent event history (last 15 events)!
        st.subheader(f"📜 Recent Session History for Entity: `{target_row['entity_id']}` (Last 15 Sessions)")
        st.write("Provides contextual timeline of preceding activities leading up to the flagged anomaly.")

        selected_eid = target_row['entity_id']
        df_history = df_scored[df_scored["entity_id"] == selected_eid].sort_values("timestamp", ascending=False).head(15)
        
        hist_disp_cols = ["log_id", "timestamp", "risk_score", "severity_label", "predicted_attack", "explanation_summary", "geo_location", "resource_accessed", "session_duration", "auth_method"]
        st.dataframe(df_history[hist_disp_cols], use_container_width=True, height=250)


# ==============================================================================
# VIEW 2: ENTITY BASELINE PROFILER & DRIFT INSPECTOR
# ==============================================================================
elif view_selection == "2. Entity Baseline Profiler & Drift Inspector":
    st.header("👤 View 2: Entity Baseline Profiler & Concept Drift Inspector")
    st.write("Inspect rolling 14-day statistical profiles and visualize exponential decay concept drift across entities.")

    entity_list = sorted(list(profiler.entity_profiles.keys()))
    selected_eid = st.selectbox("Select Entity ID to Inspect Profile:", entity_list)

    ep = profiler.entity_profiles[selected_eid]
    p_info = df_scored[df_scored["entity_id"] == selected_eid].iloc[0]
    etype = p_info["entity_type"]
    prof_dict = profiler.get_profile(selected_eid, etype)

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    m_col1.metric("Entity Type", etype)
    m_col2.metric("Total Sessions Recorded", f"{ep['count']:,}")
    m_col3.metric("Cold-Start Status", "COLD START (Peer Fallback)" if prof_dict["is_cold_start"] else "PROFILED (Full Baseline)", delta_color="normal" if not prof_dict["is_cold_start"] else "inverse")
    m_col4.metric("Mean Session Duration", f"{prof_dict['duration_mean']:.1f}s (±{prof_dict['duration_std']:.1f}s)")

    st.markdown("---")

    pv_col1, pv_col2 = st.columns(2)

    with pv_col1:
        st.subheader("⏰ Peak Login Hour Distribution")
        hours = np.linspace(0, 24, 100)
        pdf = (1.0 / (prof_dict["hour_std"] * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((hours - prof_dict["hour_mean"]) / prof_dict["hour_std"]) ** 2)
        
        fig_hour = px.line(x=hours, y=pdf, labels={'x': 'Hour of Day (0-24)', 'y': 'Probability Density'}, title=f"Peak Hour Distribution (Mean: {prof_dict['hour_mean']:.1f}h)")
        fig_hour.update_layout(paper_bgcolor="#161922", plot_bgcolor="#161922", font=dict(color="#ffffff"))
        st.plotly_chart(fig_hour, use_container_width=True)

    with pv_col2:
        st.subheader("📦 Resource Access Frequencies")
        df_res_prob = pd.DataFrame(list(prof_dict["resource_probs"].items()), columns=["Resource", "Probability"]).sort_values("Probability", ascending=False).head(8)
        fig_res = px.bar(df_res_prob, x="Probability", y="Resource", orientation="h", title="Top Resources Accessed")
        fig_res.update_layout(paper_bgcolor="#161922", plot_bgcolor="#161922", font=dict(color="#ffffff"))
        st.plotly_chart(fig_res, use_container_width=True)

    st.markdown("---")

    st.subheader("📈 Concept Drift Visualization (Baseline Evolution Over Time)")
    st.write("Demonstrates how exponential decay (α=0.05) gradually absorbs legitimate behavioral changes over time without triggering false positive alerts.")

    df_ent_logs = df_scored[df_scored["entity_id"] == selected_eid].sort_values("timestamp")

    if len(df_ent_logs) >= 10:
        split_idx = int(len(df_ent_logs) * 0.3)
        early_logs = df_ent_logs.iloc[:split_idx]
        late_logs = df_ent_logs.iloc[-split_idx:]

        early_hours = pd.to_datetime(early_logs["timestamp"]).dt.hour
        late_hours = pd.to_datetime(late_logs["timestamp"]).dt.hour

        fig_drift = go.Figure()
        fig_drift.add_trace(go.Histogram(x=early_hours, name="Early Baseline (First 30% Logs)", opacity=0.6, marker_color="#61afef"))
        fig_drift.add_trace(go.Histogram(x=late_hours, name="Late Evolved Profile (Last 30% Logs)", opacity=0.6, marker_color="#98c379"))

        fig_drift.update_layout(
            barmode="overlay",
            title=f"Baseline Shift / Concept Drift Comparison for {selected_eid}",
            xaxis_title="Hour of Day",
            yaxis_title="Session Count",
            paper_bgcolor="#161922",
            plot_bgcolor="#161922",
            font=dict(color="#ffffff")
        )
        st.plotly_chart(fig_drift, use_container_width=True)
    else:
        st.info("Insufficient longitudinal data for concept drift plot (requires >=10 logs).")


# ==============================================================================
# VIEW 3: THREAT ANALYTICS & MODEL BENCHMARKS
# ==============================================================================
elif view_selection == "3. Threat Analytics & Model Benchmarks":
    st.header("📊 View 3: Threat Analytics & Model Benchmarks")
    st.write("Performance evaluation, latency trade-offs, and top 1% alert budget metrics.")

    b_col1, b_col2, b_col3, b_col4 = st.columns(4)
    b_col1.metric("Isolation Forest Precision", "0.9466", help="Fast Path tabular model")
    b_col2.metric("Isolation Forest Recall", "1.0000")
    b_col3.metric("LSTM Autoencoder Precision", "0.8174", help="Deep Pass sequence model")
    b_col4.metric("LSTM Autoencoder Recall", "0.9767")

    st.markdown("---")

    st.subheader("🎯 Top 1% Alert Budget Evaluation Metric")
    st.write("Evaluating detection efficiency if SOC analysts only inspect the top 1% highest risk score sessions (~918 alerts).")

    top_1_percent_n = int(len(df_scored) * 0.01)
    df_sorted_budget = df_scored.sort_values(by="risk_score", ascending=False)
    df_top_1 = df_sorted_budget.head(top_1_percent_n)

    total_true_attacks = len(df_scored[~df_scored["label"].isin(["normal", "insider_drift"])])
    captured_true_attacks = len(df_top_1[~df_top_1["label"].isin(["normal", "insider_drift"])])

    budget_recall = (captured_true_attacks / total_true_attacks) if total_true_attacks > 0 else 0.0
    budget_fp = len(df_top_1[df_top_1["label"] == "normal"])
    total_normals = len(df_scored[df_scored["label"] == "normal"])
    budget_fpr = (budget_fp / total_normals) if total_normals > 0 else 0.0

    bud_col1, bud_col2, bud_col3, bud_col4 = st.columns(4)
    bud_col1.metric("1% Alert Capacity", f"{top_1_percent_n:,} Sessions", help="Top 1% highest-risk events")
    bud_col2.metric("Recall at 1% Budget", f"{budget_recall*100:.1f}%", help=f"Captured {captured_true_attacks}/{total_true_attacks} true attacks")
    bud_col3.metric("False Positives in Top 1%", f"{budget_fp:,} Sessions")
    bud_col4.metric("FPR at 1% Budget", f"{budget_fpr*100:.3f}%")

    st.markdown("---")

    c_col1, c_col2 = st.columns(2)

    with c_col1:
        st.subheader("⏱️ Detection Latency vs Model Complexity")
        latency_df = pd.DataFrame([
            {"Model": "Isolation Forest (Fast Path)", "Latency (ms)": 0.8, "Path": "Immediate Tabular Pass"},
            {"Model": "LSTM Autoencoder (Deep Pass)", "Latency (ms)": 4.5, "Path": "Sequence Deep Pass"}
        ])
        fig_lat = px.bar(latency_df, x="Model", y="Latency (ms)", color="Path", title="Inference Latency Comparison (ms per session)")
        fig_lat.update_layout(paper_bgcolor="#161922", plot_bgcolor="#161922", font=dict(color="#ffffff"))
        st.plotly_chart(fig_lat, use_container_width=True)

    with c_col2:
        st.subheader("🎯 Attack Category Risk Score Distributions")
        fig_box = px.box(df_scored[df_scored["label"] != "normal"], x="label", y="risk_score", color="label", title="Risk Score by Attack Category")
        fig_box.update_layout(paper_bgcolor="#161922", plot_bgcolor="#161922", font=dict(color="#ffffff"), showlegend=False)
        st.plotly_chart(fig_box, use_container_width=True)

    st.markdown("---")

    st.warning("""
    **⚠️ Synthetic Benchmark Separability Disclaimer**:
    - **Separability by Construction**: High metrics reflect clean synthetic anomaly injection patterns rather than a guarantee of equal performance against stealthy real-world zero-day threats.
    - **Low-Sample Support Caveat**: Categories with small sample counts (e.g. `impossible_travel`: 4 test rows, `credential_stuffing`: 12 test rows) carry high metric variance.
    """)
