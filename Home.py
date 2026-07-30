import os
import sys
import pandas as pd
import numpy as np
import streamlit as st

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.append(PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, "utils"))

from theme import inject_theme, render_header, render_pipeline_strip
from data_loader import get_pipeline_data, FEATURE_COLS

st.set_page_config(
    page_title="Vajra AI | SOC Security Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject design system
inject_theme()

# Header & Pipeline Status Strip
render_header(title="Vajra AI", subtitle="Cascaded Behavioral Threat Detection & Response")
render_pipeline_strip(active_step=5)

# Load pipeline data
try:
    df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()
except Exception as e:
    st.error("⚠️ Loading is taking longer than expected. Please refresh your browser window to reload the pipeline.")
    st.stop()

# ------------------------------------------------------------------------------
# TOP-LINE SYSTEM STAT CARDS
# ------------------------------------------------------------------------------
total_events = len(df_scored)
total_entities = len(profiler.entity_profiles)
flagged_high = len(df_scored[df_scored["risk_score"] >= 65])
alert_rate = (flagged_high / total_events) * 100.0

# Calculate Top 1% Budget Recall
top_1_n = int(total_events * 0.01)
df_top_1 = df_scored.sort_values("risk_score", ascending=False).head(top_1_n)
total_attacks = len(df_scored[~df_scored["label"].isin(["normal", "insider_drift"])])
captured_attacks = len(df_top_1[~df_top_1["label"].isin(["normal", "insider_drift"])])
budget_recall = (captured_attacks / total_attacks * 100.0) if total_attacks > 0 else 100.0

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"""
    <div class="stat-card blue">
        <div class="stat-label">Total Events Monitored</div>
        <div class="stat-value">{total_events:,}</div>
        <div class="stat-sub">30-day continuous log stream</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="stat-card green">
        <div class="stat-label">Monitored Entities</div>
        <div class="stat-value">{total_entities:,}</div>
        <div class="stat-sub">Users, Service Accounts & Edge Devices</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="stat-card yellow">
        <div class="stat-label">Overall Alert Rate</div>
        <div class="stat-value">{alert_rate:.2f}%</div>
        <div class="stat-sub">{flagged_high:,} High-Risk sessions (Risk ≥ 65)</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="stat-card red">
        <div class="stat-label">Top 1% Budget Recall</div>
        <div class="stat-value">{budget_recall:.1f}%</div>
        <div class="stat-sub">Captured {captured_true_attacks if 'captured_true_attacks' in locals() else captured_attacks}/{total_attacks} attacks in top {top_1_n} logs</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# ACTIONABLE FEATURE LEADERBOARD: TOP CONTRIBUTING FEATURES THIS PERIOD
# ------------------------------------------------------------------------------
st.markdown("## 🏆 Top Contributing Anomaly Features This Period")
st.caption("Actionable Security Hardening Intelligence: Ranks which behavioral feature deviations most frequently drive HIGH & CRITICAL risk classifications across all alerts.")

# Compute driver frequency across all high risk sessions (Risk >= 65)
high_risk_indices = df_scored[df_scored["risk_score"] >= 65].index

feature_driver_counts = {col: 0 for col in FEATURE_COLS}
feature_weight_sums = {col: 0.0 for col in FEATURE_COLS}

for idx in high_risk_indices:
    feat_row = df_features.iloc[idx].to_dict()
    # Compute relative weights for this row
    drivers = explainer.get_top_drivers(feat_row, max_drivers=9)
    for drv in drivers:
        fname = drv["feature_name"]
        if fname in feature_driver_counts:
            feature_driver_counts[fname] += 1
            feature_weight_sums[fname] += drv["score"]

# Convert to DataFrame
df_leaderboard = pd.DataFrame([
    {
        "feature_name": col,
        "label": col.replace("_", " ").title(),
        "driver_count": feature_driver_counts[col],
        "weight_sum": feature_weight_sums[col]
    }
    for col in FEATURE_COLS
]).sort_values(by="driver_count", ascending=False).reset_index(drop=True)

total_driver_events = df_leaderboard["driver_count"].sum() + 1e-9
df_leaderboard["share_pct"] = (df_leaderboard["driver_count"] / total_driver_events) * 100.0

# Feature Hardening Guidance Mapping
HARDENING_GUIDANCE = {
    "geo_distance_km": "Enforce strict IP/Geofencing policies & mandate Step-Up MFA for foreign locations.",
    "auth_failure_rate_trailing": "Enforce automated rate-limiting & IP throttling across authentication endpoints.",
    "resource_novelty": "Audit IAM role permissions & restrict unaccustomed resource access vectors.",
    "session_duration_zscore": "Inspect long-lived session tokens & enforce automated token revocation timeouts.",
    "source_ip_entity_fanout": "Block multi-account scanning IPs at perimeter firewall & deploy CAPTCHA rate-limiting.",
    "command_sequence_novelty": "Audit interactive shell executions & restrict administrative command execution scopes.",
    "fingerprint_mismatch": "Mandate hardware-backed mTLS certificates & enforce device registration checks.",
    "time_of_day_zscore": "Flag off-hours administrative logins & restrict after-hours production access.",
    "is_cold_start": "Monitor newly provisioned accounts during initial 14-day baseline profiling window."
}

# Display Top Leaderboard
for i, row in df_leaderboard.iterrows():
    rank = i + 1
    fname = row["feature_name"]
    flabel = row["label"]
    count = row["driver_count"]
    pct = row["share_pct"]
    advice = HARDENING_GUIDANCE.get(fname, "Monitor feature deviation trends.")
    
    st.markdown(f"""
    <div class="leaderboard-row">
        <div class="leaderboard-rank">#{rank}</div>
        <div class="leaderboard-name">
            <strong>{flabel}</strong> <code style="color:var(--text3); font-size:11px;">({fname})</code>
            <div style="font-size:11px; color:var(--text2); margin-top:2px;">💡 <em>SOC Recommendation:</em> {advice}</div>
        </div>
        <div class="leaderboard-count">{count:,} Alerts Driven</div>
        <div class="leaderboard-pct">{pct:.1f}% Share</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br><hr><br>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# MULTIPAGE NAVIGATION GUIDE & SYSTEM OVERVIEW
# ------------------------------------------------------------------------------
st.markdown("## 🧭 Console Navigation & System Architecture")

n_col1, n_col2, n_col3 = st.columns(3)

with n_col1:
    st.markdown("""
    <div class="stat-card blue">
        <div class="stat-label">Page 1</div>
        <h3 style="margin-top:4px;">🚨 Live Threat Feed</h3>
        <p style="font-size:12px; color:var(--text2); margin-top:8px;">
            Real-time ranked threat feed sorted by Risk Score descending. Includes cold-start entity toggles, 
            CSV export, interactive SHAP attribution inspector, and human-in-the-loop analyst feedback.
        </p>
    </div>
    """, unsafe_allow_html=True)

with n_col2:
    st.markdown("""
    <div class="stat-card green">
        <div class="stat-label">Page 2</div>
        <h3 style="margin-top:4px;">👤 Entity Profiler</h3>
        <p style="font-size:12px; color:var(--text2); margin-top:8px;">
            Inspect rolling 14-day statistical profiles for all 175 entities. Visualize exponential decay 
            concept drift plots showing behavioral evolution over time.
        </p>
    </div>
    """, unsafe_allow_html=True)

with n_col3:
    st.markdown("""
    <div class="stat-card yellow">
        <div class="stat-label">Page 3</div>
        <h3 style="margin-top:4px;">📊 Threat Analytics</h3>
        <p style="font-size:12px; color:var(--text2); margin-top:8px;">
            Comprehensive model benchmark evaluations, inference latency trade-offs (<1ms vs 4.5ms), and 
            top 1% alert capacity recall metrics.
        </p>
    </div>
    """, unsafe_allow_html=True)
