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
from data_loader import get_pipeline_data

st.set_page_config(
    page_title="Sentinel-X | Entity Profiler",
    page_icon="👤",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_theme()
render_header(title="Sentinel-X | Entity Profiler", subtitle="Trailing 14-Day Profiles · Exponential Decay · Cold-Start Peer Fallback")
render_pipeline_strip(active_step=1)

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

# Entity Selection Dropdown
entity_list = sorted(list(profiler.entity_profiles.keys()))
selected_eid = st.selectbox("Select Entity ID to Inspect Profile:", entity_list)

ep = profiler.entity_profiles[selected_eid]
p_info = df_scored[df_scored["entity_id"] == selected_eid].iloc[0]
etype = p_info["entity_type"]
prof_dict = profiler.get_profile(selected_eid, etype)

m_col1, m_col2, m_col3, m_col4 = st.columns(4)

with m_col1:
    st.markdown(f"""
    <div class="stat-card blue">
        <div class="stat-label">Entity Type</div>
        <div class="stat-value" style="font-size:24px;">{etype}</div>
        <div class="stat-sub">Monitored entity category</div>
    </div>
    """, unsafe_allow_html=True)

with m_col2:
    st.markdown(f"""
    <div class="stat-card green">
        <div class="stat-label">Total Sessions</div>
        <div class="stat-value">{ep['count']:,}</div>
        <div class="stat-sub">Historical access sessions</div>
    </div>
    """, unsafe_allow_html=True)

with m_col3:
    status_text = "COLD START" if prof_dict["is_cold_start"] else "PROFILED"
    card_color = "yellow" if prof_dict["is_cold_start"] else "blue"
    st.markdown(f"""
    <div class="stat-card {card_color}">
        <div class="stat-label">Baseline Status</div>
        <div class="stat-value" style="font-size:24px;">{status_text}</div>
        <div class="stat-sub">{'Peer Group Fallback' if prof_dict['is_cold_start'] else 'Full Trailing Baseline'}</div>
    </div>
    """, unsafe_allow_html=True)

with m_col4:
    st.markdown(f"""
    <div class="stat-card yellow">
        <div class="stat-label">Mean Duration</div>
        <div class="stat-value">{prof_dict['duration_mean']:.0f}s</div>
        <div class="stat-sub">Std Dev: ±{prof_dict['duration_std']:.1f}s</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Visualizations Row
pv_col1, pv_col2 = st.columns(2)

with pv_col1:
    st.subheader("⏰ Peak Login Hour Distribution")
    hours = np.linspace(0, 24, 100)
    pdf = (1.0 / (prof_dict["hour_std"] * np.sqrt(2 * np.pi))) * np.exp(-0.5 * ((hours - prof_dict["hour_mean"]) / prof_dict["hour_std"]) ** 2)
    
    fig_hour = px.line(
        x=hours, y=pdf, 
        labels={'x': 'Hour of Day (0-24)', 'y': 'Probability Density'},
        title=f"Peak Hour Gaussian Curve (Mean: {prof_dict['hour_mean']:.1f}h)"
    )
    fig_hour.update_traces(line_color="#4f7cff", line_width=3)
    fig_hour.update_layout(paper_bgcolor="#0f1219", plot_bgcolor="#0f1219", font=dict(color="#ffffff"))
    st.plotly_chart(fig_hour, use_container_width=True)

with pv_col2:
    st.subheader("📦 Resource Access Probabilities")
    df_res_prob = pd.DataFrame(list(prof_dict["resource_probs"].items()), columns=["Resource", "Probability"]).sort_values("Probability", ascending=False).head(8)
    fig_res = px.bar(
        df_res_prob, x="Probability", y="Resource", orientation="h",
        title="Top Historical Resources Accessed", color="Probability",
        color_continuous_scale="Blues"
    )
    fig_res.update_layout(paper_bgcolor="#0f1219", plot_bgcolor="#0f1219", font=dict(color="#ffffff"), showlegend=False)
    st.plotly_chart(fig_res, use_container_width=True)

st.markdown("---")

# Concept Drift Visualization
st.subheader("📈 Concept Drift Inspector (Baseline Shift Over Time)")
st.write("Demonstrates how exponential decay (α=0.05) gradually absorbs legitimate behavioral changes over time without triggering false positive alerts.")

df_ent_logs = df_scored[df_scored["entity_id"] == selected_eid].sort_values("timestamp")

if len(df_ent_logs) >= 10:
    split_idx = int(len(df_ent_logs) * 0.3)
    early_logs = df_ent_logs.iloc[:split_idx]
    late_logs = df_ent_logs.iloc[-split_idx:]

    early_hours = pd.to_datetime(early_logs["timestamp"]).dt.hour
    late_hours = pd.to_datetime(late_logs["timestamp"]).dt.hour

    fig_drift = go.Figure()
    fig_drift.add_trace(go.Histogram(x=early_hours, name="Early Baseline (First 30% Logs)", opacity=0.6, marker_color="#4f7cff"))
    fig_drift.add_trace(go.Histogram(x=late_hours, name="Late Evolved Profile (Last 30% Logs)", opacity=0.6, marker_color="#22d3a4"))

    fig_drift.update_layout(
        barmode="overlay",
        title=f"Baseline Shift / Behavioral Evolution for {selected_eid}",
        xaxis_title="Hour of Day",
        yaxis_title="Session Count",
        paper_bgcolor="#0f1219",
        plot_bgcolor="#0f1219",
        font=dict(color="#ffffff")
    )
    st.plotly_chart(fig_drift, use_container_width=True)
else:
    st.info("Insufficient longitudinal data for concept drift plot (requires ≥10 logs).")
