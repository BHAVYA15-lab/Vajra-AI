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
    page_title="Sentinel-X | Threat Analytics",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

inject_theme()
render_header(title="Sentinel-X | Threat Analytics", subtitle="Cascade Stage 1 vs Stage 2 Benchmarks · Latency Trade-Offs · Alert Budget Metrics")
render_pipeline_strip(active_step=2)

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

b_col1, b_col2, b_col3, b_col4 = st.columns(4)

with b_col1:
    st.markdown("""
    <div class="stat-card blue">
        <div class="stat-label">Isolation Forest Precision</div>
        <div class="stat-value">0.9466</div>
        <div class="stat-sub">Fast Path tabular model</div>
    </div>
    """, unsafe_allow_html=True)

with b_col2:
    st.markdown("""
    <div class="stat-card blue">
        <div class="stat-label">Isolation Forest Recall</div>
        <div class="stat-value">1.0000</div>
        <div class="stat-sub">PR-AUC: 0.9998</div>
    </div>
    """, unsafe_allow_html=True)

with b_col3:
    st.markdown("""
    <div class="stat-card green">
        <div class="stat-label">LSTM Autoencoder Precision</div>
        <div class="stat-value">0.8174</div>
        <div class="stat-sub">Deep Pass sequence model</div>
    </div>
    """, unsafe_allow_html=True)

with b_col4:
    st.markdown("""
    <div class="stat-card green">
        <div class="stat-label">LSTM Autoencoder Recall</div>
        <div class="stat-value">0.9767</div>
        <div class="stat-sub">PR-AUC: 0.9634</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# TOP 1% ALERT BUDGET METRIC PANEL
# ------------------------------------------------------------------------------
st.subheader("🎯 Top 1% Alert Budget Evaluation Metric")
st.caption("Evaluating detection efficiency if SOC analysts only inspect the top 1% highest risk score sessions (~918 alerts).")

top_1_percent_n = int(len(df_scored) * 0.01)
df_sorted_budget = df_scored.sort_values(by="risk_score", ascending=False)
df_top_1 = df_sorted_budget.head(top_1_percent_n)

total_true_attacks = len(df_scored[~df_scored["label"].isin(["normal", "insider_drift"])])
captured_true_attacks = len(df_top_1[~df_top_1["label"].isin(["normal", "insider_drift"])])

budget_recall = (captured_true_attacks / total_true_attacks * 100.0) if total_true_attacks > 0 else 100.0
budget_fp = len(df_top_1[df_top_1["label"] == "normal"])
total_normals = len(df_scored[df_scored["label"] == "normal"])
budget_fpr = (budget_fp / total_normals * 100.0) if total_normals > 0 else 0.0

bud_col1, bud_col2, bud_col3, bud_col4 = st.columns(4)

with bud_col1:
    st.markdown(f"""
    <div class="stat-card yellow">
        <div class="stat-label">1% Alert Capacity</div>
        <div class="stat-value">{top_1_percent_n:,}</div>
        <div class="stat-sub">Top 1% highest-risk events</div>
    </div>
    """, unsafe_allow_html=True)

with bud_col2:
    st.markdown(f"""
    <div class="stat-card red">
        <div class="stat-label">Recall at 1% Budget</div>
        <div class="stat-value">{budget_recall:.1f}%</div>
        <div class="stat-sub">Captured {captured_true_attacks}/{total_true_attacks} true attacks</div>
    </div>
    """, unsafe_allow_html=True)

with bud_col3:
    st.markdown(f"""
    <div class="stat-card green">
        <div class="stat-label">False Positives in Top 1%</div>
        <div class="stat-value">{budget_fp:,}</div>
        <div class="stat-sub">Normal sessions in top 1%</div>
    </div>
    """, unsafe_allow_html=True)

with bud_col4:
    st.markdown(f"""
    <div class="stat-card green">
        <div class="stat-label">FPR at 1% Budget</div>
        <div class="stat-value">{budget_fpr:.3f}%</div>
        <div class="stat-sub">False alarm rate</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ------------------------------------------------------------------------------
# LATENCY & RISK DISTRIBUTION CHARTS
# ------------------------------------------------------------------------------
c_col1, c_col2 = st.columns(2)

with c_col1:
    st.subheader("⏱️ Detection Latency vs Model Complexity")
    latency_df = pd.DataFrame([
        {"Model": "Isolation Forest (Fast Path)", "Latency (ms)": 0.8, "Path": "Immediate Tabular Pass"},
        {"Model": "LSTM Autoencoder (Deep Pass)", "Latency (ms)": 4.5, "Path": "Sequence Deep Pass"}
    ])
    fig_lat = px.bar(
        latency_df, x="Model", y="Latency (ms)", color="Path",
        title="Inference Latency Comparison (ms per session)",
        color_discrete_sequence=["#4f7cff", "#22d3a4"]
    )
    fig_lat.update_layout(paper_bgcolor="#0f1219", plot_bgcolor="#0f1219", font=dict(color="#ffffff"))
    st.plotly_chart(fig_lat, use_container_width=True)

with c_col2:
    st.subheader("🎯 Risk Score Distributions by Category")
    fig_box = px.box(
        df_scored[df_scored["label"] != "normal"], 
        x="label", y="risk_score", color="label", 
        title="Risk Score Spread Across Attack Scenarios"
    )
    fig_box.update_layout(paper_bgcolor="#0f1219", plot_bgcolor="#0f1219", font=dict(color="#ffffff"), showlegend=False)
    st.plotly_chart(fig_box, use_container_width=True)

st.markdown("---")

st.markdown("""
<div class="demo-note-box">
    <strong>⚠️ Synthetic Benchmark Separability & Low-Sample Disclaimer</strong>:
    <ul>
        <li><strong>Separability by Construction</strong>: High metrics reflect clean synthetic anomaly injection patterns rather than a guarantee of equal performance against stealthy real-world zero-day threats.</li>
        <li><strong>Low-Sample Support Caveat</strong>: Categories with small sample counts (e.g. <code>impossible_travel</code>: 4 test rows, <code>credential_stuffing</code>: 12 test rows) carry high metric variance.</li>
    </ul>
</div>
""", unsafe_allow_html=True)
