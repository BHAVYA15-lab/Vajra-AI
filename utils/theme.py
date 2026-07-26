import streamlit as st

def inject_theme():
    """
    Injects custom CSS design system based on the XAI Security Monitor design tokens.
    Importing 'Syne' and 'JetBrains Mono' Google Fonts.
    """
    theme_css = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');

        :root {
            --bg:        #0a0c12;
            --bg2:       #0f1219;
            --bg3:       #141720;
            --bg4:       #1c2030;
            --border:    #232840;
            --border2:   #2e3450;
            --text:      #e8eaf2;
            --text2:     #8b90a8;
            --text3:     #555a72;
            --accent:    #4f7cff;
            --accent2:   #7b5cf0;
            --green:     #22d3a4;
            --yellow:    #f5a623;
            --red:       #ff4757;
            --red2:      #ff6b81;
            --mono:      'JetBrains Mono', monospace;
            --display:   'Syne', sans-serif;
        }

        /* Overall App Background & Typography */
        .stApp {
            background-color: var(--bg);
            color: var(--text);
            font-family: var(--display);
        }
        
        h1, h2, h3, h4, h5, h6 {
            font-family: var(--display) !important;
            color: var(--text) !important;
            font-weight: 700 !important;
        }

        /* Subtle fixed 40px grid texture background */
        .stApp::before {
            content: '';
            position: fixed; inset: 0; z-index: 0;
            background-image:
                linear-gradient(rgba(79, 124, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(79, 124, 255, 0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
        }

        /* Top Header Component */
        .xai-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 24px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: rgba(15, 18, 25, 0.85);
            backdrop-filter: blur(12px);
            margin-bottom: 24px;
        }
        .xai-logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .xai-logo-icon {
            width: 38px;
            height: 38px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            box-shadow: 0 4px 12px rgba(79, 124, 255, 0.3);
        }
        .xai-logo-title {
            font-size: 18px;
            font-weight: 800;
            letter-spacing: -0.3px;
            color: var(--text);
        }
        .xai-logo-sub {
            font-size: 11px;
            color: var(--text2);
            font-weight: 400;
        }
        
        /* Status Pill with Pulsing Live Dot */
        .status-pill {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.5px;
            background: var(--bg3);
            border: 1px solid var(--green);
            color: var(--green);
            font-family: var(--mono);
        }
        .status-pill .dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--green);
            animation: pulse-dot 2s infinite;
        }

        @keyframes pulse-dot {
            0%, 100% { box-shadow: 0 0 0 0 rgba(34, 211, 164, 0.4); }
            50% { box-shadow: 0 0 0 6px rgba(34, 211, 164, 0); }
        }

        /* Pipeline Visualizer Strip */
        .pipeline-container {
            display: flex;
            align-items: center;
            gap: 6px;
            overflow-x: auto;
            padding: 12px 16px;
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 24px;
        }
        .pipeline-step {
            background: var(--bg3);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 14px;
            font-size: 11px;
            font-weight: 600;
            color: var(--text2);
            white-space: nowrap;
            letter-spacing: 0.3px;
            transition: all 0.3s;
        }
        .pipeline-step.active {
            border-color: var(--accent);
            color: var(--accent);
            background: rgba(79, 124, 255, 0.12);
            box-shadow: 0 0 10px rgba(79, 124, 255, 0.2);
        }
        .pipeline-arrow {
            color: var(--border2);
            font-size: 13px;
            font-weight: bold;
        }

        /* Stat Cards */
        .stat-card {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px 20px;
            position: relative;
            overflow: hidden;
            transition: border-color 0.3s, transform 0.2s;
            margin-bottom: 12px;
        }
        .stat-card::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
        }
        .stat-card.blue::after { background: linear-gradient(90deg, var(--accent), var(--accent2)); }
        .stat-card.red::after { background: linear-gradient(90deg, var(--red), var(--red2)); }
        .stat-card.yellow::after { background: linear-gradient(90deg, var(--yellow), #f7bc4f); }
        .stat-card.green::after { background: linear-gradient(90deg, var(--green), #4de8c0); }
        .stat-card:hover {
            border-color: var(--border2);
            transform: translateY(-2px);
        }
        .stat-label {
            font-size: 11px;
            color: var(--text3);
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 6px;
            font-weight: 600;
        }
        .stat-value {
            font-size: 30px;
            font-weight: 800;
            font-family: var(--mono);
            letter-spacing: -0.5px;
            line-height: 1.1;
        }
        .stat-card.blue .stat-value { color: var(--accent); }
        .stat-card.red .stat-value { color: var(--red); }
        .stat-card.yellow .stat-value { color: var(--yellow); }
        .stat-card.green .stat-value { color: var(--green); }
        .stat-sub {
            font-size: 11px;
            color: var(--text2);
            margin-top: 6px;
        }

        /* Risk Badges */
        .risk-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 3px 9px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            font-family: var(--mono);
        }
        .risk-badge.CRITICAL, .risk-badge.HIGH {
            background: rgba(255, 71, 87, 0.15);
            color: var(--red);
            border: 1px solid rgba(255, 71, 87, 0.3);
        }
        .risk-badge.MEDIUM {
            background: rgba(245, 166, 35, 0.15);
            color: var(--yellow);
            border: 1px solid rgba(245, 166, 35, 0.3);
        }
        .risk-badge.LOW {
            background: rgba(34, 211, 164, 0.1);
            color: var(--green);
            border: 1px solid rgba(34, 211, 164, 0.25);
        }

        /* SHAP Bar Chart Layout */
        .shap-bars {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-top: 10px;
        }
        .shap-row {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .shap-name {
            font-size: 11px;
            color: var(--text2);
            width: 170px;
            flex-shrink: 0;
            font-family: var(--mono);
        }
        .shap-bar-container {
            flex: 1;
            height: 22px;
            position: relative;
            background: var(--bg3);
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        .shap-bar {
            position: absolute;
            top: 0; height: 100%;
            border-radius: 4px;
            display: flex;
            align-items: center;
            padding: 0 8px;
            font-size: 10px;
            font-weight: 700;
            font-family: var(--mono);
            white-space: nowrap;
        }
        .shap-bar.positive {
            background: linear-gradient(90deg, rgba(255,71,87,0.7), rgba(255,71,87,0.4));
            left: 0;
            color: var(--red);
        }
        .shap-pct {
            font-size: 11px;
            color: var(--text2);
            width: 45px;
            text-align: right;
            font-family: var(--mono);
        }

        /* AI Explanation Card */
        .ai-explanation-card {
            background: var(--bg3);
            border: 1px solid var(--border2);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .ai-explanation-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }
        .ai-badge {
            background: linear-gradient(135deg, var(--accent), var(--accent2));
            color: #ffffff;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 9px;
            font-weight: 800;
            letter-spacing: 1px;
            font-family: var(--mono);
        }
        .ai-explanation-text {
            font-size: 13px;
            color: var(--text);
            line-height: 1.6;
        }

        /* Demo Warning Box */
        .demo-note-box {
            background-color: var(--bg2);
            border-left: 4px solid var(--yellow);
            border-top: 1px solid var(--border);
            border-right: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 12px;
            color: var(--text2);
            margin-bottom: 20px;
        }

        /* Leaderboard Item Styling */
        .leaderboard-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg3);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 8px;
        }
        .leaderboard-rank {
            font-family: var(--mono);
            font-size: 14px;
            font-weight: 700;
            color: var(--accent);
            width: 30px;
        }
        .leaderboard-name {
            font-family: var(--mono);
            font-size: 13px;
            font-weight: 600;
            color: var(--text);
            flex: 1;
        }
        .leaderboard-count {
            font-family: var(--mono);
            font-size: 13px;
            color: var(--red);
            font-weight: 700;
            margin-right: 16px;
        }
        .leaderboard-pct {
            background: var(--bg4);
            border: 1px solid var(--border2);
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 11px;
            color: var(--text2);
            font-family: var(--mono);
        }

        /* Streamlit Dataframe Overrides */
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--border) !important;
            border-radius: 10px !important;
            overflow: hidden !important;
            background-color: var(--bg2) !important;
        }
    </style>
    """
    st.markdown(theme_css, unsafe_allow_html=True)

def render_header(title="Vajra AI", subtitle="Cascaded Behavioral Threat Detection & Response"):
    """Renders top header with live pulsing status indicator pill."""
    st.markdown(f"""
    <div class="xai-header">
        <div class="xai-logo">
            <div class="xai-logo-icon">🛡️</div>
            <div>
                <div class="xai-logo-title">{title}</div>
                <div class="xai-logo-sub">{subtitle}</div>
            </div>
        </div>
        <div class="status-pill">
            <div class="dot"></div>
            <span>LIVE</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_pipeline_strip(active_step=5):
    """
    Renders horizontal connected pipeline status strip reflecting the CASCADE Detection Pipeline.
    """
    steps = [
        ("📡", "Access Logs"),
        ("📋", "Baseline Profiler"),
        ("🌲", "Stage 1: Isolation Forest (Fast Filter)"),
        ("🧠", "Stage 2: PyTorch LSTM (Deep Confirmation)"),
        ("⚙️", "Threat Classifier"),
        ("🔍", "Risk & MITRE Engine")
    ]
    
    html = '<div class="pipeline-container">'
    for idx, (icon, label) in enumerate(steps):
        is_active = "active" if idx == active_step else ""
        html += f'<div class="pipeline-step {is_active}">{icon} {label}</div>'
        if idx < len(steps) - 1:
            html += '<div class="pipeline-arrow">→</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)
