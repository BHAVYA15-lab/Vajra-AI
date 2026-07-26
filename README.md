# Vajra AI — Cascaded Behavioral Threat Detection & Response

**Vajra AI** is a domain-agnostic behavioral threat detection platform designed to solve modern Security Operations Center (SOC) alert fatigue. Rather than relying on rigid, easily-evaded IP blacklists or signature keywords, Vajra AI models normal access behavior per entity (users, service accounts, edge devices) over trailing 14-day windows. By combining high-throughput tabular filtering with deep sequence validation in a **two-stage cascade architecture**, the platform catches living-off-the-land intrusions in real time while reducing deep learning compute workloads by **96.88%**. Detected anomalies are mapped directly to official MITRE ATT&CK techniques and presented via an interactive, human-in-the-loop Streamlit SOC console.

---

## 🌟 Key Technical Highlights

- **⚡ Two-Stage Cascade Architecture (96.88% Workload Reduction)**:
  - **Stage 1 (Isolation Forest)**: Rapidly screens 100% of incoming session traffic in $<1.0\text{ ms}$ per event across 9 engineered baseline-deviation features.
  - **Stage 2 (PyTorch LSTM Autoencoder)**: Evaluated *only* on suspicious candidates flagged by Stage 1 (~3% of traffic), validating temporal multi-session sequence patterns ($K=5$) while cutting deep learning inference overhead by 96.88%.

- **📅 Strict Temporal Train/Test Evaluation (Zero Behavioral Leakage)**:
  Evaluated on a strict chronological split (**Training = Days 1–21 [64,250 logs]**, **Testing = Days 22–30 [27,555 logs]**). Training baseline profilers and models operate exclusively on past logs, preserving true concept-drift evaluation integrity without future context leakage.

- **🎯 Operational Alert-Budget Tuning**:
  Evaluates recall against realistic SOC analyst review capacity rather than uncalibrated static thresholds. At the **Top 1.0% Alert Budget Capacity** (276 alerts / 27,555 test logs), the system achieves **75.61% Recall** (31/41 attacks captured) at a **0.89% False Positive Rate**.

- **🔎 Transparent & Honest Engineering Documentation**:
  Explicitly documents system edge cases—including **Asset Severity Bias** (where composite risk scoring intentionally prioritizes high-value asset risk over low-value asset attacks) and **Base-Rate Precision Trade-Offs** (explaining how a 0.89% FPR yields 11.23% precision given a 0.15% attack prevalence).

- **✈️ Hybrid Physics + ML Engine**:
  Governs geometrically verifiable facts with a deterministic Haversine speed rule ($V > 900\text{ km/h}$) to flag `impossible_travel` with 100% precision and recall, while delegating statistical behavioral patterns to a multi-class Random Forest (`class_weight='balanced'`).

- **🛡️ MITRE ATT&CK Mapping & Actionable Triage**:
  Automates mapping of all threat categories to official MITRE Technique IDs (`T1110`, `T1036`, `T1078`, `T1021`, `T1041`) paired with step-by-step SOC remediation guidance.

---

## 🏗️ System Architecture & Pipeline Flow

```
  [ Access Log Stream ] (91,805 Events)
           │
           ▼
  [ Baseline Profiler ] (14-Day Trailing EMA, α=0.05)
           │
           ▼
  [ 9D Feature Matrix ] (Geo, Time, Novelty, Fan-out, etc.)
           │
           ▼
  [ Stage 1: Isolation Forest ] ──(Inliers ~97%)──► [ Safe / Logged ]
           │ (Suspicious Candidates ~3%)
           ▼
  [ Stage 2: PyTorch LSTM Autoencoder ] (Sequence Window K=5)
           │
           ▼
  [ Multi-Class Random Forest & Physics Engine ]
           │
           ▼
  [ Risk (0-100) & MITRE ATT&CK Mapping Engine ]
           │
           ▼
  [ Vajra AI Streamlit SOC Console ]
```

---

## 🚀 Setup & Execution Workflow

Run all project components in chronological order from the project root directory:

```bash
# 1. Install Dependencies
pip install -r requirements.txt

# 2. Generate Synthetic Access Log Dataset (91,805 logs, 175 entities)
python data_generator/generate_logs.py

# 3. Fit Baseline Profiler & Train Cascade Models (Isolation Forest & PyTorch LSTM)
python models/detection_model.py

# 4. Train Multi-Class Threat Classifier (Random Forest with class_weight='balanced')
python models/classifier.py

# 5. Generate Sample SOC Analyst Explainability Reports
python explainability/explainer.py

# 6. Launch Interactive Streamlit SOC Security Dashboard
python -m streamlit run Home.py
```

After running `python -m streamlit run Home.py`, open your browser to `http://localhost:8501`.

---

## 📂 Repository Structure

```
.
├── Home.py                     # Main Streamlit SOC Dashboard Entrypoint
├── pages/
│   ├── 1_Live_Threat_Feed.py   # Live Threat Stream, 🔴 LIVE Mode, Cold-Start Toggle, Triage Inspector
│   ├── 2_Entity_Profiler.py    # Entity Baseline Profiler & Concept Drift Inspector
│   └── 3_Threat_Analytics.py   # Cascade Stage Benchmarks & Alert Budget Analysis
├── models/
│   ├── baseline_profile.py     # Trailing 14-day EMA Profiler & Cold-Start Peer Fallback
│   ├── detection_model.py      # Stage 1 Isolation Forest & Stage 2 PyTorch LSTM Autoencoder
│   └── classifier.py           # Multi-Class Balanced Random Forest Threat Classifier
├── explainability/
│   ├── explainer.py            # SHAP Feature Attributions, 0-100 Risk Engine & Triage Cards
│   └── mitre_mapping.py        # MITRE ATT&CK Technique Mapping & SOC Remediation Guidance
├── utils/
│   ├── data_loader.py          # Vectorized Pipeline Data Loader & Analyst Feedback Logging
│   └── theme.py               # Dark Glassmorphic Design System & Visual Tokens
├── data_generator/
│   └── generate_logs.py        # Synthetic Access Log Stream Generator (91,805 events)
├── reports/
│   ├── report.md               # Comprehensive Technical & Architectural Report
│   ├── benchmark_limitation.md # Synthetic Separability & Low-Sample Evaluation Caveats
│   ├── project_summary.md      # High-Level Architecture & Benchmark Summary
│   └── PPT_SOURCE_CONTENT.md   # 6-Slide Hackathon Presentation Source Content
└── requirements.txt            # Python Dependencies
```

---

## ⚠️ Known Limitations & Real-World Considerations

- **Stage 1 Recall Ceiling**: Because the detection pipeline is a cascade, Stage 1 (Isolation Forest) sets the recall ceiling for the system. Stage 2 (LSTM) serves to suppress false positives and reduce compute workloads rather than recover Stage 1 misses.
- **Asset Severity Bias**: Composite Risk Score ranking incorporates a 25% asset criticality weight (`SeverityWeight`), which intentionally deprioritizes low-value asset attacks (`severity_weight = 0.30`) below high-value normal traffic. Raw unweighted anomaly ranking surfaces all low-asset attacks (100% recall at 10% budget).
- **Synthetic Benchmark Separability**: Synthetic anomaly injection patterns (abrupt geographic jumps, auth failure bursts) are cleanly separable by construction. Real-world zero-day performance would require tuning against live traffic distributions.
- **Untested Physics Borderline Range**: The speed check ($V > 900\text{ km/h}$) was evaluated against extreme synthetic jumps ($>50,000\text{ km/h}$). Realistic flight layover velocities ($900\text{--}5,000\text{ km/h}$) require real-world travel data tuning before production deployment.
