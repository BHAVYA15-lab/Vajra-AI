# Sentinel-X — Cascaded Behavioral Threat Detection & Response

A domain-agnostic machine learning system that models "normal" access and connection behavior per entity (user, service account, edge device), detects intrusions near real-time via a Staged Cascade Pipeline (Isolation Forest → LSTM Autoencoder), classifies threat categories with MITRE ATT&CK mapping, and provides human-interpretable SOC risk scores and triage recommendations.

---

## 🚀 Quickstart & Complete Execution Workflow

Run all project components in chronological order from the project root directory:

```bash
# 1. Install Dependencies
pip install -r requirements.txt

# 2. Generate Synthetic Access Log Dataset (91,805 rows, 175 entities)
python data_generator/generate_logs.py

# 3. Fit Baseline Profiler & Train Anomaly Detection Models (Isolation Forest & PyTorch LSTM)
python models/detection_model.py

# 4. Train Multi-Class Attack Classifier (Random Forest with class_weight='balanced')
python models/classifier.py

# 5. Generate Sample SOC Analyst Explainability Reports
python explainability/explainer.py

# 6. Launch Interactive Streamlit SOC Security Dashboard
streamlit run dashboard/app.py
```

After running `streamlit run dashboard/app.py`, open your browser to `http://localhost:8501`.

---

## 🛠️ Project Architecture

```
/
├── data_generator/
│   ├── generate_logs.py        # Synthetic log generator (91,805 access logs)
│   └── README.md              # Taxonomy, leak-free rules & guidelines
├── models/
│   ├── baseline_profile.py     # Trailing 14-day profiler with exponential decay & cold-start fallback
│   ├── detection_model.py      # Isolation Forest (Fast Path) & PyTorch LSTM Autoencoder (Deep Pass)
│   ├── classifier.py           # Multi-Class Threat Classifier (class_weight='balanced')
│   └── saved/                  # Serialized trained models (.joblib, .pt, .pkl)
├── explainability/
│   ├── explainer.py            # Feature attribution, 0-100 risk score engine & SOC triage cards
│   └── README.md              # Asset SeverityWeight mapping & SOC analyst guide
├── dashboard/
│   └── app.py                 # Interactive Streamlit SOC Security Console (3 Views)
├── reports/
│   ├── report.md               # Final comprehensive technical report
│   ├── benchmark_limitation.md # Synthetic evaluation separability & low-sample caveats
│   └── project_summary.md      # Architecture & benchmark summary
├── data/
│   ├── access_logs.csv        # Generated 91,805 access logs
│   ├── ground_truth_labels.csv # Ground truth attack labels
│   └── analyst_feedback.csv   # Human-in-the-loop analyst triage log
└── requirements.txt            # Python dependencies
```

---

## 📊 Key Features

- **Leak-Free Behavioral Detection**: Zero hardcoded signature keywords (`Hydra`, `Kali`, `sudo`). Detection derives strictly from entity baseline deviations.
- **Dual-Path Anomaly Engine**: Fast Tabular Pass (Isolation Forest, $<1\text{ms}$) + Deep Sequence Pass (PyTorch LSTM Autoencoder, $K=5$ window).
- **Cold-Start & Concept Drift**: Peer-group fallback for $<5$ logs; exponential decay ($\alpha=0.05$) absorbs legitimate behavioral evolution.
- **Human-in-the-Loop SOC Triage**: Interactive Streamlit dashboard with 0–100 risk scores, feature drivers, and `Confirm Threat` / `Dismiss FP` feedback buttons.
