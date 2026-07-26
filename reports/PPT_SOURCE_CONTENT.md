# Vajra AI — Hackathon Presentation Source Content (6-Slide Structure)

---

## 1. TITLE PAGE
- **Problem Statement Title**: AI-Powered Behavioral Anomaly Detection for Cybersecurity
- **Theme**: Cybersecurity / Smart Automation (TO BE CONFIRMED BY USER)
- **PS Category**: Software
- **Problem Statement ID**: TO BE FILLED — USER MUST PROVIDE (Check Hackathon Portal)
- **Student Name**: TO BE FILLED — USER MUST PROVIDE
- **Student ID**: TO BE FILLED — USER MUST PROVIDE

---

## 2. IDEA TITLE — Proposed Solution

### Product Name & Tagline
- **Vajra AI** — Cascaded Behavioral Threat Detection & Response

### System Overview (Plain Language)
- Models entity baseline behavior across 14-day trailing access logs.
- Detects complex cyber threats using a two-stage cascade architecture.
- Maps detected threats to official MITRE ATT&CK techniques with remediation steps.
- Separates impact severity (Risk Score) from machine learning certainty (Confidence Score).
- Provides an interactive Streamlit SOC console for analyst triage and feedback.

### Addressing Problem Statement Requirements
- **Sequential & Behavioral Data**: Tracks multi-event session sequences ($K=5$) and 9D deviation features.
- **Extreme Class Imbalance**: Evaluated with balanced Random Forest (`class_weight='balanced'`) and alert budgets.
- **Concept Drift**: Adapts baselines via Exponential Moving Average ($\alpha=0.05$) excluding anomalous sessions.
- **Explainability**: Combines feature attributions, Risk/Confidence gauges, and plain-language summaries.
- **Cold-Start Entities**: Uses peer-group fallback profiles with a 70% confidence cap until 5 sessions occur.

### Innovation & Uniqueness
- **Staged Cascade Architecture**: 2-tier pipeline cuts deep learning inference workload by 96.88%.
- **Deterministic Physics Engine**: Hard-coded velocity check ($V > 900\text{ km/h}$) flags `impossible_travel` with 100% accuracy.
- **Operational Alert Budget Tuning**: Evaluates recall against analyst capacity constraints rather than static cutoffs.
- **Active Learning Feedback**: Incorporates human analyst triage decisions directly into baseline updates.

---

## 3. TECHNICAL APPROACH

### Technology Stack & Frameworks
- **Language**: Python 3.12
- **Data Engineering**: pandas 2.1.4, NumPy 1.26.2, Faker
- **Machine Learning**: scikit-learn 1.7.2 (Isolation Forest, Random Forest, StandardScaler)
- **Deep Learning**: PyTorch 2.13.0 (LSTM Autoencoder)
- **SOC Console UI**: Streamlit 1.60.0, Plotly 6.9.0
- **Version Control**: Git

### Cascade Pipeline Flow Diagram
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
  [ Random Forest Classifier & Physics Engine ]
           │
           ▼
  [ Risk (0-100) & MITRE ATT&CK Mapping Engine ]
           │
           ▼
  [ Vajra AI Streamlit SOC Console ]
```

### Core Methodology
- **14-Day Trailing Baseline**: Computes rolling mean and standard deviation per entity.
- **EMA Concept Drift**: Updates baseline with decay factor $\alpha=0.05$ only on confirmed-benign logs.
- **Cold-Start Fallback**: Uses peer-group profile averages when entity session count $< 5$.
- **9D Feature Matrix**:
  1. `geo_distance_km`
  2. `time_of_day_zscore`
  3. `resource_novelty`
  4. `session_duration_zscore`
  5. `auth_failure_rate_trailing`
  6. `source_ip_entity_fanout`
  7. `command_sequence_novelty`
  8. `fingerprint_mismatch`
  9. `is_cold_start`

---

## 4. FEASIBILITY AND VIABILITY

### Feasibility & Benchmarked Prototype Results
- **Fully Working Prototype**: 4-page interactive Streamlit SOC console loading in 6.8s.
- **Cascade Workload Reduction**: Stage 1 filters 96.88% of logs; Stage 2 LSTM evaluates only 3.12%.
- **Headline Detection Performance** (Strict Temporal Split: Days 1-21 Train, Days 22-30 Test):
  - **Top 1.0% Alert Budget Capacity** (276 alerts / 27,555 test logs):
  - **System Recall**: **75.61%** (31/41 attacks captured).
  - **False Positive Rate**: **0.89%** (245 FPs / 27,514 benign logs).
  - **Precision**: **11.23%** (reflecting 0.15% attack base-rate in test set).

### Key Technical Challenges & Risks
- **Base-Rate Fallacy Precision Drop**: Low attack prevalence ($0.15\%$) causes false alarms to outnumber true attacks.
- **Low-Sample Test Categories**: 5 of 6 attack classes have $N \le 5$ under temporal split.
- **Asset Severity Bias**: 10 attacks on low-value assets (`severity_weight = 0.30`) fall below the top 1% risk threshold.
- **Untested Physics Borderline**: Speed rule ($900\text{ km/h}$) untested on borderline velocities ($900\text{--}5000\text{ km/h}$).

### Mitigation Strategies
- **Operational Alert Budget Tuning**: Tunes detection thresholds to match SOC analyst review capacity.
- **Hybrid Physics + ML Design**: Governs geometric facts with 100% physics rules; ML handles statistical patterns.
- **Active Learning Loop**: Incorporates analyst triage feedback (`data/analyst_feedback.csv`) into model retraining.
- **Dual Ranking Modes**: Allows SOC analysts to switch between Severity Risk Rank and Pure Anomaly Rank.

---

## 5. ARTIFACTS

### Recommended Dashboard Screenshots
*(Capture these 4 PNG screenshots from the running Streamlit console and save to `reports/screenshots/`)*

1. **`reports/screenshots/01_home_dashboard.png`**
   - *View*: `Home.py`
   - *Key Elements*: Vajra AI header, pulsing LIVE indicator, pipeline status strip, summary KPI cards.
2. **`reports/screenshots/02_live_threat_feed.png`**
   - *View*: `pages/1_Live_Threat_Feed.py`
   - *Key Elements*: Ranked threat queue table, explanation summary column, 🔴 LIVE streaming toggle bar.
3. **`reports/screenshots/03_triage_inspector.png`**
   - *View*: `pages/1_Live_Threat_Feed.py` (Selected Log ID Detail)
   - *Key Elements*: SHAP feature attributions, Risk vs Confidence gauges, MITRE checklist, Confirm/Dismiss buttons.
4. **`reports/screenshots/04_threat_analytics.png`**
   - *View*: `pages/3_Threat_Analytics.py`
   - *Key Elements*: Cascade benchmark comparison charts, alert budget trade-off table.

### Representative Code Snippet
```python
# File: utils/data_loader.py (Deterministic Physics Rule & Composite Risk Engine)

# 1. Physics Impossible-Travel Hard Override Check
is_physics_impossible = (feat_dict.get("is_physics_impossible_travel", 0.0) == 1.0)
if is_physics_impossible:
    pred_attack = "impossible_travel"
    conf_score = 99.9
    sev_label = "CRITICAL"
    risk_score = max(risk_score, 88.0)

# 2. Composite Risk Score Calculation
# Risk = 40% Anomaly Score + 35% Max Feature Deviation + 25% Asset Severity Weight
risk_score = (0.40 * norm_anom) + (0.35 * max_dev) + (0.25 * sev_weight * 100.0)
risk_score = float(np.clip(risk_score, 0.0, 100.0))
```

---

## 6. RESEARCH AND REFERENCES

### Research Work & Standards
- **MITRE ATT&CK Framework**: Standard taxonomy for adversary tactics and techniques (`https://attack.mitre.org/`).
- **Isolation Forest for High-Throughput Anomaly Detection**: Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE ICDM. (Justifies fast Stage 1 filtering).
- **Sequence Autoencoders for Temporal Anomaly Detection**: Malhotra, P., et al. (2016). *LSTM-based Encoder-Decoder for Multi-sensor Anomaly Detection*. arXiv:1607.00148. (Justifies PyTorch LSTM Stage 2).
- **Exponential Moving Average for Concept Drift Adaptation**: Gama, J., et al. (2014). *A survey on concept drift adaptation*. ACM Computing Surveys. (Justifies baseline profile EMA updates).
- **Explainable AI (SHAP Framework)**: Lundberg, S. M., & Lee, S. I. (2017). *A Unified Approach to Interpreting Model Predictions*. NIPS. (Justifies feature attribution explainability).
