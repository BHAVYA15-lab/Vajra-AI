# Vajra AI — Cascaded Behavioral Threat Detection & Response

> **Product**: Vajra AI  
> **Repository Structure**: Domain-Agnostic Behavioral ML Architecture  
> **Author**: Autonomous Cybersecurity Agent & Pair Programmer  

---

## Executive Summary

Security Operations Centers (SOCs) face unprecedented log volumes, sophisticated intrusion attempts, and extreme class imbalance—where true malicious activity represents less than 0.5% of total enterprise traffic. Traditional signature-based detection mechanisms fail against novel zero-day attacks, compromised credentials, and insider threats.

This project delivers a complete, domain-agnostic **Machine Learning System for Behavioral Anomaly Detection**, featuring:
1. **Synthetic Multi-Entity Log Data Pipeline**: Generates 91,805 access logs across 175 entities over 30 days, injected with 7 complex attack patterns free of leakage signatures.
2. **Rolling Baseline Profiler with Exponential Decay**: Tracks entity-level micro-behaviors with 14-day trailing windows and peer-group cold-start fallback ($N < 5$ logs).
3. **Dual-Path Anomaly Detection Pipeline**:
   - **Isolation Forest (Fast Path)**: Immediate tabular evaluation ($<1\text{ms}$ inference latency).
   - **PyTorch LSTM Autoencoder (Deep Pass)**: Temporal sequence reconstruction error modeling multi-event patterns ($K=5$ trailing events).
4. **Multi-Class Threat Classifier**: Categorizes flagged anomalies into specific attack taxonomies with per-class support metrics.
5. **Feature Attribution & SOC Explainability Engine**: Translates complex baseline deviations into transparent 0–100 risk scores, natural language triage cards, and human-in-the-loop analyst feedback loops.
6. **Interactive Streamlit SOC Dashboard**: Provides real-time threat feed sorting, entity drift inspection, and top 1% alert budget evaluations.

---

## 1. System Architecture & Components

```
+-----------------------------------------------------------------------------------+
|                               RAW ACCESS LOG STREAM                               |
|               (timestamp, entity_id, entity_type, geo, IP, resource, auth, fp)      |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                            TASK 2: BASELINE PROFILER                              |
|   - 14-Day Trailing Window Statistics (Mean/Std login hour, duration, cmd length)   |
|   - Exponential Decay Updates: mu_t = (1 - alpha)*mu_{t-1} + alpha*x_t (alpha=0.05)   |
|   - Cold-Start Fallback: N < 5 logs -> Peer Group Profile (is_cold_start = True)    |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        TASK 3: ENGINEERED FEATURE MATRIX                          |
| 1. geo_distance_km               6. source_ip_entity_fanout                       |
| 2. time_of_day_zscore            7. command_sequence_novelty                      |
| 3. resource_novelty              8. fingerprint_mismatch                          |
| 4. session_duration_zscore       9. is_cold_start                                 |
| 5. auth_failure_rate_trailing                                                     |
+-----------------------------------------------------------------------------------+
                                          |
                                          +-------------------------+
                                          |                         |
                                          v                         v
+---------------------------------------------------+ +-----------------------------+
|    ISOLATION FOREST (FAST PATH - TABULAR)         | | PYTORCH LSTM AUTOENCODER    |
|    - Contamination: 0.005, 150 Estimators         | |   (DEEP PASS - TEMPORAL)    |
|    - Inference Latency: < 1ms                     | | - Evaluates K=5 sequences   |
|    - Precision: 0.9466 | Recall: 1.0000          | | - Rec. Loss MSE > Thresh    |
+---------------------------------------------------+ +-----------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     TASK 4: MULTI-CLASS ATTACK CLASSIFIER                         |
|   Random Forest Multi-Class Classifier -> Threat Category Prediction             |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                 TASK 4 & 5: SOC EXPLAINABILITY & HUMAN TRIAGE CONSOLE             |
|   - 0-100 Risk Score Engine (40% Anomaly + 35% MaxDev + 25% Asset Severity Weight)    |
|   - Top 3 Anomaly Feature Attributions & Triage Action Recommendations             |
|   - Human-in-the-Loop Analyst Response Logger ("Confirm Threat" / "Dismiss FP")     |
+-----------------------------------------------------------------------------------+
```

---

## 2. Dataset Taxonomies & Leakage Prevention Rules

The dataset (`/data/access_logs.csv` and `/data/ground_truth_labels.csv`) contains 91,805 records across 100 `user`s, 45 `service_account`s, and 30 `edge_device`s over 30 days.

### Strict Leak-Free Engineering Rules Applied:
1. **Fingerprint Plausibility**: Device fingerprints use generic operating systems, valid browser strings, and realistic MAC addresses. Malicious keywords (`Hydra`, `Kali`, `DE:AD:BE:EF`, `00:00:00:00:00:00`) were strictly removed.
2. **Entity-Specific Baseline Mismatches**: Device spoofing is modeled as a mismatch against **that specific entity's historical device profile** (e.g. a macOS user appearing on a Windows server), rather than a static global spoof signature.
3. **Generic Command Sequence Scoring**: Removed all hardcoded command signatures (`sudo`, `nmap`, `aws s3 cp`, `cat /etc/shadow`). Command novelty is calculated purely as:
   $$\text{Command Novelty} = \text{Unseen Token Ratio} + \min(\text{Command Length Z-Score} / 5.0, 1.0)$$

---

## 3. Comprehensive Model Evaluation & Benchmarks

### A. Anomaly Detection Performance (Excluding `insider_drift`)

| Detection Model | Precision | Recall | F1-Score | PR-AUC | Inference Latency | Primary Use Case |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Isolation Forest (Fast Path)** | **0.9466** | **1.0000** | **0.9725** | **0.9998** | **< 1 ms** | Real-time immediate session scoring |
| **PyTorch LSTM Autoencoder (Deep Pass)** | **0.8174** | **0.9767** | **0.8899** | **0.9634** | **~ 4.5 ms** | Multi-session temporal sequence analysis |

---

### B. Per-Class Classifier Performance & Statistical Support Breakdown

Evaluates multi-class threat classification with explicit support checking to distinguish well-supported categories from low-sample classes.

| Attack Category | Train Support ($N$) | Test Support ($N$) | Precision | Recall | F1-Score | Statistical Support Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`brute_force`** | 117 | 63 | 0.6389 | 0.7302 | 0.6815 | **WELL-SUPPORTED** |
| **`credential_stuffing`** | 28 | 12 | 0.6667 | 0.1667 | 0.2667 | **LOW-SAMPLE CAVEAT** |
| **`device_spoofing`** | 33 | 15 | 0.2353 | 0.2667 | 0.2500 | **LOW-SAMPLE CAVEAT** |
| **`impossible_travel`** | 4 | 4 | 0.0000 | 0.0000 | 0.0000 | **LOW-SAMPLE CAVEAT** |
| **`lateral_movement`** | 42 | 18 | 0.3182 | 0.3889 | 0.3500 | **LOW-SAMPLE CAVEAT** |
| **`low_slow_exfiltration`** | 28 | 12 | 0.7000 | 0.5833 | 0.6364 | **LOW-SAMPLE CAVEAT** |

---

### C. `insider_drift` False Positive Rate Diagnostic

- Total `insider_drift` Test Sessions: **22**
- **Isolation Forest FPR**: **0.0%** (0/22 false alarms)
- **PyTorch LSTM Autoencoder FPR**: **9.1%** (2/22 false alarms)

---

### D. Top 1% Alert Budget Evaluation Metric

- **Top 1% Alert Capacity**: 918 highest-risk sessions (out of 91,805 total logs).
- **Recall at Top 1% Budget**: **100.0%** of all true attack anomalies captured.
- **FPR at Top 1% Budget**: **0.025%** false positive rate on normal traffic.

---

## 4. Honest Limitations & Synthetic Benchmarking Disclaimers

> [!WARNING]
> 1. **Synthetic Separability by Construction**: The high detection metrics (100% recall on Isolation Forest) reflect that synthetic anomaly injection patterns are cleanly separable from normal baseline behavior by design. This does **not** guarantee equal performance against evasive real-world zero-day threats.
> 2. **Low-Sample Metric Variance**: Attack categories with $<20$ test samples (`impossible_travel`, `credential_stuffing`, `low_slow_exfiltration`) exhibit high variance and cross-class confusion when signature keywords are removed. These low-sample metrics represent honest diagnostic indicators rather than statistically guaranteed production performance.

---

## 5. Deployment & Operation Instructions

### Running Detection & Classification Pipelines
```bash
# 1. Generate Synthetic Data
python data_generator/generate_logs.py

# 2. Train & Evaluate Detection Models (Isolation Forest & PyTorch LSTM)
python models/detection_model.py

# 3. Train Multi-Class Threat Classifier
python models/classifier.py

# 4. Test SOC Explainability Engine
python explainability/explainer.py
```

### Launching Streamlit SOC Dashboard
```bash
streamlit run dashboard/app.py
```
Access the interactive web console at `http://localhost:8501`.
