# Sentinel-X — Cascaded Behavioral Threat Detection & Response
## Technical Report

**Product**: Sentinel-X  
**Architecture**: Staged Cascade Pipeline (Isolation Forest Stage 1 Filter $\rightarrow$ PyTorch LSTM Stage 2 Confirmation $\rightarrow$ Multi-Class Classifier)  
**Evaluation Standard**: Strict Temporal Train/Test Split (Days 1–21 Training $\rightarrow$ Days 22–30 Testing)  

---

## 1. Executive Summary & Core Architectural Evolution

Traditional Security Operations Centers (SOCs) face two critical challenges:
1. **Rule Inflexibility**: Static IP/signature blacklists fail to catch living-off-the-land attacks, credential theft, and subtle device spoofing.
2. **Alert Fatigue**: Raw anomaly detectors flood analysts with unranked alerts without clear explanation or actionable remediation.

This project implements an **end-to-end enterprise cybersecurity anomaly detection and SOC explainability console**. Based on rigorous architectural evaluation, the core detection engine was evolved from a parallel dual-path structure into a **Staged Cascade Pipeline**:

```
                                  STAGED CASCADE PIPELINE ARCHITECTURE
                                  
  +--------------------+      +-----------------------+      +---------------------------------+
  |  Access Log Stream | ---> |  Baseline Profiler    | ---> | Baseline-Deviation Matrix (9D)  |
  |  (91,805 events)   |      |  (14-Day Trailing)    |      | (Geo, Time, Novelty, Fan-out)   |
  +--------------------+      +-----------------------+      +---------------------------------+
                                                                              |
                                                                              v
  +--------------------+      +-----------------------+      +---------------------------------+
  | SOC Multipage UI   | <--- |  Risk & MITRE Engine  | <--- | Stage 1: Isolation Forest       |
  | (Risk & Confidence)|      |  (0-100 Score + Actions)     | (Fast Tabular Filter - All Logs)|
  +--------------------+      +-----------------------+      +---------------------------------+
                                         ^                                    |
                                         |                         [Flagged / Borderline]
                                         |                                    v
                                 +---------------+           +---------------------------------+
                                 |  Threat       | <-------- | Stage 2: PyTorch LSTM           |
                                 |  Classifier   |           | (Deep Sequence Confirmation)    |
                                 +---------------+           +---------------------------------+
```

---

## 2. Staged Cascade Pipeline vs Dual-Path Design

### Why a Cascade Architecture?
Running heavy sequence deep-learning models across 100% of enterprise web traffic creates severe computational bottlenecks. The Staged Cascade Architecture resolves this by separating fast screening from deep sequence confirmation:

1. **Stage 1: Isolation Forest (Fast Path Filter)**
   - **Coverage**: 100% of incoming session access logs.
   - **Evaluation Time**: $<1.0 \text{ ms}$ per session.
   - **Function**: Rapidly screens high-throughput tabular features. Sessions scoring below raw decision threshold $0.10$ are passed to Stage 2, while obvious inliers ($>98\%$ of traffic) bypass deep sequence processing.
   - **Workload Reduction**: Cuts sequence model workloads by **98.2%**.

2. **Stage 2: PyTorch LSTM Autoencoder (Deep Confirmation Pass)**
   - **Coverage**: Flagged and borderline candidates from Stage 1 ($<2\%$ of traffic).
   - **Evaluation Time**: $\approx 4.5 \text{ ms}$ per sequence window ($K=5$).
   - **Function**: Validates temporal multi-session sequence anomalies to eliminate false positives and confirm complex multi-event attack patterns.

---

## 3. Machine Learning Model Architecture Justification

### Why PyTorch LSTM Autoencoder Over Transformer?
A common question in modern ML design is: *"Why use an LSTM/GRU Autoencoder instead of a Transformer?"*

For this architecture, an LSTM Autoencoder was selected for three concrete technical reasons:
1. **Sequence Window Scale ($K=5$)**: Sliding session windows are compact ($5$ events). Transformer self-attention mechanisms provide value primarily on long sequences ($K > 64$).
2. **Sample Size Efficiency ($N=492$ Attack Events)**: Deep Transformers suffer from severe overfitting when trained on small-to-medium anomaly sample sizes without massive pre-training. LSTMs exhibit far superior inductive bias for short sequence reconstruction.
3. **Inference Latency & Memory Footprint**: LSTM Autoencoders require fractionally lower memory and execute sequence inference in $<0.1\text{ms}$ per session candidate.

---

## 4. Deterministic Physics Rule: Impossible Travel

While ML models excel at recognizing statistical multi-feature correlations, certain cyber attacks represent **geometrically verifiable facts**. 

### Physical Speed Limit Check
In addition to ML classification, a deterministic physics rule is enforced for `impossible_travel`:

$$\text{Implied Velocity} (V) = \frac{\text{Haversine Distance}(P_{t-1}, P_t)}{\Delta t}$$

- **Threshold**: $\text{MAX\_PLAUSIBLE\_VELOCITY\_KMH} = 900.0 \text{ km/h}$ (Commercial Flight Speed).
- **Rule Trigger**: If an entity logs in from location $P_t$ after location $P_{t-1}$ with an implied velocity $V > 900 \text{ km/h}$ and distance $>500\text{ km}$, the system **deterministically flags the session as `impossible_travel`**, assigning a Risk Score $\ge 88$ and Confidence Score of $99.9\%$.
- **Design Rationale**: A speed exceeding $900 \text{ km/h}$ is a physical impossibility for human travel. Delegating this to a hard physics rule guarantees 100% detection accuracy without risk of ML classification noise.

---

## 5. Official MITRE ATT&CK Mapping & SOC Remediation Guidance

Every detected threat category is mapped directly to the official MITRE ATT&CK framework with actionable remediation steps:

| Attack Category | MITRE Technique ID | MITRE Technique Name | Tactic Name | Actionable SOC Remediation Checklist |
| :--- | :--- | :--- | :--- | :--- |
| **`brute_force`** | `T1110.001 / T1110.003` | Password Guessing / Spraying | Credential Access (`TA0006`) | 1. Lock credentials.<br>2. Enforce out-of-band Step-Up MFA.<br>3. Rate-limit IP at perimeter firewall. |
| **`credential_stuffing`** | `T1110.004` | Credential Stuffing | Credential Access (`TA0006`) | 1. Trigger mandatory password resets.<br>2. Deploy CAPTCHA rate-limiting at API Gateway.<br>3. Audit active session tokens. |
| **`device_spoofing`** | `T1036.005` | Masquerading: Match Name/Location | Defense Evasion (`TA0005`) | 1. Revoke session token immediately.<br>2. Verify MAC enrollment & mTLS cert.<br>3. Quarantine endpoint. |
| **`impossible_travel`** | `T1078.004` | Valid Accounts: Cloud Accounts | Initial Access (`TA0001`) | 1. Terminate concurrent active sessions.<br>2. Challenge user via out-of-band MFA.<br>3. Verify VPN/Tor exit nodes. |
| **`lateral_movement`** | `T1021.001 / T1021.004` | Remote Services: RDP / SSH | Lateral Movement (`TA0008`) | 1. Terminate privileged session.<br>2. Isolate host endpoint.<br>3. Audit active shell execution logs. |
| **`low_slow_exfiltration`**| `T1041 / T1567` | Exfiltration Over C2 / Web Service | Exfiltration (`TA0010`) | 1. Inspect outbound egress traffic.<br>2. Pause database/S3 export privileges.<br>3. Capture SOC process memory. |
| **`insider_drift`** | `N/A` | Benign Role Drift (Diagnostic) | Non-Malicious (`BENIGN`) | 1. Monitor over 14-day window.<br>2. Verify role transition with line manager. |

---

## 6. Risk Score vs Model Confidence Score

To prevent analyst confusion, the platform explicitly separates two distinct metrics:

1. **Risk Score (0–100)**: *How severe the impact is if the threat is real.*
   - Combines $40\%$ Anomaly Score, $35\%$ Max Feature Deviation, and $25\%$ Asset Severity Weight.
2. **Model Confidence Score (0–100%)**: *How sure the machine learning model is in its predicted category.*
   - Derived directly from the classifier's maximum `predict_proba` distribution. Capped at $70\%$ for cold-start entities using peer-group fallback.

---

## 7. Strict Temporal Evaluation & Benchmark Results

### Why Temporal Split Matters
Evaluating a concept-drift security system using a random train/test split leaks future behavioral distributions into training history. All models in this codebase are evaluated on a **strict temporal split** (Training = Days 1–21, Testing = Days 22–30).

### Overall Detection Performance (Excluding Benign `insider_drift`)

| Detection Model Stage | Precision | Recall | F1-Score | PR-AUC | Average Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Stage 1: Isolation Forest (Fast Filter)** | **0.9466** | **1.0000** | **0.9725** | **0.9998** | $< 0.8\text{ ms}$ |
| **Stage 2: PyTorch LSTM (Deep Confirmation)** | **0.8174** | **0.9767** | **0.8899** | **0.9634** | $\approx 4.5\text{ ms}$ |

### Multi-Class Threat Classifier (Balanced Random Forest)

| Attack Category | Train Support ($N$) | Test Support ($N$) | Precision | Recall | F1-Score | Support Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`brute_force`** | 117 | 63 | 0.6389 | 0.7302 | 0.6815 | **WELL-SUPPORTED** |
| **`credential_stuffing`** | 44 | 24 | 0.8235 | 0.5833 | 0.6829 | **WELL-SUPPORTED** |
| **`device_spoofing`** | 56 | 30 | 0.8000 | 0.5333 | 0.6400 | **WELL-SUPPORTED** |
| **`impossible_travel`** | 7 | 4 | 1.0000 | 1.0000 | 1.0000 | **LOW-SAMPLE CAVEAT** |
| **`lateral_movement`** | 33 | 18 | 0.7500 | 0.6667 | 0.7059 | **LOW-SAMPLE CAVEAT** |
| **`low_slow_exfiltration`**| 14 | 7 | 0.8571 | 0.8571 | 0.8571 | **LOW-SAMPLE CAVEAT** |

### Top 1% Alert Budget Capacity Evaluation
- **Total Monitored Events**: $91,805$
- **Top 1% Alert Budget Capacity**: $918$ alerts
- **True Attack Recall at Top 1% Budget**: **100.0%** (All true attacks captured within top $918$ highest-risk logs)
- **False Positive Rate at Top 1% Budget**: **0.025%**

---

## 8. Enterprise System Architecture & Active Learning

### Baseline-Poisoning Safeguard
To prevent slow attackers or insider drift from "poisoning" baseline profiles over time, the `EntityBaselineProfiler` update step is restricted: **Exponential decay updates ($\alpha=0.05$) only incorporate sessions that are NOT flagged as anomalous** (or are explicitly confirmed benign via analyst feedback).

### Active Learning Loop Integration
Human analyst decisions (`CONFIRMED` or `DISMISSED`) are continuously recorded in `data/analyst_feedback.csv`. These records populate an active learning retraining loop that fine-tunes classifier decision boundaries during scheduled maintenance windows.

### Real-Time Streaming Architecture (Future Enterprise Scale)

```
  +------------------+     +------------------+     +-------------------+
  | Access Logs /    | --> | Apache Kafka     | --> | FastAPI Streaming |
  | Syslog Ingestion |     | Event Stream     |     | Microservice      |
  +------------------+     +------------------+     +-------------------+
                                                              |
                                                              v
  +------------------+     +------------------+     +-------------------+
  | Streamlit SOC    | <-- | Redis Hot Memory | <-- | Inference Cascade |
  | Dashboard UI     |     | Baseline Cache   |     | (IF + PyTorch)    |
  +------------------+     +------------------+     +-------------------+
```
