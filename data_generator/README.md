# Synthetic Log Generator Documentation

This module (`generate_logs.py`) synthesizes multi-entity access and connection logs over a 30-day simulated timeframe to evaluate behavioral anomaly detection models.

## Baseline Entity Profiles

The synthetic generator creates **175 distinct entities**:
1. **User Accounts (`usr_001` - `usr_100`)**:
   - **Hours**: Gaussian distribution around workday peak hours (08:30–18:00 local time). Low weekend activity (~15% of normal workday volume).
   - **Locations**: Assigned 1–2 primary geographic hubs (e.g. New York, San Francisco, London).
   - **IP Range**: Consistent subnet per location.
   - **Resources**: Standard business applications (`/hr/portal`, `/crm/contacts/view`, `/jira/board`).
   - **Auth Methods**: Password, biometric, OAuth token.
   - **Device Fingerprint**: Plausible desktop OS fingerprints (`Windows 11 Enterprise`, `macOS Sonoma 14.2`, `Ubuntu Desktop`) paired with static MAC address and TLS protocol.

2. **Service Accounts (`svc_001` - `svc_045`)**:
   - **Hours**: 24/7 automated activity with periodic batch intervals (every 1–2 hours).
   - **Locations**: Datacenter IP ranges (`10.0.4.x`).
   - **Resources**: Internal APIs and databases (`/db/production_read`, `/api/v1/metrics`, `/cache/redis/flush`).
   - **Auth Methods**: Service token, mTLS certificate.
   - **Session Duration**: Short (1–8 seconds).

3. **Edge Devices (`dev_001` - `dev_030`)**:
   - **Hours**: High frequency periodic telemetry pings (every 30–60 minutes).
   - **Locations**: Field network subnets (`172.16.100.x`).
   - **Resources**: Telemetry and status endpoints (`/iot/v2/telemetry`, `/firmware/status_check`).
   - **Auth Methods**: Device certificate, token.
   - **Device Fingerprint**: Embedded firmware (`FreeRTOS v10.4.3`) with MQTT/CoAP protocols.

---

## Attack Taxonomy & Simulation Mechanics

True anomalies comprise **~0.5%–3.0%** of total generated sessions across the 30-day period.

> [!IMPORTANT]
> **No Keyword Leakage Guarantee**: All anomaly sessions use realistic, plausible device fingerprints (e.g., standard browser User-Agents, standard desktop/server OS strings). Anomaly detection must rely on **behavioral deviation from entity baseline** (e.g., unexpected OS for a device, new MAC address, unusual access time, rare resource combination, or implausible geographic velocity), rather than matching explicit attack keywords like "Hydra" or "Kali".

| Attack Type | Injected Mechanics | Key Behavioral Anomaly Indicators |
| :--- | :--- | :--- |
| **`brute_force`** | 25–40 rapid failed auth attempts in <3 minutes targeting a user from a single attacker IP (`198.51.100.x`). Plausible Chrome/Windows user-agent. | High frequency bursts, 0–2s duration, foreign IP/geo, `password` auth failure. |
| **`impossible_travel`** | User logs in from regular office location, followed 3–15 minutes later by a login from a distant city (NYC $\rightarrow$ Tokyo, London $\rightarrow$ Singapore, SF $\rightarrow$ Frankfurt). | Implausible geographic velocity ($\Delta \text{distance} / \Delta t$), unexpected destination IP. |
| **`credential_stuffing`** | Single attacker IP (`185.220.101.5`, `194.26.29.110`) attempting logins across 40 distinct user/service entities in short succession. | High fan-out across entity IDs from a single source IP, low duration, 100% failure rate. |
| **`lateral_movement`** | Compromised user account accessing sensitive domain endpoints (`/admin/domain_controller`, `/db/customer_pii`, `/k8s/secrets/prod`) with administrative shell commands. | Unusual resource scope expansion, non-empty command sequence (`whoami`, `sudo -l`, `nmap`). |
| **`device_spoofing`** | Entity (e.g., `dev_xxx` or `usr_xxx`) logging in with a **plausible but mismatched fingerprint** (e.g., an IoT device logging in as a Windows desktop, or a user logging in via an internal mTLS server certificate). | Fingerprint/protocol mismatch against the entity's stored historical baseline profile. |
| **`low_slow_exfiltration`** | User downloading confidential data exports (`/db/finance_export`, `/cloud/s3/vault_backup`) off-hours (01:00–04:00 AM) over 10 consecutive days with varied exfiltration commands. | Off-hours timing anomaly, prolonged session duration, cumulative exfiltration behavior. |
| **`insider_drift`** | Legitimate employee assigned to new project gradually expanding endpoint access (`/jira/board/security_refactor`, `/dev/repo_new_service`). | **Ambiguous FP Tuning Scenario**: Gradual shift over weeks, legitimate auth, standard work hours. |

---

## Downstream Evaluation Guidelines (Task 2 & 3)

> [!CAUTION]
> **`insider_drift` Evaluation Rule**:
> `insider_drift` represents legitimate baseline evolution (e.g., employee project role change) and is included specifically for **False Positive Rate (FPR) tuning**.
> 
> - **Primary Detection Metrics**: In Task 2 and 3, `insider_drift` **MUST BE EXCLUDED** from primary Precision, Recall, and F1-score calculations for true malicious attacks (`brute_force`, `impossible_travel`, `credential_stuffing`, `lateral_movement`, `device_spoofing`, `low_slow_exfiltration`).
> - **Diagnostic FPR Metric**: `insider_drift` must be tracked separately in a diagnostic evaluation table to measure how often normal baseline evolution is incorrectly flagged as a security threat (False Alarm Rate).

> [!WARNING]
> **Stratified Splitting & Small Class Count Handling**:
> Attack class counts range from 8 to 180 rows across the 30-day dataset.
> - **Stratified Train/Test Split Required**: Downstream model evaluation must use a **stratified split** (`stratify=y` or time-stratified window) ensuring a minimum number of samples per label exist in both training and test sets.
> - **Known Limitation Flagging**: Model evaluation reports must explicitly highlight that per-class metrics (especially for ultra-rare classes like `impossible_travel` with 8 rows) carry high variance due to small support size.

---

## Output Data Schema

### `access_logs.csv`
- `log_id` (int): Unique entry identifier.
- `entity_id` (str): Entity identifier (`usr_xxx`, `svc_xxx`, `dev_xxx`).
- `entity_type` (str): `user` \| `service_account` \| `edge_device`.
- `timestamp` (str): ISO-8601 UTC timestamp (`2026-06-01T08:14:22Z`).
- `source_ip` (str): IPv4 address.
- `geo_location` (str): City, Country.
- `resource_accessed` (str): Endpoint, file, or port.
- `auth_method` (str): `password` \| `token` \| `certificate` \| `biometric`.
- `session_duration` (int): Duration in seconds.
- `command_sequence` (str): JSON string list of shell commands executed.
- `device_fingerprint` (str): `OS | MAC | Protocol`.

### `ground_truth_labels.csv`
- `log_id` (int): Key joinable to `access_logs.csv`.
- `label` (str): Ground truth classification (`normal`, `brute_force`, `impossible_travel`, `credential_stuffing`, `lateral_movement`, `device_spoofing`, `low_slow_exfiltration`, `insider_drift`).
