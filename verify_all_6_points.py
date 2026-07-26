import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle, joblib

from data_loader import get_pipeline_data, FEATURE_COLS
from detection_model import temporal_split_with_min_test, FeatureEngineer

# ==============================================================================
# 1. VERIFY TEMPORAL SPLIT CODE & DATE RANGES
# ==============================================================================
print("======================================================================")
print("1. TEMPORAL TRAIN/TEST SPLIT VERIFICATION")
print("======================================================================")

df_logs   = pd.read_csv('data/access_logs.csv')
df_labels = pd.read_csv('data/ground_truth_labels.csv')
df_merged = df_logs.merge(df_labels, on='log_id')

df_merged['dt'] = pd.to_datetime(df_merged['timestamp'])
df_sorted = df_merged.sort_values('dt').reset_index(drop=True)

train_idx, test_idx = temporal_split_with_min_test(df_sorted, min_test_samples=4, test_ratio=0.30)
df_train = df_sorted.iloc[train_idx].reset_index(drop=True)
df_test  = df_sorted.iloc[test_idx].reset_index(drop=True)

print(f"Total Merged Logs:  {len(df_sorted):,} rows")
print(f"Training Set Rows:  {len(df_train):,} ({len(df_train)/len(df_sorted)*100:.2f}%)")
print(f"Test Set Rows:      {len(df_test):,} ({len(df_test)/len(df_sorted)*100:.2f}%)")
print(f"Training Date Range: {df_train['dt'].min()}  -->  {df_train['dt'].max()}")
print(f"Test Date Range:     {df_test['dt'].min()}  -->  {df_test['dt'].max()}")

# Confirm no overlap
assert df_train['dt'].max() <= df_test['dt'].min(), "CRITICAL ERROR: Overlap found between train and test timestamps!"
print("✅ Verified strictly chronological split (train max <= test min, zero time overlap).")

# ==============================================================================
# 5. STAGE 1 -> STAGE 2 CASCADE WORKLOAD REDUCTION
# ==============================================================================
print("\n======================================================================")
print("5. STAGE 1 -> STAGE 2 CASCADE WORKLOAD REDUCTION")
print("======================================================================")

with open('models/saved/baseline_profiler.pkl','rb') as f:
    profiler = pickle.load(f)
scaler   = joblib.load('models/saved/scaler.joblib')
if_model = joblib.load('models/saved/isolation_forest.joblib')

fe = FeatureEngineer(profiler)
df_test_feat = fe.extract_features(df_test)

X_test_scaled = scaler.transform(df_test_feat[FEATURE_COLS].values)
raw_dec = if_model.decision_function(X_test_scaled)
raw_anom_scores = np.maximum(0.0, -raw_dec)

# Stage 1 candidate filtering rule: raw_dec < 0.10 (i.e. anom_score > 0.0 or suspicious)
s1_candidates = (raw_dec < 0.10)
n_s1_candidates = s1_candidates.sum()
n_stage1_total = len(df_test)
workload_red = (1.0 - (n_s1_candidates / n_stage1_total)) * 100.0

print(f"Stage 1 Input Events (100% test set):  {n_stage1_total:,} rows")
print(f"Stage 2 Input Candidates (dec < 0.10):  {n_s1_candidates:,} rows ({n_s1_candidates/n_stage1_total*100:.2f}%)")
print(f"Exact Cascade Workload Reduction:      {workload_red:.2f}%")

# ==============================================================================
# 4. CATEGORY COUNTS IN TEST SET & INSIDER DRIFT
# ==============================================================================
print("\n======================================================================")
print("4. TEST SET ATTACK CATEGORY BREAKDOWN & INSIDER DRIFT")
print("======================================================================")

test_label_counts = df_test['label'].value_counts()
print("All Label Counts in Temporal Test Set:")
for label, count in test_label_counts.items():
    print(f"  - {label:<24}: {count:,} events")

ATTACK_LABELS = [
    'brute_force','credential_stuffing','device_spoofing',
    'impossible_travel','lateral_movement','low_slow_exfiltration'
]

df_scored, _, _, _, _, _, _ = get_pipeline_data()
df_test_scored = df_scored.iloc[test_idx].reset_index(drop=True)

y_true_attack = np.array([1 if l in ATTACK_LABELS else 0 for l in df_test_scored['label']])
y_true_normal = np.array([1 if l == 'normal' else 0 for l in df_test_scored['label']])
y_true_drift  = np.array([1 if l == 'insider_drift' else 0 for l in df_test_scored['label']])

n_attacks = y_true_attack.sum()
n_normals = y_true_normal.sum()
n_drifts  = y_true_drift.sum()

print(f"\nTotal True Attacks (6 categories): {n_attacks}")
print(f"Total Benign Normal Events:        {n_normals:,}")
print(f"Total Benign Insider Drift Events: {n_drifts}")

# ==============================================================================
# 2. PRECISION DROP & RISK SCORE DISTRIBUTION AT TOP 1.0% BUDGET
# ==============================================================================
print("\n======================================================================")
print("2. PRECISION DROP ANALYSIS AT TOP 1.0% ALERT BUDGET")
print("======================================================================")

risk_scores = df_test_scored['risk_score'].values
sorted_by_risk = np.argsort(-risk_scores)

K_1pct = int(np.round(0.01 * len(df_test_scored))) # 276 alerts
top_1pct_idx = sorted_by_risk[:K_1pct]

top_1pct_df = df_test_scored.iloc[top_1pct_idx]
tp_mask = top_1pct_df['label'].isin(ATTACK_LABELS)
fp_mask = top_1pct_df['label'] == 'normal'
drift_fp_mask = top_1pct_df['label'] == 'insider_drift'

n_tp = tp_mask.sum()
n_fp_normal = fp_mask.sum()
n_fp_drift  = drift_fp_mask.sum()
n_fp_total  = n_fp_normal + n_fp_drift

print(f"Top 1.0% Budget Alert Capacity: {K_1pct} alerts")
print(f"True Positives (Attack TP):     {n_tp} (Recall = {n_tp/n_attacks*100:.2f}%)")
print(f"False Positives (Normal FP):   {n_fp_normal} (FPR = {n_fp_normal/n_normals*100:.2f}%)")
print(f"False Positives (Drift FP):    {n_fp_drift} (Drift FPR = {n_fp_drift/n_drifts*100:.2f}%)")
print(f"Total False Positives:         {n_fp_total}")
print(f"Precision:                      {n_tp}/{K_1pct} = {n_tp/K_1pct*100:.2f}%")

print("\n--- Risk Score Distribution of Top 1% Alerts ---")
print("TP Risk Scores:")
print(top_1pct_df[tp_mask]['risk_score'].value_counts().sort_index(ascending=False))
print("FP Risk Scores:")
print(top_1pct_df[~tp_mask]['risk_score'].value_counts().sort_index(ascending=False))

# ==============================================================================
# 3. ASSET SEVERITY BIAS REPRODUCIBILITY VERIFICATION
# ==============================================================================
print("\n======================================================================")
print("3. VERIFY ASSET SEVERITY BIAS & RANKING COMPARISON")
print("======================================================================")

# Composite Risk Score Ranking vs Raw Anomaly Score Ranking
sorted_by_raw = np.argsort(-raw_anom_scores)

budgets = [0.01, 0.05, 0.10]
print(f"{'Budget':<8} | {'Composite Risk TP':<18} | {'Composite Risk Rec':<20} | {'Raw IF Anom TP':<15} | {'Raw IF Anom Rec':<18}")
print("-" * 85)
for b in budgets:
    k = int(np.round(b * len(df_test_scored)))
    top_risk_k = sorted_by_risk[:k]
    top_raw_k  = sorted_by_raw[:k]
    
    tp_risk = np.sum(y_true_attack[top_risk_k] == 1)
    tp_raw  = np.sum(y_true_attack[top_raw_k] == 1)
    
    print(f"{b*100:<7.1f}% | {tp_risk:<18} | {tp_risk/n_attacks*100:<19.2f}% | {tp_raw:<15} | {tp_raw/n_attacks*100:<17.2f}%")

# ==============================================================================
# 6. INSIDER DRIFT DIAGNOSTIC FPR
# ==============================================================================
print("\n======================================================================")
print("6. INSIDER DRIFT DIAGNOSTIC FPR")
print("======================================================================")

drift_test_mask = (df_test_scored['label'] == 'insider_drift')
drift_total = drift_test_mask.sum()
drift_flagged_high_risk = (df_test_scored[drift_test_mask]['risk_score'] >= 57.0).sum()
drift_flagged_critical  = (df_test_scored[drift_test_mask]['risk_score'] >= 85.0).sum()

print(f"Total Insider Drift Events in Test Set: {drift_total}")
print(f"Drift Events Flagged at Risk >= 57.0:    {drift_flagged_high_risk} ({drift_flagged_high_risk/drift_total*100:.2f}%)")
print(f"Drift Events Flagged at Risk >= 85.0:    {drift_flagged_critical} ({drift_flagged_critical/drift_total*100:.2f}%)")
