import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle, joblib
from detection_model import FeatureEngineer, temporal_split_with_min_test

FEATURE_COLS = [
    'geo_distance_km','time_of_day_zscore','resource_novelty',
    'session_duration_zscore','auth_failure_rate_trailing',
    'source_ip_entity_fanout','command_sequence_novelty',
    'fingerprint_mismatch','is_cold_start'
]
ATTACK_LABELS = [
    'brute_force','credential_stuffing','device_spoofing',
    'impossible_travel','lateral_movement','low_slow_exfiltration'
]

df = pd.read_csv('data/access_logs.csv').merge(pd.read_csv('data/ground_truth_labels.csv'), on='log_id')
train_idx, test_idx = temporal_split_with_min_test(df, min_test_samples=4, test_ratio=0.30)
df_test = df.iloc[test_idx].reset_index(drop=True)

with open('models/saved/baseline_profiler.pkl','rb') as f:
    profiler = pickle.load(f)
scaler   = joblib.load('models/saved/scaler.joblib')
if_model = joblib.load('models/saved/isolation_forest.joblib')

fe = FeatureEngineer(profiler)
df_test_feat = fe.extract_features(df_test)
test_labels  = df_test['label'].values

y_true_attack = np.array([1 if l in ATTACK_LABELS else 0 for l in test_labels])
y_true_normal = np.array([1 if l == 'normal' else 0 for l in test_labels])

n_test_total = len(df_test)
n_attacks = int(y_true_attack.sum())
n_normals = int(y_true_normal.sum())

X = scaler.transform(df_test_feat[FEATURE_COLS].values)
raw_dec = if_model.decision_function(X) # lower = more anomalous
anom_scores = -raw_dec # higher = more anomalous

# Sort indices by anomaly score descending
sorted_indices = np.argsort(-anom_scores)

budgets = [0.005, 0.01, 0.02, 0.03, 0.05, 0.10]

print(f"Total Test Events: {n_test_total:,}")
print(f"Total Attack Events: {n_attacks}")
print(f"Total Normal Events: {n_normals:,}\n")

print(f"{'Budget %':<10} | {'Alert Capacity':<14} | {'Cutoff Score':<12} | {'Attack TP':<10} | {'Recall':<10} | {'Normal FP':<10} | {'FPR %':<10} | {'Precision':<10}")
print("-" * 100)

for b in budgets:
    k = int(np.round(b * n_test_total))
    top_k_indices = sorted_indices[:k]
    cutoff = anom_scores[top_k_indices[-1]]
    
    flagged_mask = np.zeros(n_test_total, dtype=bool)
    flagged_mask[top_k_indices] = True
    
    tp = np.sum(flagged_mask & (y_true_attack == 1))
    fp = np.sum(flagged_mask & (y_true_normal == 1))
    
    recall = tp / n_attacks
    fpr = fp / n_normals
    precision = tp / k if k > 0 else 0.0
    
    print(f"{b*100:<9.1f}% | {k:<14} | {cutoff:<12.4f} | {tp:<10} | {recall:<10.4f} | {fp:<10} | {fpr*100:<10.4f}% | {precision:<10.4f}")
