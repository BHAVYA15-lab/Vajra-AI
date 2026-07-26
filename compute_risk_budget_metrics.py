import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle, joblib
from data_loader import get_pipeline_data, FEATURE_COLS

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

# Filter to temporal test set indices
# In data_loader, df_scored is all 91,805. Let's inspect test set explicitly.
df_logs   = pd.read_csv('data/access_logs.csv')
df_labels = pd.read_csv('data/ground_truth_labels.csv')
df        = df_logs.merge(df_labels, on='log_id')

from detection_model import temporal_split_with_min_test
train_idx, test_idx = temporal_split_with_min_test(df, min_test_samples=4, test_ratio=0.30)

df_test_scored = df_scored.iloc[test_idx].reset_index(drop=True)

ATTACK_LABELS = [
    'brute_force','credential_stuffing','device_spoofing',
    'impossible_travel','lateral_movement','low_slow_exfiltration'
]

test_labels = df_test_scored['label'].values
y_true_attack = np.array([1 if l in ATTACK_LABELS else 0 for l in test_labels])
y_true_normal = np.array([1 if l == 'normal' else 0 for l in test_labels])

n_test_total = len(df_test_scored)
n_attacks = int(y_true_attack.sum())
n_normals = int(y_true_normal.sum())

risk_scores = df_test_scored['risk_score'].values
sorted_by_risk = np.argsort(-risk_scores)

budgets = [0.005, 0.01, 0.02, 0.03, 0.05, 0.10]

print("=== ALERT BUDGET METRICS RANKED BY COMPOSITE RISK SCORE ===")
print(f"Total Test Events: {n_test_total:,}")
print(f"Total Attack Events: {n_attacks}")
print(f"Total Normal Events: {n_normals:,}\n")

print(f"{'Budget %':<10} | {'Alert Capacity':<14} | {'Cutoff Risk':<12} | {'Attack TP':<10} | {'Recall':<10} | {'Normal FP':<10} | {'FPR %':<10} | {'Precision':<10}")
print("-" * 100)

for b in budgets:
    k = int(np.round(b * n_test_total))
    top_k_indices = sorted_by_risk[:k]
    cutoff = risk_scores[top_k_indices[-1]]
    
    flagged_mask = np.zeros(n_test_total, dtype=bool)
    flagged_mask[top_k_indices] = True
    
    tp = np.sum(flagged_mask & (y_true_attack == 1))
    fp = np.sum(flagged_mask & (y_true_normal == 1))
    
    recall = tp / n_attacks
    fpr = fp / n_normals
    precision = tp / k if k > 0 else 0.0
    
    print(f"{b*100:<9.1f}% | {k:<14} | {cutoff:<12.4f} | {tp:<10} | {recall:<10.4f} | {fp:<10} | {fpr*100:<10.4f}% | {precision:<10.4f}")
