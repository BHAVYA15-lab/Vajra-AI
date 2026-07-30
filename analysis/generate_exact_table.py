import os, sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "models"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "explainability"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "utils"))
import sys, os
# sys.path handled via PROJECT_ROOT
# sys.path handled via PROJECT_ROOT
# sys.path handled via PROJECT_ROOT
import numpy as np
import pandas as pd
import pickle, joblib
from data_loader import get_pipeline_data, FEATURE_COLS
from detection_model import temporal_split_with_min_test

# Load overall scored pipeline data
df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

# Split test set index
df_logs   = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'access_logs.csv'))
df_labels = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'ground_truth_labels.csv'))
df        = df_logs.merge(df_labels, on='log_id')

train_idx, test_idx = temporal_split_with_min_test(df, min_test_samples=4, test_ratio=0.30)
df_test_scored = df_scored.iloc[test_idx].reset_index(drop=True)

ATTACK_LABELS = [
    'brute_force','credential_stuffing','device_spoofing',
    'impossible_travel','lateral_movement','low_slow_exfiltration'
]

test_labels = df_test_scored['label'].values
y_true_attack = np.array([1 if l in ATTACK_LABELS else 0 for l in test_labels])
y_true_benign = np.array([0 if l in ATTACK_LABELS else 1 for l in test_labels]) # All non-attack (normal + insider_drift)

n_test_total = len(df_test_scored)
n_attacks = int(y_true_attack.sum())
n_benign = int(y_true_benign.sum())

risk_scores = df_test_scored['risk_score'].values
# Rank by risk score descending
sorted_by_risk = np.argsort(-risk_scores)

budgets = [0.005, 0.01, 0.02, 0.03, 0.05, 0.10]

print("=== STANDARDIZED COMPOSITE RISK SCORE ALERT BUDGET METRICS ===")
print(f"Total Test Events: {n_test_total:,}")
print(f"Total Attack Events: {n_attacks}")
print(f"Total Benign Events: {n_benign:,}\n")

print(f"{'Budget %':<10} | {'Alert Capacity (K)':<18} | {'Cutoff Risk':<12} | {'Attack TP':<10} | {'Recall':<10} | {'Benign FP (K - TP)':<18} | {'FPR %':<10} | {'Precision':<10}")
print("-" * 110)

for b in budgets:
    k = int(np.round(b * n_test_total))
    top_k_indices = sorted_by_risk[:k]
    cutoff = risk_scores[top_k_indices[-1]]
    
    flagged_mask = np.zeros(n_test_total, dtype=bool)
    flagged_mask[top_k_indices] = True
    
    tp = np.sum(flagged_mask & (y_true_attack == 1))
    fp = k - tp  # Exact mathematical relationship: K - TP = FP
    
    recall = tp / n_attacks
    fpr = fp / n_benign
    precision = tp / k if k > 0 else 0.0
    
    print(f"{b*100:<9.1f}% | {k:<18} | {cutoff:<12.1f} | {tp:<10} | {recall*100:<9.2f}% | {fp:<18} | {fpr*100:<10.2f}% | {precision*100:<9.2f}%")
