import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle, joblib
from data_loader import get_pipeline_data, FEATURE_COLS
from detection_model import temporal_split_with_min_test

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

df_logs   = pd.read_csv('data/access_logs.csv')
df_labels = pd.read_csv('data/ground_truth_labels.csv')
df        = df_logs.merge(df_labels, on='log_id')

train_idx, test_idx = temporal_split_with_min_test(df, min_test_samples=4, test_ratio=0.30)
df_test_scored = df_scored.iloc[test_idx].reset_index(drop=True)

ATTACK_LABELS = [
    'brute_force','credential_stuffing','device_spoofing',
    'impossible_travel','lateral_movement','low_slow_exfiltration'
]

test_labels = df_test_scored['label'].values
y_true_attack = np.array([1 if l in ATTACK_LABELS else 0 for l in test_labels])

df_attacks = df_test_scored[y_true_attack == 1].copy()

print(f"Total True Attack Events in Temporal Test Set: {len(df_attacks)}\n")

print(f"{'Log ID':<8} | {'Label':<22} | {'Risk Score':<10} | {'Raw IF Anom':<12} | {'Severity Weight':<15} | {'Resource':<30}")
print("-" * 105)

for idx, row in df_attacks.iterrows():
    print(f"{row['log_id']:<8} | {row['label']:<22} | {row['risk_score']:<10.1f} | {row['raw_anom_score']:<12.4f} | {row['severity_weight']:<15.2f} | {row['resource_accessed']:<30}")

print("\n--- ATTACK RISK SCORE DISTRIBUTION ---")
print(df_attacks['risk_score'].value_counts().sort_index(ascending=False))

print("\n--- ATTACK SEVERITY WEIGHT DISTRIBUTION ---")
print(df_attacks['severity_weight'].value_counts())

print("\n--- ATTACKS WITH RISK SCORE < 57 ---")
df_low_risk_attacks = df_attacks[df_attacks['risk_score'] < 57]
print(f"Count: {len(df_low_risk_attacks)}")
for idx, row in df_low_risk_attacks.iterrows():
    print(f"Log ID: {row['log_id']}, Label: {row['label']}, Risk: {row['risk_score']}, IF Anom: {row['raw_anom_score']:.4f}, SevW: {row['severity_weight']}, Res: {row['resource_accessed']}")
