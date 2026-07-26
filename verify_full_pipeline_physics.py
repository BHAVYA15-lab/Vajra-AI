import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle, joblib

from data_loader import load_saved_artifacts, get_pipeline_data
from detection_model import FeatureEngineer, temporal_split_with_min_test

df_scored, df_features, profiler, scaler, if_model, classifier, explainer = get_pipeline_data()

df_logs   = pd.read_csv('data/access_logs.csv')
df_labels = pd.read_csv('data/ground_truth_labels.csv')
df_merged = df_logs.merge(df_labels, on='log_id')

train_idx, test_idx = temporal_split_with_min_test(df_merged, min_test_samples=4, test_ratio=0.30)

df_test_scored = df_scored.iloc[test_idx].reset_index(drop=True)

imp_mask = (df_test_scored['label'] == 'impossible_travel')
df_imp_test = df_test_scored[imp_mask]

print("=== FULL PIPELINE PHYSICS RULE EVALUATION ON TEMPORAL TEST SET ===")
print(f"Total True impossible_travel events in test set: {len(df_imp_test)}")

for idx, r in df_imp_test.iterrows():
    print(f"Log ID: {r['log_id']} | Label: {r['label']:<20} | Pred: {r['predicted_attack']:<20} | Risk: {r['risk_score']:<5} | Conf: {r['confidence_score']:<5} | Phys Flag: {r['is_physics_impossible_travel']} | Vel: {r['implied_velocity_kmh']:.1f} km/h")

physics_tp = (df_imp_test['is_physics_impossible_travel'] == 1.0).sum()
print(f"\nExact Physics Rule Detection on Test Set: {physics_tp} / {len(df_imp_test)} ({physics_tp/len(df_imp_test)*100:.1f}%)")
