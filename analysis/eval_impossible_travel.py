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

from data_loader import load_saved_artifacts, load_processed_data
from detection_model import FeatureEngineer, temporal_split_with_min_test

df_logs   = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'access_logs.csv'))
df_labels = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'ground_truth_labels.csv'))
df_merged = df_logs.merge(df_labels, on='log_id')

profiler, scaler, if_model, classifier = load_saved_artifacts()

train_idx, test_idx = temporal_split_with_min_test(df_merged, min_test_samples=4, test_ratio=0.30)
df_test = df_merged.iloc[test_idx].reset_index(drop=True)

fe = FeatureEngineer(profiler)
df_test_feat = fe.extract_features(df_test)

# Check physics rule flags across test set
physics_flags = df_test_feat['is_physics_impossible_travel'].values
implied_vels  = df_test_feat['implied_velocity_kmh'].values
geo_dists     = df_test_feat['geo_distance_km'].values
test_labels   = df_test['label'].values

print("=== IMPOSSIBLE TRAVEL PHYSICS RULE TEST SET EVALUATION ===")
print(f"Total Test Set Events: {len(df_test):,}")

# 1. Evaluate on True impossible_travel events in test set
imp_mask = (test_labels == 'impossible_travel')
n_imp = imp_mask.sum()
print(f"\nTrue 'impossible_travel' Events in Test Set: {n_imp}")

df_imp = df_test[imp_mask].copy()
df_imp_feat = df_test_feat[imp_mask].copy()

for i in range(len(df_imp)):
    row = df_imp.iloc[i]
    feat = df_imp_feat.iloc[i]
    print(f"\n[Test Event #{i+1}] Log ID: {row['log_id']}")
    print(f"  Entity:           {row['entity_id']} ({row['entity_type']})")
    print(f"  Timestamp:        {row['timestamp']}")
    print(f"  Geo Location:     {row['geo_location']}")
    print(f"  Geo Distance:     {feat['geo_distance_km']:.1f} km")
    print(f"  Implied Velocity: {feat['implied_velocity_kmh']:.1f} km/h")
    print(f"  Physics Flag:     {feat['is_physics_impossible_travel']} (1.0 = Triggered)")

# Check if physics rule correctly triggered on all 4
imp_triggered = np.sum(physics_flags[imp_mask] == 1.0)
print(f"\nPhysics Rule TP (True Impossible Travel Flagged): {imp_triggered} / {n_imp} ({imp_triggered/n_imp*100:.1f}%)")

# 2. Check for False Positives (Physics rule triggering on non-impossible_travel events)
non_imp_triggered = np.sum((physics_flags == 1.0) & (~imp_mask))
print(f"Physics Rule FP (Non-impossible_travel events flagged): {non_imp_triggered}")

# 3. Check for any impossible_travel events across ENTIRE dataset (train + test)
all_feat = fe.extract_features(df_merged)
all_labels = df_merged['label'].values
all_imp_mask = (all_labels == 'impossible_travel')

print(f"\n=== ALL {all_imp_mask.sum()} IMPOSSIBLE TRAVEL EVENTS ACROSS ENTIRE DATASET ===")
df_all_imp = df_merged[all_imp_mask]
df_all_imp_feat = all_feat[all_imp_mask]

for i in range(len(df_all_imp)):
    row = df_all_imp.iloc[i]
    feat = df_all_imp_feat.iloc[i]
    print(f"Log ID: {row['log_id']} | Dist: {feat['geo_distance_km']:>7.1f}km | Vel: {feat['implied_velocity_kmh']:>7.1f}km/h | Flag: {feat['is_physics_impossible_travel']}")
