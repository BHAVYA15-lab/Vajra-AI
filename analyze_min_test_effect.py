import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import pandas as pd
import numpy as np

df_logs   = pd.read_csv('data/access_logs.csv')
df_labels = pd.read_csv('data/ground_truth_labels.csv')
df_merged = df_logs.merge(df_labels, on='log_id')
df_merged['dt'] = pd.to_datetime(df_merged['timestamp'])
df_sorted = df_merged.sort_values('dt').reset_index(drop=True)

n_total = len(df_sorted)
split_cutoff_idx = int(n_total * 0.70) # 64,250

cutoff_dt = df_sorted.iloc[split_cutoff_idx]['dt']
print(f"Strict 70% Timestamp Cutoff Date: {cutoff_dt}")

df_pure_train = df_sorted.iloc[:split_cutoff_idx]
df_pure_test  = df_sorted.iloc[split_cutoff_idx:]

print(f"Pure 70% Train Date Range: {df_pure_train['dt'].min()}  -->  {df_pure_train['dt'].max()}")
print(f"Pure 30% Test Date Range:  {df_pure_test['dt'].min()}  -->  {df_pure_test['dt'].max()}")

print("\nPure 30% Test Set Attack Counts (before min_test_samples fallback):")
print(df_pure_test['label'].value_counts())

from detection_model import temporal_split_with_min_test
train_idx, test_idx = temporal_split_with_min_test(df_sorted, min_test_samples=4, test_ratio=0.30)
df_split_train = df_sorted.iloc[train_idx]
df_split_test  = df_sorted.iloc[test_idx]

moved_indices = set(test_idx) - set(range(split_cutoff_idx, n_total))
print(f"\nNumber of attack events moved from train to test for min_test_samples=4: {len(moved_indices)}")
df_moved = df_sorted.iloc[list(moved_indices)]
print("Moved Attack Events:")
for idx, r in df_moved.iterrows():
    print(f"  Log ID: {r['log_id']}, Label: {r['label']:<22}, Timestamp: {r['dt']}")
