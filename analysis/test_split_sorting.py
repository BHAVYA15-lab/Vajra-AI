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

df_logs   = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'access_logs.csv'))
df_labels = pd.read_csv(os.path.join(PROJECT_ROOT, 'data', 'ground_truth_labels.csv'))
df_merged = df_logs.merge(df_labels, on='log_id')

df_merged['dt'] = pd.to_datetime(df_merged['timestamp'])

print("Initial df_merged date order check:")
print(f"Is df_merged monotonically increasing in dt? {df_merged['dt'].is_monotonic_increasing}")

df_presorted = df_merged.sort_values('dt').reset_index(drop=True)
print(f"Is df_presorted monotonically increasing in dt? {df_presorted['dt'].is_monotonic_increasing}")

from detection_model import temporal_split_with_min_test

train_idx, test_idx = temporal_split_with_min_test(df_presorted, min_test_samples=4, test_ratio=0.30)
df_train = df_presorted.iloc[train_idx]
df_test  = df_presorted.iloc[test_idx]

print("\n--- Presorted Dataframe Split Output ---")
print(f"Train Rows: {len(df_train):,}  ({len(df_train)/len(df_presorted)*100:.2f}%)")
print(f"Test Rows:  {len(df_test):,}  ({len(df_test)/len(df_presorted)*100:.2f}%)")
print(f"Train dt min -> max: {df_train['dt'].min()}  -->  {df_train['dt'].max()}")
print(f"Test dt min -> max:  {df_test['dt'].min()}  -->  {df_test['dt'].max()}")
