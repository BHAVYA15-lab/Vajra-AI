import sys, os
sys.path.insert(0, 'models')
sys.path.insert(0, 'explainability')
sys.path.insert(0, 'utils')
import numpy as np
import pandas as pd
import pickle
import joblib
import torch
from detection_model import FeatureEngineer, temporal_split_with_min_test, PyTorchLSTMAutoencoder

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
y_true = np.array([1 if l in ATTACK_LABELS else 0 for l in test_labels])
n_attacks = int(y_true.sum())
print(f"True attacks in test: {n_attacks}")
print(f"Total test events: {len(df_test)}")
print()

X = scaler.transform(df_test_feat[FEATURE_COLS].values)
raw_dec = if_model.decision_function(X)

print("--- IF Threshold Scan ---")
header = f"{'Threshold':>12} {'Flagged':>8} {'TP':>5} {'FP':>6} {'Recall':>8} {'Prec':>8}"
print(header)
for thresh in [0.20, 0.10, 0.05, 0.02, 0.0, -0.02, -0.05, -0.10]:
    preds = (raw_dec < thresh).astype(int)
    tp = int(np.sum((preds==1) & (y_true==1)))
    fp = int(np.sum((preds==1) & (y_true==0)))
    rec  = tp/n_attacks
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    print(f"  dec < {thresh:>6.2f}   {int(preds.sum()):>8} {tp:>5} {fp:>6} {rec:>8.4f} {prec:>8.4f}")

print()
attack_scores = raw_dec[y_true==1]
normal_scores = raw_dec[y_true==0]
print("--- Decision function distribution for TRUE ATTACKS ---")
print(f"  min={attack_scores.min():.4f}  p25={np.percentile(attack_scores,25):.4f}  median={np.median(attack_scores):.4f}  p75={np.percentile(attack_scores,75):.4f}  max={attack_scores.max():.4f}")
print("--- Decision function distribution for NORMAL events ---")
print(f"  min={normal_scores.min():.4f}  p25={np.percentile(normal_scores,25):.4f}  median={np.median(normal_scores):.4f}  p75={np.percentile(normal_scores,75):.4f}  max={normal_scores.max():.4f}")

print()
print("--- Label distribution in test set ---")
for lab, cnt in pd.Series(test_labels).value_counts().items():
    is_attack = lab in ATTACK_LABELS
    print(f"  {'[ATTACK]' if is_attack else '[benign]'}  {lab:<30} {cnt}")

# NOW: LSTM stage — use anomaly_score threshold (higher = more anomalous)
# The dashboard uses raw_anom_score = max(0, -decision_function)
# Use a looser Stage 1 to pass more to LSTM for confirmation
# Use the same LSTM model from detection_model.py evaluate_and_compare pattern

print()
print("=== RUNNING FULL CASCADE WITH RISK-SCORE THRESHOLD ===")

# Stage 1: use raw anomaly scores > 0.10 as suspicious (corresponds to dec < -0.10)
# This is the actual dashboard threshold from data_loader.py line:
#   raw_anom_scores = np.maximum(0.0, -raw_dec)
# Suspicious = sent to LSTM: raw_anom_score > 0 (i.e. dec < 0)
for s1_thresh in [0.0, 0.02, 0.05, 0.10]:
    anom_score = np.maximum(0.0, -raw_dec)
    s1_mask = anom_score > s1_thresh
    s1_preds = s1_mask.astype(int)
    s1_tp = int(np.sum(s1_mask & (y_true==1)))
    s1_fp = int(np.sum(s1_mask & (y_true==0)))
    s1_rec = s1_tp / n_attacks
    s1_prec = s1_tp/(s1_tp+s1_fp) if (s1_tp+s1_fp)>0 else 0
    print(f"  [S1] anom_score>{s1_thresh:.2f}: flagged={int(s1_mask.sum()):,}  TP={s1_tp}  FP={s1_fp}  Recall={s1_rec:.4f}  Prec={s1_prec:.4f}")

# Now run LSTM on ALL positive anom_score rows (dec_fn < 0)
print()
print("Running LSTM autoencoder on IF-flagged candidates...")
anom_score = np.maximum(0.0, -raw_dec)
s1_candidates_mask = anom_score > 0.0
s1_candidates_idx = np.where(s1_candidates_mask)[0]
print(f"  Stage 1 candidates (anom>0): {len(s1_candidates_idx)}")

# Load LSTM
INPUT_DIM = len(FEATURE_COLS)
HIDDEN_DIM = 64
NUM_LAYERS = 2
K = 5

model = PyTorchLSTMAutoencoder(input_dim=INPUT_DIM, hidden_dim=16)
model.load_state_dict(torch.load('models/saved/lstm_autoencoder.pt', map_location='cpu'))
model.eval()

def build_sequences(X_all, indices, window_size=5):
    seqs = []
    for i in indices:
        start = max(0, i - window_size + 1)
        seg = X_all[start:i+1]
        if len(seg) < window_size:
            seg = np.vstack([np.zeros((window_size - len(seg), seg.shape[1])), seg])
        seqs.append(seg)
    return np.array(seqs, dtype='float32')

print("  Building LSTM sequences for candidates...")
seqs_cand = build_sequences(X, s1_candidates_idx, K)
with torch.no_grad():
    recon_cand = model(torch.tensor(seqs_cand)).numpy()
lstm_errors_cand = np.mean((seqs_cand - recon_cand)**2, axis=(1,2))

# Normal baseline threshold
normal_idx = np.where(test_labels == 'normal')[0]
print(f"  Building LSTM sequences for {len(normal_idx)} normal events to get threshold...")
seqs_norm = build_sequences(X, normal_idx, K)
with torch.no_grad():
    recon_norm = model(torch.tensor(seqs_norm)).numpy()
lstm_errors_norm = np.mean((seqs_norm - recon_norm)**2, axis=(1,2))
lstm_thresh_985 = np.percentile(lstm_errors_norm, 98.5)
lstm_thresh_95  = np.percentile(lstm_errors_norm, 95.0)
lstm_thresh_90  = np.percentile(lstm_errors_norm, 90.0)
print(f"  LSTM error thresholds: 90p={lstm_thresh_90:.6f}  95p={lstm_thresh_95:.6f}  98.5p={lstm_thresh_985:.6f}")

print()
print("=== END-TO-END CASCADE METRICS (varying LSTM threshold) ===")
for pct, thr in [("90p", lstm_thresh_90), ("95p", lstm_thresh_95), ("98.5p", lstm_thresh_985)]:
    s2_local = (lstm_errors_cand > thr).astype(int)
    final_preds = np.zeros(len(df_test), dtype=int)
    final_preds[s1_candidates_idx] = s2_local
    tp = int(np.sum((final_preds==1) & (y_true==1)))
    fp = int(np.sum((final_preds==1) & (y_true==0)))
    fn = int(np.sum((final_preds==0) & (y_true==1)))
    rec  = tp/n_attacks
    prec = tp/(tp+fp) if (tp+fp)>0 else 0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0
    print(f"  LSTM thresh {pct}: alerts={int(final_preds.sum()):,}  TP={tp}  FP={fp}  FN={fn}  Recall={rec:.4f}  Prec={prec:.4f}  F1={f1:.4f}")

# Per-category breakdown using 98.5p threshold
print()
print("=== PER-CATEGORY END-TO-END RECALL (LSTM 98.5p threshold) ===")
s2_local_985 = (lstm_errors_cand > lstm_thresh_985).astype(int)
final_985 = np.zeros(len(df_test), dtype=int)
final_985[s1_candidates_idx] = s2_local_985
for cat in ATTACK_LABELS + ['insider_drift']:
    cat_mask = (test_labels == cat)
    n_cat = int(cat_mask.sum())
    if n_cat == 0:
        continue
    s1_tp = int(np.sum((s1_candidates_mask) & cat_mask))
    e2e_tp = int(np.sum((final_985==1) & cat_mask))
    s1_rec = s1_tp/n_cat
    e2e_rec = e2e_tp/n_cat
    tag = "[ATTACK]" if cat in ATTACK_LABELS else "[benign]"
    print(f"  {tag}  {cat:<28} N={n_cat:<4}  S1-Rec={s1_rec:.2f}  E2E-Rec={e2e_rec:.2f}")
