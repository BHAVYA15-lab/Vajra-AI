import os
import sys
import joblib
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, precision_score, recall_score, f1_score

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from baseline_profile import EntityBaselineProfiler
from detection_model import FeatureEngineer, temporal_split_with_min_test

# ==============================================================================
# TEMPORAL TRAIN/TEST SPLIT MANDATE (CONCEPT DRIFT INTEGRITY)
# ==============================================================================
# The dataset is split strictly by timestamp (Training = Days 1-21, Testing = Days 22-30).
# Random splits leak future behavioral context into past training windows.
# A true concept-drift detection system must train exclusively on past logs and
# evaluate on future logs.
# ==============================================================================

class AttackClassifier:
    """
    Multi-class Random Forest classifier trained on the 9-feature baseline deviation matrix
    to categorize detected security anomalies into specific threat types.
    Uses class_weight='balanced' to mitigate majority-class bias (e.g. brute_force dominating rare classes).
    """

    def __init__(self, random_state=42):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            class_weight="balanced", # Balanced class weights to reduce majority-class bias
            random_state=random_state,
            n_jobs=-1
        )
        self.classes_ = None

    def fit(self, X_train, y_train):
        """Fits the multi-class Random Forest on anomaly feature vectors."""
        self.model.fit(X_train, y_train)
        self.classes_ = self.model.classes_

    def predict(self, X):
        """Predicts attack category labels."""
        return self.model.predict(X)

    def predict_proba(self, X):
        """Predicts class probability distributions."""
        return self.model.predict_proba(X)


def train_and_evaluate_classifier():
    """Trains and evaluates the multi-class attack classifier on a strict temporal train/test split."""
    print("[+] Loading access logs and ground truth labels...")
    df_logs = pd.read_csv("data/access_logs.csv")
    df_labels = pd.read_csv("data/ground_truth_labels.csv")
    df_merged = df_logs.merge(df_labels, on="log_id")

    # Strict Temporal Train/Test Split (Days 1-21 Train, Days 22-30 Test)
    train_idx, test_idx = temporal_split_with_min_test(df_merged, min_test_samples=4, test_ratio=0.30)
    df_train = df_merged.iloc[train_idx].reset_index(drop=True)
    df_test = df_merged.iloc[test_idx].reset_index(drop=True)

    print(f"\n[+] Strict Temporal Dataset Split Summary:")
    print(f"    - Training set: {len(df_train):,} rows (Chronologically Earlier)")
    print(f"    - Test set:     {len(df_test):,} rows (Chronologically Later)")

    profiler = EntityBaselineProfiler(cold_start_threshold=5, decay_alpha=0.05)
    profiler.fit(df_train)

    fe = FeatureEngineer(profiler)
    df_train_feat = fe.extract_features(df_train)
    df_test_feat = fe.extract_features(df_test)

    feature_cols = [
        "geo_distance_km", "time_of_day_zscore", "resource_novelty",
        "session_duration_zscore", "auth_failure_rate_trailing",
        "source_ip_entity_fanout", "command_sequence_novelty",
        "fingerprint_mismatch", "is_cold_start"
    ]

    # Filter for true attack anomalies only (excluding normal & insider_drift)
    attack_labels = ["brute_force", "credential_stuffing", "device_spoofing", "impossible_travel", "lateral_movement", "low_slow_exfiltration"]
    
    train_attack_mask = df_train["label"].isin(attack_labels)
    test_attack_mask = df_test["label"].isin(attack_labels)

    X_train = df_train_feat.loc[train_attack_mask, feature_cols].values
    y_train = df_train.loc[train_attack_mask, "label"].values

    X_test = df_test_feat.loc[test_attack_mask, feature_cols].values
    y_test = df_test.loc[test_attack_mask, "label"].values

    # Train Classifier with class_weight='balanced'
    clf = AttackClassifier()
    clf.fit(X_train, y_train)

    # Predict on Test Set
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    print("\n====================================================================================================")
    print("=== BALANCED MULTI-CLASS ATTACK CLASSIFIER REPORT (TEMPORAL TRAIN/TEST SPLIT) ===")
    print("====================================================================================================\n")

    labels_present = sorted(list(set(y_test)))
    
    print(f"{'Attack Category':<22} | {'Train N':<8} | {'Test N':<7} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Support Status':<18}")
    print("-" * 98)

    for lab in labels_present:
        mask = (y_test == lab)
        n_test_cat = np.sum(mask)
        n_train_cat = np.sum(y_train == lab)
        
        y_true_cat = (y_test == lab).astype(int)
        y_pred_cat = (y_pred == lab).astype(int)
        
        prec = precision_score(y_true_cat, y_pred_cat, zero_division=0)
        rec = recall_score(y_true_cat, y_pred_cat, zero_division=0)
        f1 = f1_score(y_true_cat, y_pred_cat, zero_division=0)
        
        status = "WELL-SUPPORTED" if n_test_cat >= 20 else "LOW-SAMPLE CAVEAT"
        print(f"{lab:<22} | {n_train_cat:<8} | {n_test_cat:<7} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {status:<18}")

    print("=" * 98)
    
    print("\n=== CONFUSION MATRIX (TEMPORAL EVALUATION) ===")
    cm = confusion_matrix(y_test, y_pred, labels=labels_present)
    cm_df = pd.DataFrame(cm, index=[f"True:{l}" for l in labels_present], columns=[f"Pred:{l}" for l in labels_present])
    print(cm_df)

    save_dir = "models/saved"
    os.makedirs(save_dir, exist_ok=True)
    joblib.dump(clf.model, os.path.join(save_dir, "attack_classifier.joblib"))
    print(f"\n[+] Saved balanced attack classifier to '{save_dir}/attack_classifier.joblib'.")


if __name__ == "__main__":
    train_and_evaluate_classifier()
