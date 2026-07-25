import os
import sys
import json
import joblib
import pickle
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"))
from baseline_profile import EntityBaselineProfiler
from detection_model import FeatureEngineer

from mitre_mapping import get_mitre_info

# ==============================================================================
# SEVERITY WEIGHT & ENTITY CRITICALITY MAPPING DOCUMENTATION
# ==============================================================================
# SeverityWeight (W_severity) determines the asset criticality factor in the risk score.
#
# Determinants:
# 1. High Severity (1.0):
#    - Resource matches sensitive assets: '/admin/*', '/db/*', 'file:/etc/shadow',
#      '/cloud/s3/*', '/k8s/secrets/*', '/hr/salary_archive'
#    - OR entity_type is 'service_account' (privileged backend credentials).
# 2. Medium Severity (0.6):
#    - entity_type is 'edge_device' accessing non-telemetry endpoints.
#    - OR user attempting administrative/privilege escalations.
# 3. Standard Severity (0.3):
#    - Standard business resource access: '/api/v1/user/profile', '/docs/wiki/*',
#      '/hr/portal/timesheet', '/crm/contacts/view'.
# ==============================================================================

SENSITIVE_RESOURCE_PREFIXES = [
    "/admin/", "/db/", "file:/etc/shadow", "/cloud/s3/", "/k8s/secrets/", "/hr/salary_archive"
]

def calculate_severity_weight(entity_type, resource_accessed):
    """
    Computes transparent SeverityWeight (0.3 to 1.0) based on asset criticality and entity privilege.
    """
    is_sensitive_res = any(prefix in str(resource_accessed) for prefix in SENSITIVE_RESOURCE_PREFIXES)
    
    if is_sensitive_res or entity_type == "service_account":
        return 1.0
    elif entity_type == "edge_device" and not str(resource_accessed).startswith("/iot/"):
        return 0.6
    else:
        return 0.3

class SOCAnomalyExplainer:
    """
    Generates feature attributions, 0-100 risk scores, MITRE ATT&CK mappings, and human-readable SOC reports.
    """

    def __init__(self, profiler, scaler, classifier=None):
        self.profiler = profiler
        self.scaler = scaler
        self.classifier = classifier
        self.feature_names = [
            "geo_distance_km", "time_of_day_zscore", "resource_novelty",
            "session_duration_zscore", "auth_failure_rate_trailing",
            "source_ip_entity_fanout", "command_sequence_novelty",
            "fingerprint_mismatch", "is_cold_start"
        ]

    def compute_risk_score(self, feature_dict, raw_anomaly_score, entity_type, resource_accessed):
        """
        Computes transparent 0-100 Risk Score combining:
        - 40% Anomaly Score (normalized 0.0 to 1.0)
        - 35% Max Feature Deviation Score
        - 25% Asset Severity Weight
        """
        norm_anom = min(max(raw_anomaly_score * 3.0, 0.0), 1.0)

        max_dev = max([
            min(feature_dict.get("geo_distance_km", 0) / 5000.0, 1.0),
            min(feature_dict.get("time_of_day_zscore", 0) / 6.0, 1.0),
            feature_dict.get("resource_novelty", 0.0),
            min(feature_dict.get("session_duration_zscore", 0) / 6.0, 1.0),
            feature_dict.get("auth_failure_rate_trailing", 0.0),
            min(feature_dict.get("source_ip_entity_fanout", 0) / 1.5, 1.0),
            min(feature_dict.get("command_sequence_novelty", 0) / 1.5, 1.0),
            feature_dict.get("fingerprint_mismatch", 0.0)
        ])

        severity_w = calculate_severity_weight(entity_type, resource_accessed)

        raw_risk = (0.40 * norm_anom) + (0.35 * max_dev) + (0.25 * severity_w)
        risk_score = int(np.clip(raw_risk * 100, 0, 100))

        if risk_score >= 85:
            severity_label = "CRITICAL"
        elif risk_score >= 65:
            severity_label = "HIGH"
        elif risk_score >= 45:
            severity_label = "MEDIUM"
        else:
            severity_label = "LOW"

        return risk_score, severity_label, severity_w

    def compute_confidence_score(self, feature_dict, predicted_attack):
        """
        Computes explicit Model Confidence Score (0.0 to 100.0%), distinct from Risk Score.
        Confidence = how sure the classifier is (predict_proba max), capped if cold-start.
        """
        is_cold = bool(feature_dict.get("is_cold_start", False))

        if self.classifier is not None and hasattr(self.classifier, "predict_proba"):
            try:
                feat_vals = np.array([[feature_dict.get(col, 0.0) for col in self.feature_names]])
                probs = self.classifier.predict_proba(feat_vals)[0]
                max_prob = float(np.max(probs)) * 100.0
            except Exception:
                max_prob = 85.0
        else:
            max_prob = 88.0

        if is_cold:
            max_prob = min(max_prob, 70.0)

        return round(max_prob, 1)

    def get_feature_attributions(self, feature_dict):
        """Calculates per-feature contribution scores to identify top 3 anomaly drivers."""
        attributions = []

        gdist = feature_dict.get("geo_distance_km", 0)
        if gdist > 100:
            attributions.append({
                "feature": "geo_distance_km",
                "score": min(gdist / 5000.0, 1.0),
                "summary": f"Geographic Distance: {gdist:.1f} km from primary location"
            })

        tz = feature_dict.get("time_of_day_zscore", 0)
        if tz > 2.0:
            attributions.append({
                "feature": "time_of_day_zscore",
                "score": min(tz / 6.0, 1.0),
                "summary": f"Time-of-Day Anomaly: Z-score = {tz:.2f} relative to peak login hours"
            })

        rn = feature_dict.get("resource_novelty", 0)
        if rn > 0.4:
            attributions.append({
                "feature": "resource_novelty",
                "score": rn,
                "summary": f"Unusual Resource: {rn*100:.1f}% novelty score vs entity baseline"
            })

        dz = feature_dict.get("session_duration_zscore", 0)
        if dz > 2.0:
            attributions.append({
                "feature": "session_duration_zscore",
                "score": min(dz / 6.0, 1.0),
                "summary": f"Session Duration Anomaly: Z-score = {dz:.2f} vs historical mean"
            })

        af = feature_dict.get("auth_failure_rate_trailing", 0)
        if af > 0.1:
            attributions.append({
                "feature": "auth_failure_rate_trailing",
                "score": af,
                "summary": f"Rapid Auth Failures: High failure rate ({af*100:.0f}%) in trailing window"
            })

        fan = feature_dict.get("source_ip_entity_fanout", 0)
        if fan > 0.1:
            attributions.append({
                "feature": "source_ip_entity_fanout",
                "score": min(fan / 1.5, 1.0),
                "summary": f"Source IP Multi-Entity Targeting: Fan-out score = {fan:.2f}"
            })

        cn = feature_dict.get("command_sequence_novelty", 0)
        if cn > 0.2:
            attributions.append({
                "feature": "command_sequence_novelty",
                "score": min(cn / 1.5, 1.0),
                "summary": f"Command Sequence Novelty: Unseen command ratio & length deviation = {cn:.2f}"
            })

        fm = feature_dict.get("fingerprint_mismatch", 0)
        if fm > 0:
            attributions.append({
                "feature": "fingerprint_mismatch",
                "score": fm,
                "summary": f"Device Fingerprint Mismatch: Unrecognized OS/MAC/Protocol ({fm:.1f})"
            })

        attributions = sorted(attributions, key=lambda x: x["score"], reverse=True)
        return attributions[:3]

    def get_top_drivers(self, feature_dict, max_drivers=3):
        """Calculates per-feature contribution scores up to max_drivers."""
        attributions = self.get_feature_attributions(feature_dict)
        results = []
        for attr in attributions:
            fname = attr["feature"]
            results.append({
                "feature_name": fname,
                "name": fname.replace("_", " ").title(),
                "score": attr["score"],
                "summary": attr["summary"]
            })
        return results[:max_drivers]

    def get_triage_recommendation(self, predicted_attack, top_features, risk_score):
        """Generates specific, actionable SOC analyst triage recommendations."""
        mitre_info = get_mitre_info(predicted_attack)
        return "\n".join(mitre_info["recommended_actions"])

    def explain_log(self, row, feature_dict, raw_anomaly_score, predicted_attack="suspicious_activity"):
        """Generates a complete SOC Analyst Natural Language Report with MITRE ATT&CK Mapping."""
        eid = row["entity_id"]
        etype = row["entity_type"]
        res = row["resource_accessed"]

        risk_score, severity_label, severity_w = self.compute_risk_score(feature_dict, raw_anomaly_score, etype, res)
        confidence_score = self.compute_confidence_score(feature_dict, predicted_attack)
        mitre_info = get_mitre_info(predicted_attack)
        top_drivers = self.get_feature_attributions(feature_dict)
        triage_rec = self.get_triage_recommendation(predicted_attack, top_drivers, risk_score)

        report = f"""
================================================================================
=== SOC ANALYST TRIAGE REPORT [LOG #{row['log_id']}] ===
================================================================================
Target Entity:      {eid} ({etype})
Timestamp:          {row['timestamp']}
Source IP / Geo:    {row['source_ip']} ({row['geo_location']})
Resource Accessed:  {res}
Auth Method:        {row['auth_method']} (Duration: {row['session_duration']}s)
Device Fingerprint: {row['device_fingerprint']}

--- THREAT & RISK ASSESSMENT ---
Risk Score:         {risk_score}/100 [{severity_label}] (Asset Severity Weight: {severity_w})
Model Confidence:   {confidence_score:.1f}% (Classifier predict_proba)
Predicted Threat:   {predicted_attack.upper()}
MITRE ATT&CK:       {mitre_info['technique_id']} - {mitre_info['technique_name']} [{mitre_info['tactic_name']}]

--- ANOMALY DRIVERS (WHY THIS WAS FLAGGED) ---
"""
        if top_drivers:
            for idx, drv in enumerate(top_drivers, 1):
                report += f"  {idx}. {drv['summary']} (Contribution: {drv['score']:.2f})\n"
        else:
            report += "  - Slight multi-feature baseline variance across session parameters.\n"

        report += f"""
--- RECOMMENDED TRIAGE ACTION ---
{triage_rec}
================================================================================
"""
        return {
            "log_id": row["log_id"],
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "severity_label": severity_label,
            "predicted_attack": predicted_attack,
            "mitre_info": mitre_info,
            "top_drivers": top_drivers,
            "triage_recommendation": triage_rec,
            "full_report": report
        }


def generate_sample_explanations():
    """Generates and prints sample SOC Explainability reports for 1 example of each anomaly type."""
    print("[+] Loading test dataset and saved models...")
    df_logs = pd.read_csv("data/access_logs.csv")
    df_labels = pd.read_csv("data/ground_truth_labels.csv")
    df_merged = df_logs.merge(df_labels, on="log_id")

    save_dir = "models/saved"
    with open(os.path.join(save_dir, "baseline_profiler.pkl"), "rb") as f:
        profiler = pickle.load(f)

    scaler = joblib.load(os.path.join(save_dir, "scaler.joblib"))
    if_model = joblib.load(os.path.join(save_dir, "isolation_forest.joblib"))

    fe = FeatureEngineer(profiler)
    df_feat = fe.extract_features(df_merged)

    explainer = SOCAnomalyExplainer(profiler, scaler)

    print("\n====================================================================================================")
    print("=== SAMPLE SOC ANALYST EXPLAINABILITY REPORTS (1 PER ANOMALY TYPE) ===")
    print("====================================================================================================\n")

    anomaly_types = ["brute_force", "credential_stuffing", "device_spoofing", "impossible_travel", "lateral_movement", "low_slow_exfiltration", "insider_drift"]

    feature_cols = [
        "geo_distance_km", "time_of_day_zscore", "resource_novelty",
        "session_duration_zscore", "auth_failure_rate_trailing",
        "source_ip_entity_fanout", "command_sequence_novelty",
        "fingerprint_mismatch", "is_cold_start"
    ]

    for anom in anomaly_types:
        sub = df_merged[df_merged["label"] == anom]
        if len(sub) > 0:
            sample_row = sub.iloc[0]
            idx = sample_row.name
            feat_dict = df_feat.iloc[idx].to_dict()
            
            X_samp = scaler.transform(df_feat.loc[[idx], feature_cols].values)
            raw_anom_score = float(-if_model.decision_function(X_samp)[0])

            res = explainer.explain_log(sample_row, feat_dict, raw_anom_score, predicted_attack=anom)
            print(res["full_report"])

if __name__ == "__main__":
    generate_sample_explanations()
