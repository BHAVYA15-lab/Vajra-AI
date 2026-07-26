# Vajra AI — Cascaded Behavioral Threat Detection & Response
## Benchmark Limitation & Synthetic Evaluation Note

> [!WARNING]
> **Synthetic Benchmark Separability Notice**:
> In the evaluation of anomaly detection and classification models on this synthetic dataset, certain attack categories achieve **100% recall** or near-perfect precision/recall. 
> 
> - **Synthetic Separability by Construction**: This performance reflects that synthetic anomaly injection patterns (e.g. abrupt geographic velocity jumps, rapid password failure bursts, distinct fan-out counts, or unseen command sequences) are cleanly separable from normal baseline behavior by design.
> - **Real-World Generalization Caveat**: High metric scores on this synthetic dataset **DO NOT PROVE** that the models would achieve equal performance against subtler, evasive real-world zero-day attacks or stealthy insiders.
> - **Deterministic Physics vs ML Separation**: `impossible_travel` is evaluated via a deterministic physics rule (speed limit check $V > 900 \text{ km/h}$), achieving 100% detection accuracy (4/4 test events) with zero false negatives. It is evaluated separately from the ML multi-class Random Forest. All synthetic `impossible_travel` test events exhibited velocities far above the 900 km/h threshold (range: 50,067–430,115 km/h), reflecting clearly injected anomalies rather than borderline cases. The rule's behavior in the realistic borderline range (approximately 900–5,000 km/h, consistent with long-haul international flights with layovers) has not been empirically tested against this synthetic dataset. The 900 km/h threshold itself is set at commercial flight speed and would need tuning against real-world travel pattern data before production deployment to avoid false positives on legitimate fast international travel.

- **Statistical Reliability of Low-Sample ML Categories**: ML-classified categories with small sample counts under the temporal split (`device_spoofing` $N=5$, `brute_force` $N=4$, `credential_stuffing` $N=4$, `low_slow_exfiltration` $N=4$) carry high metric variance. Per-class metrics for these low-support classes must be interpreted as diagnostic indicators rather than statistically reliable production guarantees.
