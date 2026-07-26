# Vajra AI — Cascaded Behavioral Threat Detection & Response
## Benchmark Limitation & Synthetic Evaluation Note

> [!WARNING]
> **Synthetic Benchmark Separability Notice**:
> In the evaluation of anomaly detection and classification models on this synthetic dataset, certain attack categories achieve **100% recall** or near-perfect precision/recall. 
> 
> - **Synthetic Separability by Construction**: This performance reflects that synthetic anomaly injection patterns (e.g. abrupt geographic velocity jumps, rapid password failure bursts, distinct fan-out counts, or unseen command sequences) are cleanly separable from normal baseline behavior by design.
> - **Real-World Generalization Caveat**: High metric scores on this synthetic dataset **DO NOT PROVE** that the models would achieve equal performance against subtler, evasive real-world zero-day attacks or stealthy insiders.
> - **Statistical Reliability of Low-Sample Categories**: Categories with small sample counts (e.g. `impossible_travel` with 8 total rows, `credential_stuffing` with 40 rows, `low_slow_exfiltration` with 40 rows) carry high metric variance. Per-class metrics for these low-support classes must be interpreted as diagnostic indicators rather than statistically reliable production performance guarantees.
