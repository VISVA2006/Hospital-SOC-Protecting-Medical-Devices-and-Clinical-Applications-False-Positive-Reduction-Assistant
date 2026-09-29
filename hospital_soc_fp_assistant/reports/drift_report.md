# Controlled Feature Drift Monitoring Report

> [!NOTE]
> **Disclaimer:** This analysis represents controlled synthetic drift testing simulating clinical network shifts (e.g. Wi-Fi resegmentation, credential policy updates). It does NOT claim real-world drift detection.

## 1. Feature Distribution Divergence Summary

| Feature | Baseline Mean | Drifted Mean | PSI Metric | KS Statistic | KS p-value | Drift Severity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| failed_login_count | 3.037 | 5.415 | 0.9471 | 0.4398 | 0.0 | `SIGNIFICANT` |
| latency_seconds | 115.097 | 217.235 | 2.077 | 0.6856 | 0.0 | `SIGNIFICANT` |
| historical_false_positive_rate | 0.802 | 0.682 | 6.8941 | 0.5255 | 0.0 | `SIGNIFICANT` |
| event_count | 134.372 | 134.372 | 0.0 | 0.0 | 1.0 | `NEGLIGIBLE` |
| destination_port | 2222.12 | 2222.12 | 0.0 | 0.0 | 1.0 | `NEGLIGIBLE` |

## 2. Model Performance Impact Under Drift

- **Threat Detection Recall Before Drift:** 100.00%
- **Threat Detection Recall After Drift:**  100.00%
- **Missed Incidents Before:** 0
- **Missed Incidents After:**  0
- **Alerts Sent to Human Review (Before vs After):** 1996 → 2470

### Clinical Safety Conclusion
While feature drift increased the volume of alerts requiring review (analyst burden rose as telemetry became noisier), the deterministic clinical safety guardrails successfully prevented any false negatives on patient-connected systems.
