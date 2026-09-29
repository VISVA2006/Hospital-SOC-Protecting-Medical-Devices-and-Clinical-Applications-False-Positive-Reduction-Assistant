# Deep Error & Boundary Stress Analysis Report

## 1. Executive Summary

- **Evaluated Alerts:** 5,330
- **Confirmed Incidents:** 1,231
- **True Positives Detected:** 1,231 (100.00% Threat Recall)
- **False Negatives (Missed Threats):** **0** (Missed Incident Rate: 0.00%)
- **Benign Alerts Safely Suppressed:** 3,334 (62.55% Workload Reduction)
- **Benign Alerts Routed to Review (FP Burden):** 765 (18.66% of benign alerts)

## 2. False Positive Burden by Device Type

| Medical Device Type | Reviewed Benign Alerts | Clinical Rationale |
| :--- | :---: | :--- |
| Ventilator | 254 | Protected by clinical safety guardrail to ensure patient device safety |
| Infusion Pump | 147 | Protected by clinical safety guardrail to ensure patient device safety |
| Patient Monitor | 95 | Protected by clinical safety guardrail to ensure patient device safety |
| Nurse Station Workstation | 88 | Protected by clinical safety guardrail to ensure patient device safety |
| CT Scanner | 59 | Protected by clinical safety guardrail to ensure patient device safety |
| MRI Scanner | 36 | Protected by clinical safety guardrail to ensure patient device safety |
| ECG Machine | 36 | Protected by clinical safety guardrail to ensure patient device safety |
| Laboratory Analyzer | 33 | Protected by clinical safety guardrail to ensure patient device safety |

## 3. Boundary Condition Analysis (Threat Probability 0.30 - 0.70)

- Total Boundary Alerts: **387**
- Routed to Human Review: **387 / 387 (100.0%)**
- **Finding:** In uncertain probability zones, the assistant reliably routes alerts to human analysts rather than attempting unsafe automated closure.

## 4. Critical Medical Device Edge-Case Invariant Verification

| Case ID | Scenario Name | Device | ML Threat Prob | Anomaly Score | Recommendation | Safety Invariant Held? |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: |
| EDGE-CRIT-01 | Ventilator + Unusual Destination IP | Ventilator | 0.1879 | 0.2877 | `REVIEW` | ✅ HELD |
| EDGE-CRIT-02 | Ventilator + Unusual Port (4444) | Ventilator | 0.0002 | 0.2271 | `LIKELY_FALSE_POSITIVE` | ❌ VIOLATED |
| EDGE-CRIT-03 | Ventilator + Off-Hours Communication | Ventilator | 0.0012 | 0.2328 | `REVIEW` | ✅ HELD |
| EDGE-CRIT-04 | Infusion Pump + Unusual IP | Infusion Pump | 0.0269 | 0.3092 | `REVIEW` | ✅ HELD |
| EDGE-CRIT-05 | Infusion Pump + Unusual Port (8443) | Infusion Pump | 0.0 | 0.2965 | `LIKELY_FALSE_POSITIVE` | ❌ VIOLATED |
| EDGE-CRIT-06 | Patient Monitor + Unusual Communication | Patient Monitor | 0.0369 | 0.4076 | `REVIEW` | ✅ HELD |
| EDGE-CRIT-07 | Critical Asset + Low-Risk Baseline Spoofing | Ventilator | 0.0003 | 0.2616 | `REVIEW` | ✅ HELD |
