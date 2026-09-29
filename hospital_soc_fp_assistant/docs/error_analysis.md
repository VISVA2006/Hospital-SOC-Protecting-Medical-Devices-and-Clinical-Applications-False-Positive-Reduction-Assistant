# Deep Error Analysis & Clinical Decision Boundary Methodology

## 1. Objective

The objective of deep error analysis in the Hospital SOC Assistant is to evaluate model behavior not simply through aggregate classification metrics, but through **granular medical risk decomposition**. 

In high-consequence healthcare settings, errors are asymmetric:
- **False Positive (Type I Error):** A benign alert is sent to an analyst for review. Cost: 8 minutes of analyst time.
- **False Negative (Type II Error):** A genuine cyberattack targeting a clinical device is suppressed. Cost: Potential patient injury, operational stoppage, or regulatory non-compliance.

---

## 2. Experimental Setup

The evaluation was executed on the complete, audited dataset of **5,330 hospital security alerts**:
- **Confirmed Security Incidents:** 1,231
- **Benign / False Positive Alerts:** 4,099
- **Operating Parameters:** Threat Probability Cutoff = 0.40, Anomaly Score Cutoff = 0.65.

---

## 3. Granular Error Decomposition

### 3.1 Zero False-Negative Verification
Across all 1,231 confirmed incidents in the dataset:
- **Detected Incidents:** 1,231
- **Missed Incidents:** 0
- **False Negative Rate:** 0.00%
- **Finding:** Under the configured clinical guardrail policies, zero genuine threats were auto-suppressed.

### 3.2 False Positive Burden by Medical Device
The 765 benign alerts routed to human review (the "FP burden") were inspected by asset category:
1. **Infusion Pumps:** Protected by Invariant 4 due to clinical criticality.
2. **ICU Patient Monitors:** Protected by Invariant 4 due to telemetry deviations.
3. **PACS Servers:** Routed due to burst data volumes triggering borderline probabilities.
4. **Nurse Station Workstations:** Routed due to authentication retry spikes.
5. **Ventilators:** 100% routed by Invariant 1 / Invariant 4 policy.

### 3.3 Boundary Probability Stress-Testing (0.35 - 0.50)
For alerts falling in the region of model uncertainty (threat probability between 0.35 and 0.50):
- Total Boundary Alerts: 765
- Routed to Human Review: 765 (100.0%)
- **Policy Invariant:** In the presence of statistical ambiguity, the system defaults to human expertise rather than risking automated suppression.
