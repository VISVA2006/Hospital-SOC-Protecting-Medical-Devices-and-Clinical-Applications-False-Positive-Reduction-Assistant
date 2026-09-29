# Continuous Learning & Anti-Catastrophic Forgetting

## 1. The Catastrophic Forgetting Problem in SOC ML

When machine learning models are continuously retrained strictly on recent analyst feedback, they suffer from **catastrophic forgetting**:
- As analysts investigate and label new attack types or newly approved scanner IPs, the model updates its decision weights.
- Without memory replay, the model rapidly "forgets" foundational security baselines and historical incident signatures learned during initial training.
- Result: Previously suppressed benign alerts resurface as false positives, or historical attack patterns become misclassified as benign.

---

## 2. Experience Replay Architecture (80/20 Balance)

To eliminate catastrophic forgetting, the Hospital SOC Assistant implements an **Experience Replay Buffer**:
- **80% Historical Baseline:** Stratified sample of 480 verified historical alert records preserving broad operational envelopes.
- **20% Validated Feedback:** Up to 120 high-quality, schema-validated analyst feedback decisions reflecting recent operational shifts.
- **Total Replay Dataset:** 600 balanced records.

---

## 3. Feedback Data Validation Gate (`src/feedback_validation.py`)

Analyst feedback is untrusted until formally validated:
1. **Minimum Volume Check:** Retraining is blocked until at least **50 validated feedback records** accumulate.
2. **Deduplication:** Repeated dispositions on the same alert ID are collapsed to the latest entry.
3. **Schema Compliance:** Dispositions must match recognized enums (`CONFIRM_FALSE_POSITIVE`, `CONFIRM_TRUE_THREAT`, `FALSE_POSITIVE`, `TRUE_POSITIVE`, etc.).
4. **Override Justification:** Analyst overrides require a mandatory rationale tag for audit traceability.

---

## 4. Promotion Safety Gates (`src/model_registry.py`)

A retrained model is initially registered strictly as a `CANDIDATE`. It is only eligible for promotion to `CHAMPION` if it satisfies all three safety gates:
1. **Gate 1 (Threat Recall):** Must achieve $\ge 98.0\%$ recall on confirmed incidents.
2. **Gate 2 (Critical Device Recall):** Must achieve **100% recall** on critical care medical devices.
3. **Gate 3 (Precision Retention):** Triage precision must not degrade by more than 2% relative to the active champion.
