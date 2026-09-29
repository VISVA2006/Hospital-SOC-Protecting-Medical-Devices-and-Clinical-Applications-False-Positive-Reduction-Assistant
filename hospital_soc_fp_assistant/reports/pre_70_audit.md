# Pre-70% Milestone Technical Audit Report
**Location:** `reports/pre_70_audit.md`  
**Date:** September 29, 2026  
**Auditor:** Hospital SOC AI & Safety Engineering Team  

---

## 1. Project Structure Analysis
The repository currently contains:
- **Core Pipeline Scripts (`src/`):** 9 Python files (`data_generator.py`, `preprocessing.py`, `event_processor.py`, `baseline.py`, `train_model.py`, `anomaly_detection.py`, `explainability.py`, `feedback_learning.py`, `evaluation.py`).
- **Interactive UI:** `app.py` (Streamlit 5-tab application).
- **Data Store (`data/`):** `raw_alerts.csv` (5,330 rows), `cleaned_alerts.csv` (5,330 rows), `confirmed_incidents.csv` (1,231 rows), `analyst_feedback.csv` (150 rows), `preprocessing_audit_log.json`.
- **Model Artifacts (`models/`):** `false_positive_model.joblib` (Logistic Regression pipeline), `anomaly_model.joblib` (Isolation Forest).
- **Evaluation Outputs (`results/`):** `metrics.json`, `evaluation_report.csv`, `model_comparison.json`, `test_results.csv`, and 8 chart figures in `results/figures/`.
- **Test Suite (`tests/`):** 5 test files containing 8 test functions.

---

## 2. Existing Model Pipeline & Metrics
The model training module (`src/train_model.py`) executes an 80/20 stratified split:
- **Logistic Regression (Champion):** Threat Recall = 1.0000, Missed Incidents = 0, Threat Precision = 0.8013, F1 = 0.8897, Accuracy = 0.9428.
- **Decision Tree:** Threat Recall = 0.9512, Missed Incidents = 12, Precision = 0.8211, F1 = 0.8814, Accuracy = 0.9409.
- **Random Forest:** Threat Recall = 0.9837, Missed Incidents = 4, Precision = 0.8148, F1 = 0.8913, Accuracy = 0.9447.
- **Novelty Detection:** Isolation Forest fitted with 150 estimators, contamination = 0.07. Normalized anomaly scores output between 0.00 and 1.00.

---

## 3. Test Suite Status
Running `pytest -v` confirms:
- **Total Tests:** 8
- **Passed:** 8 (100%)
- **Failed:** 0
- **Execution Time:** ~16.5 seconds

Tests accurately cover:
1. `test_delayed_critical_event`: Latency calculation for 9-minute delayed ventilator beacon.
2. `test_duplicate_flood_ten_times`: Deduplication collapsing 10 identical events to 1.
3. `test_batch_deduplication`: Batch DataFrame deduplication.
4. `test_normal_false_positive_scanner`: Verification that routine scanner traffic is marked `LIKELY_FALSE_POSITIVE`.
5. `test_real_suspicious_alert_brute_force`: PACS server SSH brute-force alert routed to `INVESTIGATE`.
6. `test_novel_medical_device_threat`: Infusion pump C2 beacon flagged by Isolation Forest.
7. `test_model_deception_adversarial_bypass`: Spoofed low-severity alert on Ventilator blocked by safety guardrail.
8. `test_out_of_order_stream_reconstruction`: Re-ordering scrambled timestamps into strict sequence.

---

## 4. Technical Debt, Duplicate Code & Unsafe Assumptions
1. **Safety Guardrail Coupling:** The clinical safety guardrail logic is hardcoded inside `MedicalDeviceNoveltyDetector.evaluate_safety_guardrails` in `src/anomaly_detection.py`. It should be an independent, configurable module (`safety_guardrail.py`) separate from anomaly detection.
2. **Absence of Centralized Configuration:** Magic numbers (e.g., anomaly threshold `0.65`, threat threshold `0.40`, review time `8.0` minutes) are duplicated across `evaluation.py`, `anomaly_detection.py`, and `app.py`. A centralized `config/config.yaml` is required.
3. **Catastrophic Forgetting in Retraining:** `FeedbackManager.retrain_with_feedback` replaces the model weights using a naive full retrain on the augmented dataset without replay buffering, validation against historical test benchmarks, or promotion gating.
4. **Single-Alert Window Limitations:** Threat evaluation occurs strictly on a single event at a time. Multi-hour low-and-slow reconnaissance or gradual port sweeps cannot be identified without a rolling-window sequence accumulator.

---

## 5. Data Leakage & Evaluation Contamination Findings
1. **Whole-Dataset Evaluation:** `src/evaluation.py` computed proposed metrics across all 5,330 rows in `cleaned_alerts.csv`, meaning 80% of the evaluation set had already been seen during training. In the 100% upgrade, out-of-sample test metrics must be evaluated and reported independently.
2. **Unsupervised Fit on Full Data:** The Isolation Forest in `train_model.py` was fit on all benign alerts across the entire dataset rather than strictly on the training partition.
3. **Synthetic Correlation Sharpness:** The synthetic generator created clean separations (e.g., known scanner IPs vs malicious external IPs, high failed login counts), which explains the 100% recall. Deep error analysis and controlled feature perturbations must be implemented to test the model under realistic degradation.

---

## 6. Preprocessing & Model Persistence Inconsistencies
- Preprocessing imputations (`src/preprocessing.py`) use hardcoded constants (e.g., missing patch status = `"Unknown"`). While safe for zero-drop operations, these should be codified into reusable transformer classes.
- Model persistence in `models/false_positive_model.joblib` and `models/anomaly_model.joblib` lacks metadata tracking (training timestamp, git hash, schema version, dataset hash). The upgrade requires a formal `models/model_registry.json`.

---

## 7. Next Actions (Transition to Phase 2)
Proceed to Phase 2:
1. Extract and implement `src/safety_guardrail.py`.
2. Create `config/config.yaml` to centralize all operational and safety parameters.
3. Refactor train/test separation to guarantee zero leakage.
