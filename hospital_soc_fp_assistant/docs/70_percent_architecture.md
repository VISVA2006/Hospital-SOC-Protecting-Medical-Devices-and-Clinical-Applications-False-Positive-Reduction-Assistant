# System Architecture: Hospital SOC False-Positive Reduction Assistant

## 1. Architectural Overview

The **Hospital SOC False-Positive Reduction Assistant** is an end-to-end defensive cybersecurity system tailored specifically for healthcare environments and Internet of Medical Things (IoMT) infrastructures.

Traditional security triage models rely heavily on static rule thresholds, causing massive false-positive fatigue (up to 75% of alerts) while remaining vulnerable to sophisticated attackers who disguise attacks as routine network telemetry. The assistant replaces brittle heuristics with a **multi-layered, explainable, and safety-governed AI architecture**.

```
                           [ Incoming Security Telemetry Stream ]
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │  EventProcessor Pipeline  │
                               │  - Deduplication Storms   │
                               │  - Chronological Sorting  │
                               │  - Latency Reconciliation │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │   Feature Extraction Layer    │
                             │   - Temporal & Risk Features  │
                             │   - Asset Criticality Mapping │
                             └───────────────┬───────────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    ▼                        ▼                        ▼
       ┌────────────────────────┐┌───────────────────────┐┌────────────────────────┐
       │ Supervised ML Pipeline ││ Isolation Forest Novel││ Temporal Sequence Track│
       │ (Balanced LogReg/RF)   ││ (Novelty Detection)   ││ (Multi-Alert Window)   │
       │ Threat Probability     ││ Anomaly Score         ││ Rolling Risk Score     │
       └────────────┬───────────┘└───────────┬───────────┘└───────────┬────────────┘
                    │                        │                        │
                    └────────────────────────┼────────────────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ Clinical Safety Guardrail │
                               │ - Critical Asset Defense  │
                               │ - Invariant Rules 1 - 6   │
                               │ - Fail-Safe Fallback      │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
                               ┌───────────────────────────┐
                               │ Explainable Evidence Gen  │
                               │ - Human-Readable Bullets  │
                               │ - Guardrail Audit Trail   │
                               └─────────────┬─────────────┘
                                             │
                         ┌───────────────────┴───────────────────┐
                         ▼                                       ▼
            [ LIKELY_FALSE_POSITIVE ]               [ REVIEW / INVESTIGATE ]
            (Safely Suppressed; 0 min)              (Analyst Decision Queue)
                                                                 │
                                                                 ▼
                                                    ┌────────────────────────┐
                                                    │ Human-in-the-Loop      │
                                                    │ Analyst Confirmation   │
                                                    │ & Override Feedback    │
                                                    └────────────┬───────────┘
                                                                 │
                                                                 ▼
                                                    ┌────────────────────────┐
                                                    │ Replay Retraining &    │
                                                    │ Model Governance       │
                                                    │ (Anti-Forgetting)      │
                                                    └────────────────────────┘
```

---

## 2. Core Architectural Components

### 2.1 Event Ingestion & Stream Integrity (`src/event_processor.py`)
- **Deduplication:** Collapses repetitive alert storms sharing the same logical `event_id` or `(source_ip, alert_type, window)` to a single consolidated event.
- **Chronological Re-sequencing:** Handles network jitter and out-of-order arrival, ordering events strictly by generation timestamp rather than receipt timestamp.
- **Latency Reconciliation:** Tracks elapsed latency between device event emission and SIEM ingestion to identify network delays and clock skew.

### 2.2 Supervised Threat Classifier (`src/train_model.py`)
- **Model:** Class-balanced Logistic Regression with Scikit-learn Pipeline encapsulation.
- **Preprocessing:** `StandardScaler` for continuous numerical telemetry and `OneHotEncoder(handle_unknown='ignore')` for categorical telemetry (protocol, detection source, device type, network segment).
- **Selection Criterion:** Strict minimization of False Negative Rate ($\text{FNR} = 0.0\%$, $\text{Recall} = 1.0$).

### 2.3 Novel Threat & Anomaly Detection (`src/anomaly_detection.py`)
- **Model:** Isolation Forest fitted strictly on normal/benign operational profiles.
- **Purpose:** Prevents novel threats and zero-day attacks with unseen telemetry profiles from being classified as benign false positives.
- **Output:** Normalized anomaly score (0.0 to 1.0) and novelty flag.

### 2.4 Multi-Alert Sequence Accumulator (`src/sequence_detection.py`)
- **Structure:** In-memory sliding time window (60 minutes).
- **Purpose:** Detects low-and-slow reconnaissance and distributed scanning across multiple endpoints that individually appear low-severity.
- **Metrics Tracked:** Event frequency, unique destination host count, failed authentication count, and cumulative risk velocity.

### 2.5 Deterministic Clinical Safety Guardrail (`src/safety_guardrail.py`)
- **Core Invariant:** Automated suppression of critical medical assets (Ventilators, Infusion Pumps, ICU Monitors) is strictly prohibited.
- **Invariants 1-6:** Enforces deterministic routing to `REVIEW`, `INVESTIGATE`, or `ESCALATE` across threat thresholds, anomaly cutoffs, and sequence triggers.
- **Fail-Safe Mechanism:** Any unhandled exception during parsing or feature engineering fails open to human review (`REVIEW` or `ESCALATE`), guaranteeing the system never suppresses an alert due to a software error.

### 2.6 Enterprise REST API Layer (`app/api.py`, `app/services.py`)
- Built on FastAPI with Pydantic schema validation.
- Endpoints for single-alert triage, high-throughput batch stream processing, analyst feedback recording, model status introspection, and candidate retraining.

### 2.7 Interactive Analyst Workspace (`app.py`)
- Streamlit application delivering 11 modular workspaces:
  1. Executive Dashboard
  2. Alert Investigation & Triage
  3. Event Stream Integrity
  4. Model Performance & Evaluation
  5. Analyst Feedback
  6. Deep Error Analysis
  7. Feature Drift Monitoring
  8. Continuous Learning & Replay Retraining
  9. Model Registry & Governance
  10. Adversarial Testing Suite
  11. Threshold Calibration & Operating Points
