# Model Registry & Clinical Governance Architecture

## 1. Governance Architecture

In regulated clinical environments, machine learning models cannot operate as "black boxes" that update silently in production. The **Model Registry** (`src/model_registry.py` and `models/model_registry.json`) provides an auditable, deterministic lifecycle management layer.

---

## 2. Model States & Transitions

```
               [ Training Pipeline ]
                         │
                         ▼
                  ┌──────────────┐
                  │  CANDIDATE   │
                  └──────┬───────┘
                         │
             Promotion Gate Evaluation
           (Recall >= 98%, Crit Dev = 100%)
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
      [ REJECTED ]              [ CHAMPION ] ◄── (Active Inference)
                                      │
                                      ▼
                                [ ARCHIVED ] ◄── (Eligible for Rollback)
```

---

## 3. Metadata Schema

Every model entry tracks:
- `model_version`: SemVer identifier (e.g. `v1.0`, `v2.0`).
- `status`: Lifecycle state (`CHAMPION`, `CANDIDATE`, `REJECTED`, `ARCHIVED`).
- `model_path`: Relative filesystem artifact path.
- `training_timestamp`: ISO 8601 creation timestamp.
- `dataset_version`: Dataset identifier used for training.
- `training_samples`: Sample count (including baseline count).
- `feedback_samples`: Analyst feedback sample count ingested.
- `metrics`: Dictionary recording `threat_recall`, `missed_incidents`, `triage_precision`, `f1_score`, `accuracy`, and `critical_device_recall`.
- `notes`: Human-readable audit narrative.

---

## 4. Deterministic Rollback

If unexpected behavior or distribution shifts degrade production performance, SOC administrators can trigger an instantaneous, single-click rollback via the Streamlit dashboard or REST API:
```python
registry.rollback_to_version("v1.0")
```
The active pointer is safely updated, the previous champion's weights are restored, and the event is permanently recorded in the audit trail.
