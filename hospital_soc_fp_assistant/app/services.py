"""
Core Service Layer for Hospital SOC Assistant.
Orchestrates model inference, anomaly detection, temporal sequence accumulation,
safety guardrails, explainability, and fail-safe exception recovery.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, List, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from safety_guardrail import ClinicalSafetyGuardrail
from anomaly_detection import MedicalDeviceNoveltyDetector
from sequence_detection import TemporalSequenceDetector
from explainability import generate_evidence
from model_registry import ModelRegistry
from retraining_pipeline import ReplayRetrainingPipeline
from feedback_learning import FeedbackManager

SEVERITY_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DEVICE_CRIT_MAP = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class TriageService:
    """Singleton-style service managing live triage pipelines and state."""
    
    def __init__(
        self,
        champion_path="models/false_positive_model.joblib",
        anomaly_path="models/anomaly_model.joblib",
        registry_path="models/model_registry.json"
    ):
        self.champion_path = champion_path
        self.anomaly_path = anomaly_path
        self.registry = ModelRegistry(registry_path=registry_path)
        self.guardrail = ClinicalSafetyGuardrail(threat_threshold=0.40, anomaly_threshold=0.65)
        self.sequence_detector = TemporalSequenceDetector(window_minutes=60)
        self.feedback_manager = FeedbackManager()
        self.retraining_pipeline = ReplayRetrainingPipeline(min_feedback_samples=50, registry_path=registry_path)
        
        self.model_data = None
        self.pipeline = None
        self.anomaly_detector = None
        self._load_models()

    def _load_models(self):
        """Loads model artifacts with fail-safe error handling."""
        try:
            if os.path.exists(self.champion_path):
                self.model_data = joblib.load(self.champion_path)
                self.pipeline = self.model_data.get("pipeline")
            if os.path.exists(self.anomaly_path):
                self.anomaly_detector = MedicalDeviceNoveltyDetector.load(self.anomaly_path)
        except Exception as e:
            self.pipeline = None
            self.anomaly_detector = None
            print(f"[WARNING] Model loading failed: {e}. Fail-safe active.")

    def analyze_single_alert(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes complete defensive triage for an alert.
        Fail-safe guaranteed: any internal failure routes to human review.
        """
        alert_id = str(alert_dict.get("alert_id", "UNKNOWN"))
        champ_meta = self.registry.get_champion()
        model_ver = champ_meta["model_version"] if champ_meta else "v1.0-fallback"
        
        try:
            # 1. Enrich & Preprocess Single Record with Complete Defaults
            default_fields = {
                "severity": "LOW",
                "device_criticality": "LOW",
                "failed_login_count": 0,
                "login_attempts": 0,
                "event_count": 1,
                "destination_port": 80,
                "source_port": 0,
                "unusual_time": 0,
                "unusual_destination": 0,
                "historical_alert_count": 10,
                "historical_false_positive_rate": 0.5,
                "known_scanner": 0,
                "maintenance_window": 0,
                "latency_seconds": 0.0,
                "high_failure_rate": 0.0,
                "protocol": "TCP",
                "detection_source": "Network NIDS",
                "device_type": "Workstation",
                "network_segment": "Clinical-VLAN"
            }
            alert_clean = {**default_fields, **dict(alert_dict)}
            alert_clean["severity_score"] = SEVERITY_MAP.get(str(alert_clean.get("severity", "LOW")).upper(), 1)
            alert_clean["device_criticality_score"] = DEVICE_CRIT_MAP.get(str(alert_clean.get("device_criticality", "LOW")).upper(), 1)
            
            # Latency calculation
            ts_val = alert_clean.get("timestamp") or datetime.now()
            r_ts_val = alert_clean.get("received_timestamp") or ts_val
            try:
                ts = pd.to_datetime(ts_val)
                r_ts = pd.to_datetime(r_ts_val)
                diff = (r_ts - ts).total_seconds()
                alert_clean["latency_seconds"] = max(0.0, float(diff)) if not pd.isna(diff) else 0.0
            except Exception:
                alert_clean["latency_seconds"] = 0.0
            
            # High failure rate
            l_attempts = float(alert_clean.get("login_attempts", 0))
            f_logins = float(alert_clean.get("failed_login_count", 0))
            alert_clean["high_failure_rate"] = (f_logins / l_attempts) if l_attempts > 0 else 0.0
            
            # 2. Sequence Risk Accumulation
            seq_risk = self.sequence_detector.add_event(alert_clean)
            
            # 3. Model Scoring
            if self.pipeline is not None and self.model_data is not None:
                num_cols = self.model_data["features"]["numeric"]
                cat_cols = self.model_data["features"]["categorical"]
                df_feat = pd.DataFrame([alert_clean])[num_cols + cat_cols].fillna(0)
                threat_prob = float(self.pipeline.predict_proba(df_feat)[0, 1])
                ml_is_threat = (threat_prob >= 0.50)
            else:
                threat_prob = 0.50
                ml_is_threat = True
                
            # 4. Anomaly Scoring
            if self.anomaly_detector is not None:
                scores, novelties = self.anomaly_detector.predict_anomaly(pd.DataFrame([alert_clean]))
                anom_score = float(scores[0])
                is_novel = bool(novelties[0])
            else:
                anom_score = 0.50
                is_novel = False
                
            # 5. Clinical Safety Guardrail Evaluation
            rec, guard_reason, req_review = self.guardrail.evaluate(
                alert=alert_clean,
                ml_is_threat=ml_is_threat,
                ml_threat_prob=threat_prob,
                anomaly_score=anom_score,
                is_novelty=is_novel,
                sequence_risk_score=seq_risk
            )
            
            # 6. Generate Explainability Evidence
            evidence = generate_evidence(alert_clean, rec, threat_prob, anom_score, is_novel)
            if seq_risk >= 0.50:
                evidence.append(f"Sequence alert trend: Cumulative rolling risk score is {seq_risk:.2f}")
                
            return {
                "alert_id": alert_id,
                "recommendation": rec,
                "ml_threat_probability": round(threat_prob, 4),
                "anomaly_score": round(anom_score, 4),
                "is_novelty": is_novel,
                "sequence_risk_score": round(seq_risk, 4),
                "requires_human_review": req_review,
                "evidence_bullets": evidence,
                "clinical_guardrail_reason": guard_reason,
                "model_version": model_ver,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            # Clinical Fail-Safe: NEVER suppress on exception
            rec, reason, req = self.guardrail.fail_safe_fallback(alert_dict, str(e))
            return {
                "alert_id": alert_id,
                "recommendation": rec,
                "ml_threat_probability": 0.50,
                "anomaly_score": 0.50,
                "is_novelty": True,
                "sequence_risk_score": 0.50,
                "requires_human_review": True,
                "evidence_bullets": [f"System fail-safe invoked due to processing error: {e}"],
                "clinical_guardrail_reason": reason,
                "model_version": "fail-safe",
                "timestamp": datetime.now().isoformat()
            }

    def record_analyst_decision(self, feedback_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Logs an analyst decision and override reason."""
        aid = feedback_dict.get("alert_id")
        rec = feedback_dict.get("recommendation", "REVIEW")
        disp = feedback_dict.get("analyst_decision")
        anl_id = feedback_dict.get("analyst_id", "ANL-CURRENT")
        reason = feedback_dict.get("override_reason", "")
        
        return self.feedback_manager.log_feedback(
            alert_id=aid,
            recommendation=rec,
            analyst_decision=disp,
            analyst_id=anl_id,
            override_reason=reason
        )

    def trigger_retraining(self) -> Dict[str, Any]:
        """Triggers candidate model training on replay dataset."""
        res = self.retraining_pipeline.train_and_validate_candidate()
        # Reload models in case champion changed
        self._load_models()
        return res
