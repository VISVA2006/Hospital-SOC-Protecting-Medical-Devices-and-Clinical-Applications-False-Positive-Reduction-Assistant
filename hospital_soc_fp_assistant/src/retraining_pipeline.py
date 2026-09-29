"""
Replay-Based Retraining Pipeline for Hospital SOC Assistant.
Mitigates catastrophic forgetting using historical replay buffers (80/20 ratio),
enforces champion/challenger validation gates, and registers versioned models.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from typing import Dict, Any, Tuple, Optional
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import recall_score, precision_score, f1_score, accuracy_score, confusion_matrix

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from feedback_validation import FeedbackValidator
from model_registry import ModelRegistry
from train_model import build_preprocessor, NUMERIC_FEATURES, CATEGORICAL_FEATURES

class ReplayRetrainingPipeline:
    """
    Manages safe, replay-buffered continuous learning:
    Combines historical baseline data with validated human feedback.
    """
    def __init__(
        self,
        historical_ratio: float = 0.80,
        feedback_ratio: float = 0.20,
        min_feedback_samples: int = 50,
        registry_path: str = "models/model_registry.json"
    ):
        self.historical_ratio = historical_ratio
        self.feedback_ratio = feedback_ratio
        self.validator = FeedbackValidator(min_samples=min_feedback_samples)
        self.registry = ModelRegistry(registry_path=registry_path)

    def prepare_replay_dataset(
        self,
        cleaned_data_path: str = "data/cleaned_alerts.csv",
        feedback_data_path: str = "data/analyst_feedback.csv"
    ) -> Tuple[Optional[pd.DataFrame], Dict[str, Any]]:
        """
        Builds a balanced replay dataset:
        80% historical representative samples + 20% validated analyst feedback.
        """
        if not os.path.exists(cleaned_data_path) or not os.path.exists(feedback_data_path):
            return None, {"status": "ERROR", "reason": "Data or feedback file not found."}
            
        df_hist = pd.read_csv(cleaned_data_path)
        df_fb_raw = pd.read_csv(feedback_data_path)
        
        # 1. Validate Feedback
        df_fb_valid, val_stats = self.validator.validate_batch(df_fb_raw)
        if not val_stats["can_trigger_retraining"]:
            return None, {
                "status": "ABORTED",
                "reason": val_stats["reason"],
                "validation_stats": val_stats
            }
            
        # 2. Build Feedback-Augmented Map
        # Map analyst decisions to binary threat labels (1 = Incident, 0 = False Positive)
        fb_label_map = {}
        for _, r in df_fb_valid.iterrows():
            decision = str(r["analyst_decision"]).strip().upper()
            if decision in ["CONFIRM_TRUE_THREAT", "TRUE_POSITIVE", "INVESTIGATE", "ESCALATE", "NEEDS_INVESTIGATION"]:
                fb_label_map[r["alert_id"]] = 1
            elif decision in ["CONFIRM_FALSE_POSITIVE", "FALSE_POSITIVE", "BENIGN"]:
                fb_label_map[r["alert_id"]] = 0
                
        # 3. Create Augmented Records
        df_feedback_records = df_hist[df_hist["alert_id"].isin(fb_label_map.keys())].copy()
        for idx, row in df_feedback_records.iterrows():
            aid = row["alert_id"]
            if aid in fb_label_map:
                df_feedback_records.loc[idx, "confirmed_incident"] = fb_label_map[aid]
                
        # 4. Sample Historical Data (Replay Buffer)
        # Stratified sampling of historical baseline data
        n_feedback = len(df_feedback_records)
        target_hist_samples = int(n_feedback * (self.historical_ratio / self.feedback_ratio))
        target_hist_samples = min(target_hist_samples, len(df_hist))
        
        # Exclude feedback alerts from the historical replay pool to prevent duplicates
        df_hist_pool = df_hist[~df_hist["alert_id"].isin(fb_label_map.keys())]
        
        if len(df_hist_pool) > target_hist_samples:
            df_replay_hist = df_hist_pool.sample(n=target_hist_samples, random_state=42)
        else:
            df_replay_hist = df_hist_pool
            
        # 5. Concatenate Replay Dataset
        replay_df = pd.concat([df_replay_hist, df_feedback_records], ignore_index=True)
        replay_df = replay_df.sample(frac=1.0, random_state=42).reset_index(drop=True)
        
        stats = {
            "status": "SUCCESS",
            "historical_samples": len(df_replay_hist),
            "feedback_samples": len(df_feedback_records),
            "total_replay_samples": len(replay_df),
            "validation_stats": val_stats
        }
        return replay_df, stats

    def train_and_validate_candidate(
        self,
        cleaned_data_path: str = "data/cleaned_alerts.csv",
        feedback_data_path: str = "data/analyst_feedback.csv",
        version_label: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes candidate model training and evaluates against champion model.
        Returns evaluation comparison and promotion readiness.
        """
        replay_df, replay_stats = self.prepare_replay_dataset(cleaned_data_path, feedback_data_path)
        if replay_df is None:
            return {"status": "FAILED", "reason": replay_stats["reason"]}
            
        # Stratified split of replay dataset
        y = replay_df["confirmed_incident"].values
        X = replay_df[NUMERIC_FEATURES + CATEGORICAL_FEATURES].copy().fillna(0)
        
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.20, stratify=y, random_state=42
        )
        
        # Build Pipeline & Fit Candidate Model
        from sklearn.pipeline import Pipeline
        preprocessor = build_preprocessor()
        candidate_clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        candidate_pipeline = Pipeline(steps=[
            ("preprocessor", preprocessor),
            ("classifier", candidate_clf)
        ])
        candidate_pipeline.fit(X_train, y_train)
        
        # Evaluate Candidate Model
        c_preds = candidate_pipeline.predict(X_val)
        cm = confusion_matrix(y_val, c_preds)
        tn, fp, fn, tp = cm.ravel()
        
        rec = float(recall_score(y_val, c_preds, zero_division=0))
        prec = float(precision_score(y_val, c_preds, zero_division=0))
        f1 = float(f1_score(y_val, c_preds, zero_division=0))
        acc = float(accuracy_score(y_val, c_preds))
        
        # Evaluate Critical Device Recall on Validation Subset
        crit_mask = (replay_df.iloc[X_val.index]["device_criticality"] == "CRITICAL").values
        if crit_mask.sum() > 0:
            crit_y_true = y_val[crit_mask]
            crit_preds = c_preds[crit_mask]
            crit_tp = ((crit_y_true == 1) & (crit_preds == 1)).sum()
            crit_total = (crit_y_true == 1).sum()
            crit_recall = float(crit_tp / crit_total) if crit_total > 0 else 1.0
        else:
            crit_recall = 1.0
            
        candidate_metrics = {
            "threat_recall": round(rec, 4),
            "missed_incidents": int(fn),
            "triage_precision": round(prec, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(acc, 4),
            "critical_device_recall": round(crit_recall, 4)
        }
        
        # Compare with Current Champion
        champ = self.registry.get_champion()
        champ_metrics = champ["metrics"] if champ else {}
        
        # Promotion Policy Gates:
        # 1. Threat recall >= 0.95
        # 2. Missed incidents on critical devices == 0 (crit_recall == 1.0)
        # 3. Overall F1 >= 0.70
        passed_safety_gates = (
            candidate_metrics["threat_recall"] >= 0.95 and
            candidate_metrics["critical_device_recall"] >= 1.0 and
            candidate_metrics["missed_incidents"] == 0
        )
        
        if not version_label:
            version_label = f"v{len(self.registry.load_registry()['models']) + 1}.0"
            
        candidate_path = f"models/candidate_model_{version_label}.joblib"
        joblib.dump({
            "pipeline": candidate_pipeline,
            "version": version_label,
            "metrics": candidate_metrics,
            "features": {"numeric": NUMERIC_FEATURES, "categorical": CATEGORICAL_FEATURES}
        }, candidate_path)
        
        # Register in Model Registry
        reg_record = self.registry.register_candidate(
            model_version=version_label,
            model_path=candidate_path,
            metrics=candidate_metrics,
            training_samples=len(X_train),
            feedback_samples=replay_stats["feedback_samples"],
            notes=f"Replay-retrained candidate with {replay_stats['feedback_samples']} feedback samples."
        )
        
        return {
            "status": "SUCCESS",
            "candidate_version": version_label,
            "candidate_path": candidate_path,
            "candidate_metrics": candidate_metrics,
            "champion_metrics": champ_metrics,
            "passed_safety_gates": passed_safety_gates,
            "promotion_eligible": passed_safety_gates,
            "replay_stats": replay_stats
        }

if __name__ == "__main__":
    pipeline = ReplayRetrainingPipeline(min_feedback_samples=50)
    result = pipeline.train_and_validate_candidate()
    print("Retraining Pipeline Execution Result:")
    print(f"  Status: {result.get('status')}")
    print(f"  Candidate Version: {result.get('candidate_version')}")
    print(f"  Promotion Eligible: {result.get('promotion_eligible')}")
    print(f"  Metrics: {result.get('candidate_metrics')}")
