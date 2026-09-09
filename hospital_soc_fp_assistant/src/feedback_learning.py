"""
Analyst Feedback Capture and Continuous Learning Pipeline for Hospital SOC.
Records analyst decisions/overrides, batches feedback, periodically retrains models,
and measures before vs after performance metrics.
"""

import os
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split

FEEDBACK_FILE = "data/analyst_feedback.csv"

OVERRIDE_REASONS = [
    "New threat pattern",
    "Medical device involved",
    "Insufficient evidence",
    "Model incorrect",
    "Existing incident",
    "Analyst investigation required"
]

class FeedbackManager:
    """Manages logging of human analyst dispositions and model retraining."""
    def __init__(self, feedback_path=FEEDBACK_FILE):
        self.feedback_path = feedback_path
        self._ensure_feedback_file()

    def _ensure_feedback_file(self):
        """Initializes empty feedback file if not already present."""
        if not os.path.exists(self.feedback_path):
            os.makedirs(os.path.dirname(self.feedback_path), exist_ok=True)
            df = pd.DataFrame(columns=[
                "alert_id", "timestamp", "recommendation", "analyst_decision",
                "override_flag", "override_reason", "analyst_id"
            ])
            df.to_csv(self.feedback_path, index=False)

    def log_feedback(self, alert_id, recommendation, analyst_decision, analyst_id="ANL-CURRENT", override_reason=""):
        """Records an analyst's decision and override reason."""
        # Determine override: if recommendation was FP and analyst chose TP/Investigate/Escalate, or vice versa
        override_flag = 0
        if recommendation == "LIKELY_FALSE_POSITIVE" and analyst_decision in ["TRUE_POSITIVE", "INVESTIGATE", "ESCALATE"]:
            override_flag = 1
        elif recommendation in ["INVESTIGATE", "ESCALATE"] and analyst_decision in ["FALSE_POSITIVE", "BENIGN"]:
            override_flag = 1
            
        record = {
            "alert_id": alert_id,
            "timestamp": datetime.now().isoformat(),
            "recommendation": recommendation,
            "analyst_decision": analyst_decision,
            "override_flag": override_flag,
            "override_reason": override_reason if override_flag else "",
            "analyst_id": analyst_id
        }
        
        df = pd.read_csv(self.feedback_path)
        # Avoid duplicate feedback rows for the same alert
        df = df[df["alert_id"] != alert_id]
        df = pd.concat([df, pd.DataFrame([record])], ignore_index=True)
        df.to_csv(self.feedback_path, index=False)
        return record

    def get_feedback_stats(self):
        """Calculates statistics on logged analyst feedback."""
        if not os.path.exists(self.feedback_path):
            return {"total_feedback": 0, "overrides": 0, "override_rate": 0.0}
        df = pd.read_csv(self.feedback_path)
        if len(df) == 0:
            return {"total_feedback": 0, "overrides": 0, "override_rate": 0.0, "reasons": {}}
        total = len(df)
        overrides = int(df["override_flag"].sum())
        override_rate = round(overrides / total if total > 0 else 0.0, 4)
        reasons = df[df["override_flag"] == 1]["override_reason"].value_counts().to_dict()
        return {
            "total_feedback": total,
            "overrides": overrides,
            "override_rate": override_rate,
            "reasons": reasons
        }

    def simulate_analyst_feedback_batch(self, cleaned_data_path="data/cleaned_alerts.csv", num_feedback=150):
        """
        Seeds feedback file with realistic initial analyst decisions for demonstration.
        """
        if not os.path.exists(cleaned_data_path):
            return
        df = pd.read_csv(cleaned_data_path).sample(n=min(num_feedback, 300), random_state=42)
        feedback_list = []
        for _, row in df.iterrows():
            rec = "LIKELY_FALSE_POSITIVE" if row["severity"] == "LOW" and row["historical_false_positive_rate"] > 0.8 else "INVESTIGATE"
            disp = row.get("analyst_disposition", "FALSE_POSITIVE")
            override = 1 if (rec == "LIKELY_FALSE_POSITIVE" and disp != "FALSE_POSITIVE") or (rec == "INVESTIGATE" and disp == "FALSE_POSITIVE") else 0
            reason = ""
            if override:
                reason = np.random.choice(OVERRIDE_REASONS)
            feedback_list.append({
                "alert_id": row["alert_id"],
                "timestamp": datetime.now().isoformat(),
                "recommendation": rec,
                "analyst_decision": disp,
                "override_flag": override,
                "override_reason": reason,
                "analyst_id": row.get("analyst_id", "ANL-101")
            })
        fb_df = pd.DataFrame(feedback_list)
        fb_df.to_csv(self.feedback_path, index=False)
        print(f"Simulated {len(fb_df)} initial analyst feedback records -> {self.feedback_path}")

    def retrain_with_feedback(self, model_path="models/false_positive_model.joblib", cleaned_data_path="data/cleaned_alerts.csv"):
        """
        Periodic retraining incorporating analyst overrides.
        Updates model weights and compares before vs after metrics.
        """
        if not os.path.exists(model_path) or not os.path.exists(self.feedback_path):
            return None
            
        saved_data = joblib.load(model_path)
        pipeline = saved_data["pipeline"]
        before_metrics = saved_data["metrics"]
        
        df = pd.read_csv(cleaned_data_path)
        fb_df = pd.read_csv(self.feedback_path)
        
        # Merge feedback: override ground truth where analyst confirmed
        fb_map = {}
        for _, r in fb_df.iterrows():
            if r["analyst_decision"] in ["TRUE_POSITIVE", "INVESTIGATE", "ESCALATE"]:
                fb_map[r["alert_id"]] = 1
            elif r["analyst_decision"] in ["FALSE_POSITIVE", "BENIGN"]:
                fb_map[r["alert_id"]] = 0
                
        df_augmented = df.copy()
        for aid, new_label in fb_map.items():
            df_augmented.loc[df_augmented["alert_id"] == aid, "confirmed_incident"] = new_label
            
        num_cols = saved_data["features"]["numeric"]
        cat_cols = saved_data["features"]["categorical"]
        
        X = df_augmented[num_cols + cat_cols].copy().fillna(0)
        y = df_augmented["confirmed_incident"].values
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, stratify=y, random_state=42
        )
        
        # Fit on augmented data
        pipeline.fit(X_train, y_train)
        
        # Evaluate after
        preds = pipeline.predict(X_test)
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
        cm = confusion_matrix(y_test, preds)
        tn, fp, fn, tp = cm.ravel()
        
        after_metrics = {
            "model_name": saved_data["model_name"] + " (Feedback-Tuned)",
            "accuracy": round(float(accuracy_score(y_test, preds)), 4),
            "precision": round(float(precision_score(y_test, preds, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, preds, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_test, preds, zero_division=0)), 4),
            "false_negative_rate": round(float(fn / (fn + tp) if (fn + tp) > 0 else 0.0), 4),
            "missed_incidents": int(fn),
            "total_incidents": int(fn + tp)
        }
        
        comparison = {
            "before_feedback": before_metrics,
            "after_feedback": after_metrics,
            "feedback_samples_used": len(fb_df),
            "overrides_incorporated": int(fb_df["override_flag"].sum()) if len(fb_df) > 0 else 0
        }
        
        # Save updated model
        saved_data["pipeline"] = pipeline
        saved_data["feedback_tuning"] = comparison
        joblib.dump(saved_data, model_path)
        
        return comparison

if __name__ == "__main__":
    mgr = FeedbackManager()
    mgr.simulate_analyst_feedback_batch()
    comp = mgr.retrain_with_feedback()
    print("Feedback Retraining Comparison:")
    print(f"  Before Precision: {comp['before_feedback']['precision']} -> After Precision: {comp['after_feedback']['precision']}")
    print(f"  Before Recall:    {comp['before_feedback']['recall']} -> After Recall:    {comp['after_feedback']['recall']}")
    print(f"  Missed Incidents: {comp['after_feedback']['missed_incidents']}")
