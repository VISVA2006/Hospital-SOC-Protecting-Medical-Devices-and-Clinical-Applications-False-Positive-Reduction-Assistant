"""
Rule-Based SOC Baseline Engine.
Implements traditional static threshold rules for alert triage and calculates
workload, accuracy, and missed-incident metrics.
"""

import os
import pandas as pd
import numpy as np

class RuleBasedBaseline:
    """
    Standard Rule-Based SOC Triage:
    Rule 1: IF severity = LOW AND historical_false_positive_rate > 0.80 -> LIKELY_FALSE_POSITIVE
    Rule 2: IF failed_login_count > 10 -> SUSPICIOUS
    Rule 3: IF device_criticality = CRITICAL AND unusual_destination = TRUE -> HIGH_RISK
    Rule 4: IF known_scanner = TRUE AND maintenance_window = TRUE -> LIKELY_FALSE_POSITIVE
    Otherwise -> NEEDS_REVIEW
    """
    def __init__(self, review_time_minutes=8.0):
        self.review_time_minutes = review_time_minutes

    def predict_single(self, row):
        """Evaluates rules in order of priority (risk rules take precedence over suppression)."""
        # Rule 3 (High Risk)
        if str(row.get("device_criticality")).upper() == "CRITICAL" and int(row.get("unusual_destination", 0)) == 1:
            return "HIGH_RISK"
            
        # Rule 2 (Suspicious)
        if float(row.get("failed_login_count", 0)) > 10:
            return "SUSPICIOUS"
            
        # Rule 4 (Known scanner + maintenance)
        if int(row.get("known_scanner", 0)) == 1 and int(row.get("maintenance_window", 0)) == 1:
            return "LIKELY_FALSE_POSITIVE"
            
        # Rule 1 (Low severity + high FP rate)
        if str(row.get("severity")).upper() == "LOW" and float(row.get("historical_false_positive_rate", 0)) > 0.80:
            return "LIKELY_FALSE_POSITIVE"
            
        return "NEEDS_REVIEW"

    def predict(self, df):
        """Applies baseline rules to all rows in DataFrame."""
        return df.apply(self.predict_single, axis=1)

    def evaluate(self, df):
        """
        Evaluates baseline performance against ground truth confirmed_incident (1 = real incident, 0 = benign/FP).
        - Alerts predicted as 'LIKELY_FALSE_POSITIVE' are suppressed (not reviewed).
        - Alerts predicted as 'SUSPICIOUS', 'HIGH_RISK', or 'NEEDS_REVIEW' are reviewed by analysts.
        """
        predictions = self.predict(df)
        
        # Ground truth: 1 if confirmed_incident == 1, else 0
        actual_incidents = df["confirmed_incident"].values
        total_alerts = len(df)
        total_actual_incidents = int((actual_incidents == 1).sum())
        total_actual_fps = total_alerts - total_actual_incidents
        
        # In baseline triage:
        # suppressed_as_fp = (predictions == 'LIKELY_FALSE_POSITIVE')
        # flagged_for_review = (predictions != 'LIKELY_FALSE_POSITIVE')
        flagged_for_review = (predictions.isin(["SUSPICIOUS", "HIGH_RISK", "NEEDS_REVIEW"])).values
        suppressed_as_fp = ~flagged_for_review
        
        # A true threat that was suppressed as FP is a MISSED INCIDENT (False Negative)
        missed_incidents = int(((actual_incidents == 1) & suppressed_as_fp).sum())
        detected_incidents = int(((actual_incidents == 1) & flagged_for_review).sum())
        
        # False Positives sent to analyst review: benign events that were NOT suppressed
        benign_sent_to_analyst = int(((actual_incidents == 0) & flagged_for_review).sum())
        benign_correctly_suppressed = int(((actual_incidents == 0) & suppressed_as_fp).sum())
        
        # Metrics
        recall = detected_incidents / total_actual_incidents if total_actual_incidents > 0 else 1.0
        precision = detected_incidents / int(flagged_for_review.sum()) if flagged_for_review.sum() > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        missed_incident_rate = missed_incidents / total_actual_incidents if total_actual_incidents > 0 else 0.0
        false_negative_rate = missed_incident_rate
        false_positive_rate = benign_sent_to_analyst / total_actual_fps if total_actual_fps > 0 else 0.0
        accuracy = (detected_incidents + benign_correctly_suppressed) / total_alerts
        
        alerts_requiring_review = int(flagged_for_review.sum())
        analyst_hours = round(alerts_requiring_review * self.review_time_minutes / 60.0, 2)
        
        return {
            "total_alerts": total_alerts,
            "actual_incidents": total_actual_incidents,
            "actual_fps": total_actual_fps,
            "alerts_requiring_review": alerts_requiring_review,
            "alerts_suppressed": int(suppressed_as_fp.sum()),
            "detected_incidents": detected_incidents,
            "missed_incidents": missed_incidents,
            "missed_incident_rate": round(missed_incident_rate, 4),
            "false_negative_rate": round(false_negative_rate, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "analyst_hours": analyst_hours
        }

if __name__ == "__main__":
    if os.path.exists("data/cleaned_alerts.csv"):
        df = pd.read_csv("data/cleaned_alerts.csv")
        baseline = RuleBasedBaseline()
        metrics = baseline.evaluate(df)
        print("=== BASELINE SOC RULE EVALUATION ===")
        for k, v in metrics.items():
            print(f"  {k}: {v}")
