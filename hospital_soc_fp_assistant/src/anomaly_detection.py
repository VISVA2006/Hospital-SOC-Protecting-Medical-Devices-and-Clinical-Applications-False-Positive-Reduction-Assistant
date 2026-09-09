"""
Novelty and Anomaly Detection Layer for Hospital SOC.
Uses Isolation Forest to detect novel threats, unusual medical device telemetry,
and enforces critical clinical safety guardrails against unwarranted suppression.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ANOMALY_FEATURE_COLS = [
    "severity_score",
    "device_criticality_score",
    "failed_login_count",
    "login_attempts",
    "event_count",
    "destination_port",
    "unusual_time",
    "unusual_destination",
    "historical_alert_count",
    "historical_false_positive_rate",
    "latency_seconds"
]

class MedicalDeviceNoveltyDetector:
    """
    Detects unseen/novel attack patterns on medical devices and endpoints.
    Protects novel threats from being misclassified and suppressed as false positives.
    """
    def __init__(self, contamination=0.07, random_state=42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.feature_cols = ANOMALY_FEATURE_COLS

    def fit(self, df):
        """Fits Isolation Forest on baseline/benign dataset features."""
        # Train on benign / normal baseline alerts to learn normal operational envelopes
        benign_df = df[df["confirmed_incident"] == 0] if "confirmed_incident" in df.columns else df
        X = benign_df[self.feature_cols].copy().fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return self

    def predict_anomaly(self, df):
        """
        Returns anomaly scores (0 to 1, where higher = more anomalous)
        and boolean novelty flags (True = anomaly/novel).
        """
        X = df[self.feature_cols].copy().fillna(0)
        X_scaled = self.scaler.transform(X)
        
        # Raw decision function: lower is more anomalous
        raw_scores = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled) # -1 is anomaly, 1 is normal
        
        # Normalize to 0-1 scale where 1.0 is extreme anomaly
        # Typically raw_scores range from -0.3 to +0.3
        min_s, max_s = -0.35, 0.25
        norm_scores = 1.0 - np.clip((raw_scores - min_s) / (max_s - min_s), 0.0, 1.0)
        
        novelty_flags = (preds == -1)
        return norm_scores, novelty_flags

    def evaluate_safety_guardrails(self, alert_row, ml_is_threat, ml_threat_prob, anomaly_score, is_novelty):
        """
        Applies Critical Hospital Safety Rules:
        1. Anomaly detected -> Force INVESTIGATE
        2. Critical medical device + unusual destination/time -> NEVER suppress (force INVESTIGATE/REVIEW)
        3. Low model confidence -> Force REVIEW
        4. ML predicts threat -> INVESTIGATE or ESCALATE
        5. Only high-confidence benign + low anomaly + non-critical/clean device -> LIKELY_FALSE_POSITIVE
        """
        is_critical_device = str(alert_row.get("device_criticality")).upper() == "CRITICAL"
        unusual_dest = int(alert_row.get("unusual_destination", 0)) == 1
        unusual_time = int(alert_row.get("unusual_time", 0)) == 1
        
        # Rule 1: ML predicts Threat
        if ml_is_threat:
            if is_critical_device and (unusual_dest or alert_row.get("severity") in ["HIGH", "CRITICAL"]):
                return "ESCALATE", "Critical medical device exhibiting active threat telemetry", True
            return "INVESTIGATE", "ML model classified alert as actionable security incident", True

        # Rule 2: Novelty / Anomaly detected (Novel Threat Protection)
        if is_novelty or anomaly_score > 0.65:
            return "INVESTIGATE", f"Novel/anomalous telemetry pattern detected (Anomaly Score: {anomaly_score:.2f}). Protected by safety layer.", True

        # Rule 3: Critical Medical Device with unusual behavior
        if is_critical_device and (unusual_dest or unusual_time):
            return "REVIEW", "Critical medical device with unusual network/time activity. Auto-suppression blocked by safety rule.", True

        # Rule 4: Model uncertainty (threat prob between 0.25 and 0.50)
        if ml_threat_prob >= 0.25:
            return "REVIEW", f"Borderline model confidence ({1.0 - ml_threat_prob:.2f}). Requires human confirmation.", True

        # Rule 5: Safe False Positive
        confidence_pct = int((1.0 - ml_threat_prob) * 100)
        return "LIKELY_FALSE_POSITIVE", f"Repetitive benign pattern with {confidence_pct}% model confidence and normal operational profile.", False

    def save(self, filepath="models/anomaly_model.joblib"):
        """Saves model and scaler to joblib."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler, "features": self.feature_cols}, filepath)
        print(f"Saved anomaly model -> {filepath}")

    @classmethod
    def load(cls, filepath="models/anomaly_model.joblib"):
        """Loads model and scaler from joblib."""
        data = joblib.load(filepath)
        detector = cls()
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        detector.feature_cols = data["features"]
        return detector

if __name__ == "__main__":
    if os.path.exists("data/cleaned_alerts.csv"):
        df = pd.read_csv("data/cleaned_alerts.csv")
        detector = MedicalDeviceNoveltyDetector()
        detector.fit(df)
        scores, flags = detector.predict_anomaly(df)
        print(f"Anomaly Detection Fitted:")
        print(f"  Anomalies flagged: {flags.sum()} / {len(df)} ({flags.sum()/len(df)*100:.1f}%)")
        print(f"  Mean anomaly score: {scores.mean():.3f}")
        detector.save()
