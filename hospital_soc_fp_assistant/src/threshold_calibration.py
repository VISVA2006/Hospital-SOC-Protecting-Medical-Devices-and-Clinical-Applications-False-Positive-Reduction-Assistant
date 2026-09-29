"""
Multi-Point Threshold Calibration and Controlled Missed-Incident Module.
Evaluates operating boundaries across threat probability cutoffs (0.30-0.70)
and anomaly thresholds (0.50-0.80), measuring analyst hours and safety constraints.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from safety_guardrail import ClinicalSafetyGuardrail
from anomaly_detection import MedicalDeviceNoveltyDetector

def calibrate_thresholds(
    data_path="data/cleaned_alerts.csv",
    model_path="models/false_positive_model.joblib",
    anomaly_path="models/anomaly_model.joblib",
    output_csv="reports/threshold_calibration.csv"
):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    df = pd.read_csv(data_path)
    model_data = joblib.load(model_path)
    pipeline = model_data["pipeline"]
    num_cols = model_data["features"]["numeric"]
    cat_cols = model_data["features"]["categorical"]
    
    detector = MedicalDeviceNoveltyDetector.load(anomaly_path)
    
    X = df[num_cols + cat_cols].copy().fillna(0)
    threat_probs = pipeline.predict_proba(X)[:, 1]
    anomaly_scores, novelty_flags = detector.predict_anomaly(df)
    
    y_true = df["confirmed_incident"].values
    total_incidents = int((y_true == 1).sum())
    total_alerts = len(df)
    
    is_critical_mask = (df["device_criticality"] == "CRITICAL").values
    
    threat_cutoffs = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    anomaly_cutoffs = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]
    
    records = []
    
    for t_th in threat_cutoffs:
        for a_th in anomaly_cutoffs:
            guardrail = ClinicalSafetyGuardrail(threat_threshold=t_th, anomaly_threshold=a_th)
            
            review_flags = []
            for idx, row in df.iterrows():
                _, _, req = guardrail.evaluate(
                    alert=row,
                    ml_is_threat=bool(threat_probs[idx] >= 0.50),
                    ml_threat_prob=float(threat_probs[idx]),
                    anomaly_score=float(anomaly_scores[idx]),
                    is_novelty=bool(novelty_flags[idx])
                )
                review_flags.append(int(req))
                
            y_actions = np.array(review_flags)
            
            tp = int(((y_true == 1) & (y_actions == 1)).sum())
            fn = int(((y_true == 1) & (y_actions == 0)).sum())
            fp = int(((y_true == 0) & (y_actions == 1)).sum())
            tn = int(((y_true == 0) & (y_actions == 0)).sum())
            
            # Critical device missed incidents
            crit_fn = int(((y_true == 1) & (y_actions == 0) & is_critical_mask).sum())
            
            rec = tp / total_incidents if total_incidents > 0 else 1.0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            hours = round(int(y_actions.sum()) * 8.0 / 60.0, 2)
            
            records.append({
                "threat_threshold": t_th,
                "anomaly_threshold": a_th,
                "threat_recall": round(rec, 4),
                "missed_incidents": fn,
                "critical_device_missed_incidents": crit_fn,
                "triage_precision": round(prec, 4),
                "f1_score": round(f1, 4),
                "alerts_reviewed": int(y_actions.sum()),
                "alerts_suppressed": tn,
                "analyst_hours": hours,
                "safety_status": "SAFE" if fn == 0 and crit_fn == 0 else "UNSAFE"
            })
            
    calib_df = pd.DataFrame(records)
    calib_df.to_csv(output_csv, index=False)
    print(f"Threshold calibration completed: {len(calib_df)} points evaluated -> {output_csv}")
    return calib_df

if __name__ == "__main__":
    calibrate_thresholds()
