"""
Controlled Noise Robustness Experiment for Hospital SOC Assistant.
Evaluates model and guardrail resilience under 0%, 2%, 5%, 10%, 15%, and 20%
numerical feature perturbation.
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from safety_guardrail import ClinicalSafetyGuardrail
from anomaly_detection import MedicalDeviceNoveltyDetector

NUM_PERTURB_COLS = [
    "failed_login_count",
    "login_attempts",
    "event_count",
    "historical_alert_count",
    "historical_false_positive_rate",
    "latency_seconds"
]

def run_noise_robustness_experiment(
    data_path="data/cleaned_alerts.csv",
    model_path="models/false_positive_model.joblib",
    anomaly_path="models/anomaly_model.joblib",
    output_csv="reports/noise_robustness.csv",
    output_png="reports/noise_robustness.png"
):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    df = pd.read_csv(data_path)
    model_data = joblib.load(model_path)
    pipeline = model_data["pipeline"]
    num_cols = model_data["features"]["numeric"]
    cat_cols = model_data["features"]["categorical"]
    
    detector = MedicalDeviceNoveltyDetector.load(anomaly_path)
    guardrail = ClinicalSafetyGuardrail(threat_threshold=0.40, anomaly_threshold=0.65)
    
    noise_levels = [0.0, 0.02, 0.05, 0.10, 0.15, 0.20]
    results = []
    
    y_true = df["confirmed_incident"].values
    total_incidents = int((y_true == 1).sum())
    total_benign = int((y_true == 0).sum())
    
    np.random.seed(42)
    
    for noise in noise_levels:
        df_perturbed = df.copy()
        
        # Apply controlled relative Gaussian noise to numerical features
        if noise > 0:
            for col in NUM_PERTURB_COLS:
                if col in df_perturbed.columns:
                    noise_factor = 1.0 + np.random.normal(0.0, noise, size=len(df_perturbed))
                    df_perturbed[col] = (df_perturbed[col] * noise_factor).clip(lower=0.0)
                    if "rate" in col:
                        df_perturbed[col] = df_perturbed[col].clip(0.0, 1.0)
                        
        X = df_perturbed[num_cols + cat_cols].copy().fillna(0)
        threat_probs = pipeline.predict_proba(X)[:, 1]
        ml_preds = (threat_probs >= 0.50).astype(int)
        
        anomaly_scores, novelty_flags = detector.predict_anomaly(df_perturbed)
        
        # Evaluate safety guardrail
        requires_review = []
        for idx, row in df_perturbed.iterrows():
            rec, reason, req_rev = guardrail.evaluate(
                alert=row,
                ml_is_threat=bool(ml_preds[idx]),
                ml_threat_prob=float(threat_probs[idx]),
                anomaly_score=float(anomaly_scores[idx]),
                is_novelty=bool(novelty_flags[idx])
            )
            requires_review.append(int(req_rev))
            
        y_pred_action = np.array(requires_review)
        
        # Threat detection metrics
        tp = int(((y_true == 1) & (y_pred_action == 1)).sum())
        fn = int(((y_true == 1) & (y_pred_action == 0)).sum())
        fp = int(((y_true == 0) & (y_pred_action == 1)).sum())
        tn = int(((y_true == 0) & (y_pred_action == 0)).sum())
        
        recall = tp / total_incidents if total_incidents > 0 else 1.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        acc = (tp + tn) / len(df)
        fnr = fn / total_incidents if total_incidents > 0 else 0.0
        fpr = fp / total_benign if total_benign > 0 else 0.0
        
        results.append({
            "noise_level_pct": int(noise * 100),
            "threat_recall": round(recall, 4),
            "missed_incidents": fn,
            "false_negative_rate": round(fnr, 4),
            "triage_precision": round(precision, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(acc, 4),
            "false_positive_rate": round(fpr, 4),
            "alerts_reviewed": int(y_pred_action.sum()),
            "alerts_suppressed": int((y_pred_action == 0).sum())
        })
        
    res_df = pd.DataFrame(results)
    res_df.to_csv(output_csv, index=False)
    
    # Plotting
    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    color = 'tab:blue'
    ax1.set_xlabel('Numerical Perturbation / Noise Level (%)', fontweight='bold')
    ax1.set_ylabel('Recall & F1 Score', color=color, fontweight='bold')
    ax1.plot(res_df['noise_level_pct'], res_df['threat_recall'], marker='o', color='tab:green', label='Threat Recall', linewidth=2)
    ax1.plot(res_df['noise_level_pct'], res_df['f1_score'], marker='s', color='tab:blue', label='F1 Score', linewidth=2)
    ax1.plot(res_df['noise_level_pct'], res_df['triage_precision'], marker='^', color='tab:orange', label='Precision', linewidth=2)
    ax1.set_ylim(0.5, 1.05)
    ax1.legend(loc='lower left')
    
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('Missed Incidents (Count)', color=color, fontweight='bold')
    ax2.bar(res_df['noise_level_pct'], res_df['missed_incidents'], alpha=0.3, color='tab:red', width=1.5, label='Missed Incidents')
    ax2.set_ylim(0, max(5, max(res_df['missed_incidents']) * 2))
    
    plt.title("Performance Degradation Profile under Controlled Feature Perturbations", fontsize=12, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_png, dpi=200)
    plt.close()
    
    print(f"Noise robustness experiment complete:")
    print(f"  CSV: {output_csv}")
    print(f"  PNG: {output_png}")
    return res_df

if __name__ == "__main__":
    run_noise_robustness_experiment()
