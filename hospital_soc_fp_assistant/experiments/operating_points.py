"""
Controlled Missed-Incident Operating Points Experiment for Hospital SOC Assistant.
Evaluates trade-offs between analyst hours saved and allowed missed-incident tolerances
(0.0%, 0.5%, 1.0%, 2.0%), generating operating_points.csv and operating_points.png.
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from threshold_calibration import calibrate_thresholds

def run_operating_points_experiment(
    calib_csv="reports/threshold_calibration.csv",
    output_csv="reports/operating_points.csv",
    output_png="reports/operating_points.png",
    baseline_hours=475.33
):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    if not os.path.exists(calib_csv):
        calib_df = calibrate_thresholds(output_csv=calib_csv)
    else:
        calib_df = pd.read_csv(calib_csv)
        
    total_incidents = 1231
    tolerances = [0.0, 0.005, 0.010, 0.020] # 0.0%, 0.5%, 1.0%, 2.0%
    
    operating_points = []
    
    for tol in tolerances:
        max_allowed_missed = int(total_incidents * tol)
        # Filter candidate thresholds where missed incidents <= max_allowed_missed and critical device missed == 0
        valid = calib_df[
            (calib_df["missed_incidents"] <= max_allowed_missed) &
            (calib_df["critical_device_missed_incidents"] == 0)
        ]
        
        if len(valid) > 0:
            # Select the point that minimizes analyst hours (maximizes savings)
            best_point = valid.sort_values(by="analyst_hours", ascending=True).iloc[0].to_dict()
            hours_saved = round(baseline_hours - best_point["analyst_hours"], 2)
            pct_saved = round((hours_saved / baseline_hours) * 100, 2)
            
            operating_points.append({
                "missed_incident_tolerance_pct": round(tol * 100, 1),
                "max_allowed_missed": max_allowed_missed,
                "optimal_threat_threshold": best_point["threat_threshold"],
                "optimal_anomaly_threshold": best_point["anomaly_threshold"],
                "actual_missed_incidents": int(best_point["missed_incidents"]),
                "threat_recall": best_point["threat_recall"],
                "triage_precision": best_point["triage_precision"],
                "f1_score": best_point["f1_score"],
                "alerts_reviewed": int(best_point["alerts_reviewed"]),
                "alerts_suppressed": int(best_point["alerts_suppressed"]),
                "analyst_hours": best_point["analyst_hours"],
                "hours_saved": hours_saved,
                "percentage_hours_saved": pct_saved,
                "safety_gate": "PASSED" if best_point["critical_device_missed_incidents"] == 0 else "FAILED"
            })
            
    op_df = pd.DataFrame(operating_points)
    op_df.to_csv(output_csv, index=False)
    
    # Generate Operating Points Curve Chart
    plt.figure(figsize=(7, 4.5))
    plt.plot(
        op_df["missed_incident_tolerance_pct"],
        op_df["analyst_hours"],
        marker='o',
        color='#2563eb',
        linewidth=2.5,
        label='Proposed System Workload'
    )
    plt.axhline(baseline_hours, color='#dc2626', linestyle='--', label=f'Baseline SOC Workload ({baseline_hours:.1f} hrs)')
    
    for idx, row in op_df.iterrows():
        plt.annotate(
            f"{row['analyst_hours']} hrs\n(-{row['percentage_hours_saved']}%)",
            (row["missed_incident_tolerance_pct"], row["analyst_hours"]),
            textcoords="offset points",
            xytext=(0, 10),
            ha='center',
            fontweight='bold',
            fontsize=9
        )
        
    plt.title("Analyst Workload vs. Missed-Incident Tolerance Policy", fontsize=11, fontweight='bold')
    plt.xlabel("Configured Missed-Incident Tolerance (%)", fontweight='bold')
    plt.ylabel("Required Analyst Workload (Hours)", fontweight='bold')
    plt.ylim(200, baseline_hours * 1.15)
    plt.legend(loc='center right')
    plt.tight_layout()
    plt.savefig(output_png, dpi=200)
    plt.close()
    
    print(f"Operating points analysis complete:")
    print(f"  CSV: {output_csv}")
    print(f"  PNG: {output_png}")
    return op_df

if __name__ == "__main__":
    run_operating_points_experiment()
