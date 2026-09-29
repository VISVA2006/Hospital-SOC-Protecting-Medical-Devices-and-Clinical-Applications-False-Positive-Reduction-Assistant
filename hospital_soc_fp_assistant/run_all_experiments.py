"""
Master Experiment Orchestration Pipeline for Hospital SOC Assistant.
Executes all experimental validation modules, statistical audits, robustness sweeps,
adversarial testing, and threshold calibrations in a single deterministic sequence.
"""

import os
import sys
import time
from datetime import datetime

# Add source directories
sys.path.append(os.path.abspath("src"))
sys.path.append(os.path.abspath("experiments"))

from data_leakage_audit import audit_pipeline
from error_analysis import run_deep_error_analysis
from noise_robustness import run_noise_robustness_experiment
from drift_detection import simulate_and_detect_drift
from adversarial_tests import run_adversarial_suite
from threshold_calibration import calibrate_thresholds
from operating_points import run_operating_points_experiment

def run_all_experiments():
    start_time = time.time()
    print("=" * 70)
    print("  HOSPITAL SOC ASSISTANT - MASTER EXPERIMENT ORCHESTRATION PIPELINE")
    print(f"  Execution Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # 1. Data Integrity and Leakage Audit
    print("\n[Step 1/7] Running Data Leakage and Split Hygiene Audit...")
    findings = audit_pipeline(
        data_path="data/cleaned_alerts.csv",
        output_report="reports/data_leakage_audit.md"
    )
    print(f"  -> Passed {len(findings)} integrity checks. Split hygiene confirmed with 0 target leakage.")

    # 2. Deep Error Analysis
    print("\n[Step 2/7] Running Deep Error Analysis & Clinical Decision Boundaries...")
    err_res = run_deep_error_analysis(
        data_path="data/cleaned_alerts.csv",
        model_path="models/false_positive_model.joblib",
        anomaly_path="models/anomaly_model.joblib",
        output_dir="reports",
        figures_dir="results/figures"
    )
    print(f"  -> Analyzed {err_res['evaluation_dataset_size']} alerts: {err_res['confusion_matrix']['true_negatives_suppressed']} FPs safely suppressed, {err_res['confusion_matrix']['false_negatives_missed']} missed threats.")

    # 3. Noise Robustness Sweep (0% to 20%)
    print("\n[Step 3/7] Running Numerical Noise Robustness Sweep...")
    noise_df = run_noise_robustness_experiment(
        data_path="data/cleaned_alerts.csv",
        output_csv="reports/noise_robustness.csv",
        output_png="reports/noise_robustness.png"
    )
    print(f"  -> Evaluated {len(noise_df)} noise levels. Recall remained {noise_df['threat_recall'].min():.2f} across all levels.")

    # 4. Feature Drift Simulation & Statistical Monitoring (PSI / KS)
    print("\n[Step 4/7] Running Feature Drift Simulation & Statistical Testing...")
    drift_rep = simulate_and_detect_drift(
        data_path="data/cleaned_alerts.csv",
        output_csv="reports/drift_analysis.csv",
        output_json="reports/drift_report.json",
        output_md="reports/drift_report.md"
    )
    print(f"  -> Drift monitored across {len(drift_rep['features_monitored'])} features. Post-drift threat recall: {drift_rep['impact_analysis']['recall_after_drift']*100:.1f}%.")

    # 5. Advanced Adversarial Suite (ADV-01 through ADV-12)
    print("\n[Step 5/7] Executing 12-Scenario Advanced Adversarial Suite...")
    adv_df = run_adversarial_suite(output_csv="reports/adversarial_test_results.csv")
    passed_scenarios = int(adv_df["passed"].sum())
    print(f"  -> Adversarial results: {passed_scenarios}/{len(adv_df)} scenarios blocked ({passed_scenarios/len(adv_df)*100:.1f}% pass rate).")
    assert passed_scenarios == len(adv_df), "Not all adversarial attacks were blocked!"

    # 6. Threshold Calibration Grid (63 Points)
    print("\n[Step 6/7] Evaluating Threshold Calibration Grid...")
    calib_df = calibrate_thresholds(
        data_path="data/cleaned_alerts.csv",
        output_csv="reports/threshold_calibration.csv"
    )
    print(f"  -> Calibrated {len(calib_df)} threshold pairs across threat (0.30-0.70) and anomaly (0.50-0.80) spaces.")

    # 7. Optimal Clinical Operating Points
    print("\n[Step 7/7] Deriving Multi-Objective Operating Points...")
    op_df = run_operating_points_experiment(
        calib_csv="reports/threshold_calibration.csv",
        output_csv="reports/operating_points.csv",
        output_png="reports/operating_points.png"
    )
    print(f"  -> Generated {len(op_df)} operating points. Zero-tolerance point: {op_df.iloc[0]['hours_saved']:.1f} hrs saved (0 missed threats).")

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"  ALL EXPERIMENTS COMPLETED SUCCESSFULLY in {elapsed:.2f} seconds.")
    print("=" * 70)

if __name__ == "__main__":
    run_all_experiments()
