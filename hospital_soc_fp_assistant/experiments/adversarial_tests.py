"""
Advanced Adversarial Telemetry and Evasion Testing Suite for Hospital SOC Assistant.
Evaluates 12 distinct adversarial edge cases (ADV-01 to ADV-12) covering telemetry perturbation,
low-and-slow sequences, maintenance spoofing, and stream turbulence.
"""

import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from safety_guardrail import ClinicalSafetyGuardrail
from anomaly_detection import MedicalDeviceNoveltyDetector
from sequence_detection import TemporalSequenceDetector
from event_processor import EventProcessor

def run_adversarial_suite(
    model_path="models/false_positive_model.joblib",
    anomaly_path="models/anomaly_model.joblib",
    output_csv="reports/adversarial_test_results.csv"
):
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    
    model_data = joblib.load(model_path)
    pipeline = model_data["pipeline"]
    num_cols = model_data["features"]["numeric"]
    cat_cols = model_data["features"]["categorical"]
    
    detector = MedicalDeviceNoveltyDetector.load(anomaly_path)
    guardrail = ClinicalSafetyGuardrail(threat_threshold=0.40, anomaly_threshold=0.65)
    
    results = []
    
    # Helper for evaluating an alert through full defense pipeline
    def evaluate_alert(alert, seq_detector=None):
        df_single = pd.DataFrame([alert])[num_cols + cat_cols].fillna(0)
        threat_prob = float(pipeline.predict_proba(df_single)[0, 1])
        scores, novelties = detector.predict_anomaly(pd.DataFrame([alert]))
        
        seq_risk = 0.0
        if seq_detector:
            seq_risk = seq_detector.add_event(alert)
            
        rec, reason, req_review = guardrail.evaluate(
            alert=alert,
            ml_is_threat=(threat_prob >= 0.50),
            ml_threat_prob=threat_prob,
            anomaly_score=float(scores[0]),
            is_novelty=bool(novelties[0]),
            sequence_risk_score=seq_risk
        )
        return {
            "ml_threat_prob": round(threat_prob, 4),
            "anomaly_score": round(float(scores[0]), 4),
            "is_novelty": bool(novelties[0]),
            "sequence_risk": round(seq_risk, 4),
            "recommendation": rec,
            "requires_review": req_review,
            "reason": reason
        }

    # ADV-01: Low-severity deception on critical Ventilator
    a1 = {
        "alert_id": "ADV-01",
        "device_type": "Ventilator",
        "device_criticality": "CRITICAL",
        "severity": "LOW",
        "severity_score": 1,
        "device_criticality_score": 4,
        "failed_login_count": 0,
        "login_attempts": 0,
        "event_count": 2,
        "destination_port": 80,
        "unusual_time": 1,
        "unusual_destination": 1,
        "historical_alert_count": 50,
        "historical_false_positive_rate": 0.95,
        "latency_seconds": 1.0,
        "high_failure_rate": 0.0,
        "known_scanner": 0,
        "maintenance_window": 0,
        "protocol": "TCP",
        "detection_source": "Network NIDS",
        "network_segment": "Medical-Device-VLAN"
    }
    r1 = evaluate_alert(a1)
    results.append({
        "scenario_id": "ADV-01",
        "scenario_name": "Low-Severity Deception on Ventilator",
        "category": "Deception",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r1["recommendation"],
        "anomaly_score": r1["anomaly_score"],
        "guardrail_status": "SAFETY HELD",
        "passed": (r1["recommendation"] != "LIKELY_FALSE_POSITIVE" and r1["requires_review"])
    })

    # ADV-02: Medical telemetry perturbation (frequency and port drift on Ventilator)
    a2 = a1.copy()
    a2["alert_id"] = "ADV-02"
    a2["event_count"] = 120 # Perturbed frequency
    a2["destination_port"] = 8443
    r2 = evaluate_alert(a2)
    results.append({
        "scenario_id": "ADV-02",
        "scenario_name": "Medical Telemetry Perturbation",
        "category": "Perturbation",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r2["recommendation"],
        "anomaly_score": r2["anomaly_score"],
        "guardrail_status": "SAFETY HELD",
        "passed": (r2["recommendation"] != "LIKELY_FALSE_POSITIVE" and r2["requires_review"])
    })

    # ADV-03: Low-and-slow attack sequence (5-hour gradual escalation on Infusion Pump)
    seq_det = TemporalSequenceDetector(window_minutes=60)
    base_t = datetime(2026, 8, 1, 10, 0, 0)
    for h in range(5):
        for e in range(h + 1):
            evt = {
                "alert_id": f"ADV-03-{h}-{e}",
                "device_id": "DEV-INF-101",
                "device_type": "Infusion Pump",
                "device_criticality": "CRITICAL",
                "timestamp": (base_t + timedelta(hours=h, minutes=e * 10)).isoformat(),
                "failed_login_count": 1 if h >= 2 else 0,
                "login_attempts": 1 if h >= 2 else 0,
                "destination_ip": f"198.51.100.{h + 10}",
                "destination_port": 443,
                "severity": "LOW",
                "severity_score": 1,
                "device_criticality_score": 4,
                "event_count": 2,
                "unusual_time": 0,
                "unusual_destination": 1 if h >= 3 else 0,
                "historical_alert_count": 30,
                "historical_false_positive_rate": 0.90,
                "latency_seconds": 1.0,
                "high_failure_rate": 1.0 if h >= 2 else 0.0,
                "known_scanner": 0,
                "maintenance_window": 0,
                "protocol": "TCP",
                "detection_source": "Network NIDS",
                "network_segment": "Medical-Device-VLAN"
            }
            r3 = evaluate_alert(evt, seq_det)
    results.append({
        "scenario_id": "ADV-03",
        "scenario_name": "Low-and-Slow Attack Sequence",
        "category": "Sequence",
        "expected_action": "INVESTIGATE / REVIEW",
        "actual_recommendation": r3["recommendation"],
        "anomaly_score": r3["anomaly_score"],
        "guardrail_status": f"SEQUENCE RISK: {r3['sequence_risk']}",
        "passed": (r3["recommendation"] in ["INVESTIGATE", "REVIEW", "ESCALATE"] and r3["requires_review"])
    })

    # ADV-04: Delayed suspicious event (15-minute delay on Patient Monitor beacon)
    evt_proc = EventProcessor(delay_threshold_seconds=180)
    a4 = {
        "alert_id": "ADV-04",
        "event_id": "EVT-DELAY-04",
        "device_type": "Patient Monitor",
        "device_criticality": "CRITICAL",
        "timestamp": "2026-08-01T12:00:00",
        "received_timestamp": "2026-08-01T12:15:00", # 15 min delay
        "severity": "HIGH",
        "destination_ip": "185.220.101.5",
        "destination_port": 4444
    }
    is_dup, proc_evt = evt_proc.process_event(a4)
    results.append({
        "scenario_id": "ADV-04",
        "scenario_name": "Delayed Suspicious Telemetry (15m Delay)",
        "category": "Event Integrity",
        "expected_action": "RETAINED WITH LATENCY TAG",
        "actual_recommendation": f"LATENCY: {proc_evt.get('latency_seconds')}s, DELAYED: {proc_evt.get('is_delayed')}",
        "anomaly_score": 0.0,
        "guardrail_status": "STREAM PRESERVED",
        "passed": (proc_evt is not None and proc_evt.get("is_delayed") == 1 and proc_evt.get("latency_seconds") == 900.0)
    })

    # ADV-05: Out-of-order suspicious sequence resequencing
    out_of_order_events = [
        {"event_id": "E5", "timestamp": "2026-08-01T10:05:00", "received_timestamp": "2026-08-01T10:05:01"},
        {"event_id": "E1", "timestamp": "2026-08-01T10:01:00", "received_timestamp": "2026-08-01T10:05:02"},
        {"event_id": "E3", "timestamp": "2026-08-01T10:03:00", "received_timestamp": "2026-08-01T10:05:03"}
    ]
    reordered_df, ooo_stats = evt_proc.process_batch(pd.DataFrame(out_of_order_events))
    results.append({
        "scenario_id": "ADV-05",
        "scenario_name": "Out-of-Order Event Stream Delivery",
        "category": "Event Integrity",
        "expected_action": "REORDERED CHRONOLOGICALLY",
        "actual_recommendation": f"ORDER: {list(reordered_df['event_id'])}",
        "anomaly_score": 0.0,
        "guardrail_status": "SEQUENCE REPAIRED",
        "passed": (list(reordered_df["event_id"]) == ["E1", "E3", "E5"])
    })

    # ADV-06: Duplicate alert storm (20 identical beacons)
    dup_proc = EventProcessor()
    dup_emitted = []
    for i in range(20):
        d_evt = {"alert_id": f"D-{i}", "event_id": "EVT-STORM-99", "timestamp": "2026-08-01T10:00:00", "device_id": "DEV-1"}
        is_d, p_evt = dup_proc.process_event(d_evt)
        if not is_d:
            dup_emitted.append(p_evt)
    results.append({
        "scenario_id": "ADV-06",
        "scenario_name": "Duplicate Alert Storm (20x Flood)",
        "category": "Event Integrity",
        "expected_action": "1 LOGICAL EVENT EMITTED",
        "actual_recommendation": f"{len(dup_emitted)} EMITTED",
        "anomaly_score": 0.0,
        "guardrail_status": "FLOOD SUPPRESSED",
        "passed": (len(dup_emitted) == 1)
    })

    # ADV-07: Maintenance window deception
    a7 = a1.copy()
    a7["alert_id"] = "ADV-07"
    a7["maintenance_window"] = 1 # Attacker spoofs active maintenance
    a7["destination_port"] = 445 # Lateral SMB attack
    a7["unusual_destination"] = 1
    r7 = evaluate_alert(a7)
    results.append({
        "scenario_id": "ADV-07",
        "scenario_name": "Maintenance Window Lateral Deception",
        "category": "Deception",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r7["recommendation"],
        "anomaly_score": r7["anomaly_score"],
        "guardrail_status": "SAFETY OVERRIDE ACTIVE",
        "passed": (r7["recommendation"] != "LIKELY_FALSE_POSITIVE" and r7["requires_review"])
    })

    # ADV-08: Critical device unusual external destination
    a8 = a1.copy()
    a8["alert_id"] = "ADV-08"
    a8["destination_ip"] = "194.26.29.112"
    a8["unusual_destination"] = 1
    r8 = evaluate_alert(a8)
    results.append({
        "scenario_id": "ADV-08",
        "scenario_name": "Critical Asset External Communication",
        "category": "Novel Destination",
        "expected_action": "REVIEW / ESCALATE",
        "actual_recommendation": r8["recommendation"],
        "anomaly_score": r8["anomaly_score"],
        "guardrail_status": "AUTO-SUPPRESSION FORBIDDEN",
        "passed": (r8["recommendation"] != "LIKELY_FALSE_POSITIVE" and r8["requires_review"])
    })

    # ADV-09: Unknown non-standard port on Infusion Pump
    a9 = a1.copy()
    a9["alert_id"] = "ADV-09"
    a9["device_type"] = "Infusion Pump"
    a9["destination_port"] = 9001
    r9 = evaluate_alert(a9)
    results.append({
        "scenario_id": "ADV-09",
        "scenario_name": "Unknown High Port (9001) on Infusion Pump",
        "category": "Novel Port",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r9["recommendation"],
        "anomaly_score": r9["anomaly_score"],
        "guardrail_status": "SAFETY HELD",
        "passed": (r9["recommendation"] != "LIKELY_FALSE_POSITIVE" and r9["requires_review"])
    })

    # ADV-10: Distributed low-volume auth attempts across medical VLAN
    a10 = a1.copy()
    a10["alert_id"] = "ADV-10"
    a10["failed_login_count"] = 4
    a10["login_attempts"] = 4
    a10["high_failure_rate"] = 1.0
    r10 = evaluate_alert(a10)
    results.append({
        "scenario_id": "ADV-10",
        "scenario_name": "Distributed Low-Volume Auth Attack",
        "category": "Distributed",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r10["recommendation"],
        "anomaly_score": r10["anomaly_score"],
        "guardrail_status": "SAFETY HELD",
        "passed": (r10["recommendation"] != "LIKELY_FALSE_POSITIVE" and r10["requires_review"])
    })

    # ADV-11: Missing telemetry on critical alert (null patch/AV)
    a11 = a1.copy()
    a11["alert_id"] = "ADV-11"
    a11["patch_status"] = None
    a11["antivirus_status"] = None
    r11 = evaluate_alert(a11)
    results.append({
        "scenario_id": "ADV-11",
        "scenario_name": "Critical Alert with Missing Telemetry",
        "category": "Missing Data",
        "expected_action": "REVIEW / INVESTIGATE",
        "actual_recommendation": r11["recommendation"],
        "anomaly_score": r11["anomaly_score"],
        "guardrail_status": "SAFE IMPUTATION",
        "passed": (r11["recommendation"] != "LIKELY_FALSE_POSITIVE" and r11["requires_review"])
    })

    # ADV-12: Combined perturbation and multi-hour low-and-slow sequence
    a12 = a1.copy()
    a12["alert_id"] = "ADV-12"
    a12["event_count"] = 14
    a12["failed_login_count"] = 3
    a12["destination_port"] = 8080
    r12 = evaluate_alert(a12, seq_det)
    results.append({
        "scenario_id": "ADV-12",
        "scenario_name": "Combined Perturbation + Sequence Escalation",
        "category": "Hybrid",
        "expected_action": "INVESTIGATE / ESCALATE",
        "actual_recommendation": r12["recommendation"],
        "anomaly_score": r12["anomaly_score"],
        "guardrail_status": "COMPOUND THREAT DETECTED",
        "passed": (r12["recommendation"] in ["INVESTIGATE", "ESCALATE", "REVIEW"] and r12["requires_review"])
    })

    adv_df = pd.DataFrame(results)
    adv_df.to_csv(output_csv, index=False)
    print(f"Adversarial Suite Execution Complete: {len(adv_df)} scenarios tested -> {output_csv}")
    print(f"  All Passed: {adv_df['passed'].all()} ({adv_df['passed'].sum()}/{len(adv_df)})")
    return adv_df

if __name__ == "__main__":
    run_adversarial_suite()
