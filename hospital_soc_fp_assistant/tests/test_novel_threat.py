"""
Adversarial Tests for Novel Threat Detection and Model Deception Resistance.
Verifies that the Assistant NEVER suppresses novel attacks or deceptive alerts targeting critical medical devices.
"""

import pytest
import joblib
import pandas as pd
import numpy as np
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from anomaly_detection import MedicalDeviceNoveltyDetector

@pytest.fixture(scope="module")
def safety_components():
    fp_model_data = joblib.load("models/false_positive_model.joblib")
    detector = MedicalDeviceNoveltyDetector.load("models/anomaly_model.joblib")
    return {
        "pipeline": fp_model_data["pipeline"],
        "detector": detector,
        "features": fp_model_data["features"]
    }

def test_novel_medical_device_threat(safety_components):
    """
    Test 3 — Novel medical-device threat:
    Critical medical device (Infusion Pump) communicates with a previously unseen external destination IP.
    Expected: Recommendation MUST be INVESTIGATE or ESCALATE. The system must NOT suppress it.
    """
    novel_alert = {
        "alert_id": "TEST-NOVEL-01",
        "severity": "MEDIUM",
        "severity_score": 2,
        "device_criticality": "CRITICAL",
        "device_criticality_score": 4,
        "failed_login_count": 0,
        "login_attempts": 0,
        "event_count": 8,
        "destination_port": 9001,
        "unusual_time": 1,
        "unusual_destination": 1,
        "historical_alert_count": 30,
        "historical_false_positive_rate": 0.85,
        "known_scanner": 0,
        "maintenance_window": 0,
        "latency_seconds": 1.0,
        "high_failure_rate": 0.0,
        "protocol": "TCP",
        "detection_source": "Network NIDS",
        "device_type": "Infusion Pump",
        "network_segment": "Medical-Device-VLAN"
    }
    
    # Compute ML and Anomaly metrics
    cols = safety_components["features"]["numeric"] + safety_components["features"]["categorical"]
    df = pd.DataFrame([novel_alert])[cols]
    threat_prob = safety_components["pipeline"].predict_proba(df)[0, 1]
    scores, novelties = safety_components["detector"].predict_anomaly(pd.DataFrame([novel_alert]))
    
    rec, reason, requires_review = safety_components["detector"].evaluate_safety_guardrails(
        novel_alert,
        ml_is_threat=(threat_prob >= 0.50),
        ml_threat_prob=threat_prob,
        anomaly_score=scores[0],
        is_novelty=novelties[0]
    )
    
    # Safety Assertion: Must NOT be suppressed as false positive
    assert rec != "LIKELY_FALSE_POSITIVE", f"CRITICAL SAFETY VIOLATION: Novel medical device threat was suppressed as {rec}"
    assert requires_review is True, "Must require analyst review"
    assert rec in ["INVESTIGATE", "ESCALATE", "REVIEW"]

def test_model_deception_adversarial_bypass(safety_components):
    """
    Test 7 — Model deception:
    Create an alert crafted to mimic historical false positives (e.g. low severity, high historical FP rate, routine event count)
    BUT maliciously targeting a CRITICAL device with unseen destination, unusual port, and off-hours timing.
    Expected: The Novelty & Safety guardrail layer MUST override any ML false-positive recommendation.
    """
    deceptive_alert = {
        "alert_id": "TEST-DECEIVE-01",
        "severity": "LOW",  # Crafting: make severity LOW like routine scanner alerts
        "severity_score": 1,
        "device_criticality": "CRITICAL",  # Attack target: Ventilator
        "device_criticality_score": 4,
        "failed_login_count": 0,
        "login_attempts": 0,
        "event_count": 2,
        "destination_port": 4444,  # Meterpreter/reverse shell port
        "unusual_time": 1,         # Middle of the night
        "unusual_destination": 1,  # Unseen external C2 IP
        "historical_alert_count": 50,
        "historical_false_positive_rate": 0.96,  # Crafting: spoofing high historical FP rate
        "known_scanner": 0,
        "maintenance_window": 0,
        "latency_seconds": 1.2,
        "high_failure_rate": 0.0,
        "protocol": "TCP",
        "detection_source": "Medical Device Gateway",
        "device_type": "Ventilator",
        "network_segment": "Medical-Device-VLAN"
    }
    
    cols = safety_components["features"]["numeric"] + safety_components["features"]["categorical"]
    df = pd.DataFrame([deceptive_alert])[cols]
    threat_prob = safety_components["pipeline"].predict_proba(df)[0, 1]
    scores, novelties = safety_components["detector"].predict_anomaly(pd.DataFrame([deceptive_alert]))
    
    rec, reason, requires_review = safety_components["detector"].evaluate_safety_guardrails(
        deceptive_alert,
        ml_is_threat=(threat_prob >= 0.50),
        ml_threat_prob=threat_prob,
        anomaly_score=scores[0],
        is_novelty=novelties[0]
    )
    
    # Assert that safety layer prevents spoofed suppression
    assert rec != "LIKELY_FALSE_POSITIVE", "Deceptive alert successfully bypassed ML without safety layer!"
    assert requires_review is True
    assert rec in ["INVESTIGATE", "REVIEW", "ESCALATE"]
    assert "safety" in reason.lower() or "anomaly" in reason.lower() or "critical" in reason.lower()
