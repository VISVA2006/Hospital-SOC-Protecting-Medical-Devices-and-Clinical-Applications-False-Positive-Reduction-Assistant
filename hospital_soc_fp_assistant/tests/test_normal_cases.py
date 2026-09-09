"""
Unit and Integration Tests for Normal SOC Cases.
Verifies standard false-positive suppression and suspicious alert triage.
"""

import pytest
import joblib
import pandas as pd
import numpy as np

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from baseline import RuleBasedBaseline
from anomaly_detection import MedicalDeviceNoveltyDetector

@pytest.fixture(scope="module")
def models():
    fp_model_data = joblib.load("models/false_positive_model.joblib")
    anomaly_detector = MedicalDeviceNoveltyDetector.load("models/anomaly_model.joblib")
    baseline = RuleBasedBaseline()
    return {
        "pipeline": fp_model_data["pipeline"],
        "detector": anomaly_detector,
        "baseline": baseline,
        "features": fp_model_data["features"]
    }

def test_normal_false_positive_scanner(models):
    """
    Test 1: Known scanner generating repetitive scheduled traffic during maintenance.
    Expected: Baseline and Proposed recommend LIKELY_FALSE_POSITIVE.
    """
    alert = {
        "alert_id": "TEST-SCAN-01",
        "severity": "LOW",
        "severity_score": 1,
        "device_criticality": "MEDIUM",
        "device_criticality_score": 2,
        "failed_login_count": 0,
        "login_attempts": 0,
        "event_count": 50,
        "destination_port": 80,
        "unusual_time": 0,
        "unusual_destination": 0,
        "historical_alert_count": 45,
        "historical_false_positive_rate": 0.95,
        "known_scanner": 1,
        "maintenance_window": 1,
        "latency_seconds": 2.0,
        "high_failure_rate": 0.0,
        "protocol": "TCP",
        "detection_source": "Network NIDS",
        "device_type": "Laboratory Analyzer",
        "network_segment": "Medical-Device-VLAN"
    }
    
    # Baseline check
    base_rec = models["baseline"].predict_single(alert)
    assert base_rec == "LIKELY_FALSE_POSITIVE"
    
    # ML check
    cols = models["features"]["numeric"] + models["features"]["categorical"]
    df = pd.DataFrame([alert])[cols]
    threat_prob = models["pipeline"].predict_proba(df)[0, 1]
    
    scores, novelties = models["detector"].predict_anomaly(pd.DataFrame([alert]))
    rec, reason, _ = models["detector"].evaluate_safety_guardrails(
        alert,
        ml_is_threat=(threat_prob >= 0.50),
        ml_threat_prob=threat_prob,
        anomaly_score=scores[0],
        is_novelty=novelties[0]
    )
    assert rec == "LIKELY_FALSE_POSITIVE"
    assert threat_prob < 0.25

def test_real_suspicious_alert_brute_force(models):
    """
    Test 2: Repeated failed authentication from unusual external source.
    Expected: Baseline flags SUSPICIOUS, Proposed recommends INVESTIGATE / ESCALATE.
    """
    alert = {
        "alert_id": "TEST-BRUTE-01",
        "severity": "HIGH",
        "severity_score": 3,
        "device_criticality": "HIGH",
        "device_criticality_score": 3,
        "failed_login_count": 35,
        "login_attempts": 35,
        "event_count": 35,
        "destination_port": 22,
        "unusual_time": 1,
        "unusual_destination": 1,
        "historical_alert_count": 2,
        "historical_false_positive_rate": 0.10,
        "known_scanner": 0,
        "maintenance_window": 0,
        "latency_seconds": 1.5,
        "high_failure_rate": 1.0,
        "protocol": "SSH",
        "detection_source": "Host EDR",
        "device_type": "PACS Server",
        "network_segment": "Imaging-PACS-VLAN"
    }
    
    base_rec = models["baseline"].predict_single(alert)
    assert base_rec in ["SUSPICIOUS", "HIGH_RISK", "NEEDS_REVIEW"]
    
    cols = models["features"]["numeric"] + models["features"]["categorical"]
    df = pd.DataFrame([alert])[cols]
    threat_prob = models["pipeline"].predict_proba(df)[0, 1]
    scores, novelties = models["detector"].predict_anomaly(pd.DataFrame([alert]))
    
    rec, reason, requires_review = models["detector"].evaluate_safety_guardrails(
        alert,
        ml_is_threat=(threat_prob >= 0.50),
        ml_threat_prob=threat_prob,
        anomaly_score=scores[0],
        is_novelty=novelties[0]
    )
    assert requires_review is True
    assert rec in ["INVESTIGATE", "ESCALATE"]
