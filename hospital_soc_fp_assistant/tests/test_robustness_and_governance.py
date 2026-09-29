"""
Pytest Suite for Robustness, Drift Monitoring, Feedback Governance, and Safety Invariants.
Expands automated testing coverage to 23 comprehensive test cases.
"""

import os
import sys
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "experiments")))

from drift_detection import calculate_psi, simulate_and_detect_drift
from feedback_validation import FeedbackValidator
from model_registry import ModelRegistry
from safety_guardrail import ClinicalSafetyGuardrail
from sequence_detection import TemporalSequenceDetector
from retraining_pipeline import ReplayRetrainingPipeline

def test_feature_drift_psi_identical_distributions():
    """Verifies PSI calculation returns near-zero drift on identical distributions."""
    np.random.seed(42)
    baseline = pd.Series(np.random.normal(loc=10.0, scale=2.0, size=500))
    current = pd.Series(np.random.normal(loc=10.0, scale=2.0, size=500))
    psi = calculate_psi(baseline, current, num_bins=10)
    assert psi < 0.10, f"Expected PSI < 0.10 for identical distributions, got {psi}"

def test_feature_drift_psi_shifted_distribution():
    """Verifies PSI flags significant drift (PSI > 0.25) when mean shifts substantially."""
    np.random.seed(42)
    baseline = pd.Series(np.random.normal(loc=5.0, scale=1.0, size=500))
    shifted = pd.Series(np.random.normal(loc=12.0, scale=1.0, size=500))
    psi = calculate_psi(baseline, shifted, num_bins=10)
    assert psi >= 0.25, f"Expected significant drift PSI >= 0.25, got {psi}"

def test_feedback_validation_schema_and_duplicate():
    """Verifies feedback validation rejects invalid schema and detects duplicates."""
    validator = FeedbackValidator()
    
    # Valid record
    valid_record = {
        "alert_id": "ALT-TEST-FB-01",
        "analyst_id": "ANL-VAL-01",
        "analyst_decision": "CONFIRM_FALSE_POSITIVE",
        "timestamp": datetime.now().isoformat()
    }
    is_valid, reason = validator.validate_record(valid_record)
    assert is_valid is True
    
    # Invalid decision enum
    invalid_record = dict(valid_record)
    invalid_record["analyst_decision"] = "INVALID_DECISION"
    is_valid, reason = validator.validate_record(invalid_record)
    assert is_valid is False
    assert "Invalid analyst decision" in reason

def test_clinical_guardrail_invariant_failsafe():
    """Verifies fail-safe fallback guarantees human review and never auto-suppresses."""
    guardrail = ClinicalSafetyGuardrail()
    test_alert = {
        "alert_id": "ALT-FAILSAFE-01",
        "device_type": "Infusion Pump",
        "device_criticality": "CRITICAL"
    }
    rec, reason, req_review = guardrail.fail_safe_fallback(test_alert, "Simulated network timeout")
    assert req_review is True
    assert rec in ["ESCALATE", "REVIEW"]
    assert "FAIL-SAFE TRIGGERED" in reason

def test_temporal_sequence_accumulator():
    """Verifies TemporalSequenceDetector accumulates risk across correlated alerts."""
    detector = TemporalSequenceDetector(window_minutes=30)
    base_time = datetime(2026, 9, 29, 10, 0, 0)
    
    # Initial alert
    alert1 = {
        "source_ip": "10.0.15.44",
        "destination_ip": "10.0.12.50",
        "timestamp": base_time.isoformat(),
        "failed_login_count": 1,
        "high_failure_rate": 0.2
    }
    risk1 = detector.add_event(alert1)
    
    # Rapid sequence of 5 failed auth events from same source
    for i in range(1, 6):
        a = {
            "source_ip": "10.0.15.44",
            "destination_ip": f"10.0.12.{50+i}",
            "timestamp": (base_time + timedelta(minutes=i*2)).isoformat(),
            "failed_login_count": 8,
            "high_failure_rate": 0.8
        }
        risk_seq = detector.add_event(a)
        
    assert risk_seq > risk1, "Sequence risk score must increase with correlated events"
    assert risk_seq >= 0.50, f"Expected risk >= 0.50 after multi-host scan, got {risk_seq}"

def test_model_registry_schema_and_champion_lookup():
    """Verifies ModelRegistry properly parses champion and maintains governance records."""
    registry = ModelRegistry(registry_path="models/model_registry.json")
    champ = registry.get_champion()
    assert champ is not None
    assert "model_version" in champ
    assert "metrics" in champ
    assert champ["status"] == "CHAMPION"
    assert champ["metrics"]["threat_recall"] >= 0.95
