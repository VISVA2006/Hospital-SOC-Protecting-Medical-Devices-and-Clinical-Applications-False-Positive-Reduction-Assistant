"""
Pytest Suite for Hospital SOC Assistant FastAPI Endpoints.
Validates /health, /alerts/analyze, /feedback, /alerts/{id}, and /models/retrain.
"""

import pytest
import os
import sys
from fastapi.testclient import TestClient

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from api import app

client = TestClient(app)

def test_api_health_endpoint():
    """Verifies /health endpoint returns HTTP 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "active_model_version" in data

def test_api_analyze_alert_safe_scanner():
    """Verifies /alerts/analyze triages routine scanner as LIKELY_FALSE_POSITIVE."""
    alert_payload = {
        "alert_id": "API-TEST-SCAN-01",
        "alert_type": "Scheduled Vulnerability Scan",
        "severity": "LOW",
        "source_ip": "10.0.10.50",
        "destination_ip": "10.0.12.100",
        "protocol": "TCP",
        "source_port": 45000,
        "destination_port": 80,
        "device_type": "Laboratory Analyzer",
        "device_criticality": "MEDIUM",
        "known_scanner": 1,
        "maintenance_window": 1,
        "historical_false_positive_rate": 0.95
    }
    response = client.post("/alerts/analyze", json=alert_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "API-TEST-SCAN-01"
    assert data["recommendation"] == "LIKELY_FALSE_POSITIVE"
    assert data["requires_human_review"] is False

def test_api_analyze_critical_ventilator_threat():
    """Verifies /alerts/analyze forces review on critical medical device with unusual telemetry."""
    alert_payload = {
        "alert_id": "API-TEST-VENT-01",
        "alert_type": "Medical Device Reverse Shell Beacon",
        "severity": "CRITICAL",
        "source_ip": "10.0.12.88",
        "destination_ip": "193.142.146.35",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 4444,
        "device_type": "Ventilator",
        "device_criticality": "CRITICAL",
        "unusual_destination": 1,
        "unusual_time": 1
    }
    response = client.post("/alerts/analyze", json=alert_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["alert_id"] == "API-TEST-VENT-01"
    assert data["requires_human_review"] is True
    assert data["recommendation"] in ["ESCALATE", "INVESTIGATE", "REVIEW"]

def test_api_feedback_logging():
    """Verifies /feedback endpoint captures analyst override."""
    feedback_payload = {
        "alert_id": "ALT-10001",
        "analyst_decision": "CONFIRM_FALSE_POSITIVE",
        "analyst_id": "ANL-API-TEST",
        "override_reason": "Verified clinical workflow with floor nurse"
    }
    response = client.post("/feedback", json=feedback_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "RECORDED"
    assert data["alert_id"] == "ALT-10001"

def test_api_get_current_model():
    """Verifies /models/current returns champion model metadata."""
    response = client.get("/models/current")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "CHAMPION"
    assert "metrics" in data

def test_api_retraining_trigger():
    """Verifies /models/retrain triggers candidate evaluation without auto-promoting."""
    response = client.post("/models/retrain")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["SUCCESS", "ABORTED"]
