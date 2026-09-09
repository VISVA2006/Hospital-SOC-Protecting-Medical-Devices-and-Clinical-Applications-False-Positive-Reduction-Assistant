"""
Tests for Delayed Event Reconciliation.
Verifies that delayed alerts from network jitter or offline devices are properly ingested,
flagged with accurate latency, and not corrupted or discarded.
"""

import pytest
import pandas as pd
from datetime import datetime
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from event_processor import EventProcessor

def test_delayed_critical_event():
    """
    Test 6: Create an event at 10:01:00 but deliver it at 10:10:00 (9 minutes latency).
    Expected: Event remains valid, processed correctly, flagged as delayed, and preserves all payload fields.
    """
    processor = EventProcessor(delay_threshold_seconds=180) # 3 min threshold
    
    delayed_alert = {
        "alert_id": "ALT-DELAYED-99",
        "event_id": "EVT-DELAYED-99",
        "timestamp": "2026-08-01T10:01:00",
        "received_timestamp": "2026-08-01T10:10:00",
        "alert_type": "Medical Device Reverse Shell Beacon",
        "severity": "CRITICAL",
        "device_criticality": "CRITICAL",
        "device_type": "Ventilator",
        "device_id": "DEV-VEN-104",
        "source_ip": "10.0.12.88",
        "destination_ip": "193.142.146.35"
    }
    
    is_dup, processed = processor.process_event(delayed_alert)
    
    assert is_dup is False, "Delayed event should not be treated as a duplicate"
    assert processed is not None, "Processed event must be retained"
    assert processed["is_delayed"] == 1, "Must be flagged as delayed"
    assert processed["latency_seconds"] == 540.0, "Latency must match 9 minutes (540s)"
    assert processed["severity"] == "CRITICAL"
    assert processed["device_id"] == "DEV-VEN-104"
    assert "processing_timestamp" in processed
