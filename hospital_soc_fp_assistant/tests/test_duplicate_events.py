"""
Tests for Duplicate Event Handling and Deduplication Integrity.
Verifies that redundant or flooded alerts are collapsed to a single logical event.
"""

import pytest
import pandas as pd
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from event_processor import EventProcessor

def test_duplicate_flood_ten_times():
    """
    Test 4: Send the exact same event 10 times.
    Expected: Exactly 1 logical event remains; 9 duplicate events suppressed.
    """
    processor = EventProcessor()
    
    base_event = {
        "alert_id": "ALT-FLOOD-01",
        "event_id": "EVT-UNIQUE-9999",
        "timestamp": "2026-08-10T14:30:00",
        "received_timestamp": "2026-08-10T14:30:05",
        "alert_type": "Scheduled Vulnerability Scan",
        "severity": "LOW",
        "source_ip": "10.0.10.50",
        "destination_ip": "10.0.12.44",
        "device_id": "DEV-INF-102"
    }
    
    emitted_events = []
    duplicate_count = 0
    
    for i in range(10):
        # Even if alert_id changes slightly in a storm, event_id and fingerprint match
        evt = base_event.copy()
        evt["alert_id"] = f"ALT-FLOOD-01-{i}"
        is_dup, processed = processor.process_event(evt)
        if is_dup:
            duplicate_count += 1
        else:
            emitted_events.append(processed)
            
    assert len(emitted_events) == 1, "Exactly one logical event must be emitted"
    assert duplicate_count == 9, "Nine duplicates must be suppressed"
    assert emitted_events[0]["event_id"] == "EVT-UNIQUE-9999"

def test_batch_deduplication():
    """
    Verifies batch deduplication logic across a DataFrame containing multiple copies of alerts.
    """
    processor = EventProcessor()
    rows = [
        {"event_id": "E-101", "timestamp": "2026-08-01T10:00:00", "received_timestamp": "2026-08-01T10:00:02"},
        {"event_id": "E-101", "timestamp": "2026-08-01T10:00:00", "received_timestamp": "2026-08-01T10:00:05"},
        {"event_id": "E-102", "timestamp": "2026-08-01T10:01:00", "received_timestamp": "2026-08-01T10:01:03"},
        {"event_id": "E-101", "timestamp": "2026-08-01T10:00:00", "received_timestamp": "2026-08-01T10:00:10"}
    ]
    df = pd.DataFrame(rows)
    deduped_df, stats = processor.process_batch(df)
    
    assert stats["initial_events"] == 4
    assert stats["duplicates_removed"] == 2
    assert len(deduped_df) == 2
    assert set(deduped_df["event_id"]) == {"E-101", "E-102"}
