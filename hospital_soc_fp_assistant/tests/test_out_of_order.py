"""
Tests for Out-of-Order Event Stream Sequence Reconstruction.
Verifies that events arriving out of chronological order are correctly re-sequenced by true timestamp.
"""

import pytest
import pandas as pd
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from event_processor import EventProcessor

def test_out_of_order_stream_reconstruction():
    """
    Test 5: Inject events in random out-of-order timestamp sequence:
    Arrival order: 10:05, 10:01, 10:04, 10:02, 10:03.
    Expected: System reconstructs strictly chronological sequence (10:01, 10:02, 10:03, 10:04, 10:05)
    without dropping or corrupting any record.
    """
    processor = EventProcessor()
    
    out_of_order_rows = [
        {"event_id": "EVT-05", "timestamp": "2026-08-01T10:05:00", "received_timestamp": "2026-08-01T10:05:01", "step": 5},
        {"event_id": "EVT-01", "timestamp": "2026-08-01T10:01:00", "received_timestamp": "2026-08-01T10:05:02", "step": 1},
        {"event_id": "EVT-04", "timestamp": "2026-08-01T10:04:00", "received_timestamp": "2026-08-01T10:05:03", "step": 4},
        {"event_id": "EVT-02", "timestamp": "2026-08-01T10:02:00", "received_timestamp": "2026-08-01T10:05:04", "step": 2},
        {"event_id": "EVT-03", "timestamp": "2026-08-01T10:03:00", "received_timestamp": "2026-08-01T10:05:05", "step": 3},
    ]
    
    df = pd.DataFrame(out_of_order_rows)
    reconstructed_df, stats = processor.process_batch(df)
    
    assert stats["was_out_of_order"] is True, "Pipeline must flag the stream as initially out of order"
    assert len(reconstructed_df) == 5, "No records should be lost during resequencing"
    
    # Verify strict ascending order of reconstructed timestamps
    ordered_events = list(reconstructed_df["event_id"])
    expected_order = ["EVT-01", "EVT-02", "EVT-03", "EVT-04", "EVT-05"]
    assert ordered_events == expected_order, f"Expected {expected_order}, got {ordered_events}"
    
    ordered_steps = list(reconstructed_df["step"])
    assert ordered_steps == [1, 2, 3, 4, 5]
