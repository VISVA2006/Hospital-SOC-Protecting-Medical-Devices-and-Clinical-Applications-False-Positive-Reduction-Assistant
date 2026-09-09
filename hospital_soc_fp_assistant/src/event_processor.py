"""
Event Integrity and Stream Processing Module for Hospital SOC.
Handles duplicate detection, delayed event reconciliation, and out-of-order event sequence reconstruction.
"""

import hashlib
import pandas as pd
from datetime import datetime

class EventProcessor:
    """
    Manages event streaming integrity:
    1. Deduplication using event_id or fingerprint
    2. Latency calculation and delayed arrival handling
    3. Out-of-order buffer re-sequencing
    """
    def __init__(self, delay_threshold_seconds=180):
        self.delay_threshold_seconds = delay_threshold_seconds
        self.seen_event_ids = set()
        self.seen_fingerprints = {}
        self.duplicate_audit_log = []
        self.delayed_audit_log = []
        
    def generate_fingerprint(self, row):
        """Generates a deterministic hash for deduplicating alerts without valid IDs."""
        key = f"{row.get('source_ip')}_{row.get('destination_ip')}_{row.get('alert_type')}_{row.get('device_id')}_{str(row.get('timestamp'))[:16]}"
        return hashlib.sha256(key.encode()).hexdigest()
        
    def process_event(self, event_dict):
        """
        Processes a single incoming event.
        Returns (is_duplicate: bool, processed_event: dict)
        """
        processing_time = datetime.now()
        event = dict(event_dict)
        event["processing_timestamp"] = processing_time.isoformat()
        
        event_id = event.get("event_id")
        fp = self.generate_fingerprint(event)
        
        # Check duplicate
        is_dup = False
        if event_id and event_id in self.seen_event_ids:
            is_dup = True
        elif fp in self.seen_fingerprints:
            is_dup = True
            
        if is_dup:
            self.seen_fingerprints[fp] = self.seen_fingerprints.get(fp, 1) + 1
            self.duplicate_audit_log.append({
                "event_id": event_id,
                "fingerprint": fp,
                "received_timestamp": event.get("received_timestamp"),
                "first_seen": True
            })
            return True, None  # Suppress duplicate emission
            
        # Register new event
        if event_id:
            self.seen_event_ids.add(event_id)
        self.seen_fingerprints[fp] = 1
        
        # Calculate latency & delayed flag
        try:
            ts = pd.to_datetime(event.get("timestamp"))
            r_ts = pd.to_datetime(event.get("received_timestamp", processing_time))
            latency = (r_ts - ts).total_seconds()
            event["latency_seconds"] = max(0.0, latency)
            event["is_delayed"] = 1 if latency > self.delay_threshold_seconds else 0
            if event["is_delayed"]:
                self.delayed_audit_log.append({
                    "event_id": event_id,
                    "latency_seconds": latency,
                    "device_criticality": event.get("device_criticality")
                })
        except Exception:
            event["latency_seconds"] = 0.0
            event["is_delayed"] = 0
            
        return False, event

    def process_batch(self, df):
        """
        Processes a batch of raw alerts:
        1. Identifies and removes duplicate events, preserving only one logical event
        2. Annotates delayed events
        3. Reorders out-of-order arrivals by true generation timestamp
        """
        initial_count = len(df)
        df_copy = df.copy()
        
        # Ensure proper timestamp types
        df_copy["parsed_ts"] = pd.to_datetime(df_copy["timestamp"], errors="coerce")
        df_copy["parsed_rec_ts"] = pd.to_datetime(df_copy["received_timestamp"], errors="coerce")
        
        # Deduplication based on event_id, keeping first occurrence
        if "event_id" in df_copy.columns:
            dup_mask = df_copy.duplicated(subset=["event_id"], keep="first")
            num_dups = int(dup_mask.sum())
            deduped_df = df_copy[~dup_mask].copy()
        else:
            deduped_df = df_copy.drop_duplicates().copy()
            num_dups = initial_count - len(deduped_df)
            
        # Delayed event flag
        latency_sec = (deduped_df["parsed_rec_ts"] - deduped_df["parsed_ts"]).dt.total_seconds().fillna(0.0).clip(lower=0.0)
        deduped_df["latency_seconds"] = latency_sec
        deduped_df["is_delayed"] = (latency_sec > self.delay_threshold_seconds).astype(int)
        num_delayed = int(deduped_df["is_delayed"].sum())
        
        # Detect and reconstruct out-of-order sequence:
        # Check if received_timestamp ordering matches true timestamp ordering
        is_out_of_order = not deduped_df["parsed_ts"].is_monotonic_increasing
        # Sort chronologically by true generation timestamp
        reconstructed_df = deduped_df.sort_values(by=["parsed_ts", "parsed_rec_ts"]).reset_index(drop=True)
        
        # Clean temporary columns
        reconstructed_df = reconstructed_df.drop(columns=["parsed_ts", "parsed_rec_ts"])
        
        stats = {
            "initial_events": initial_count,
            "duplicates_removed": num_dups,
            "delayed_events_detected": num_delayed,
            "was_out_of_order": is_out_of_order,
            "reconstructed_event_count": len(reconstructed_df)
        }
        return reconstructed_df, stats

if __name__ == "__main__":
    import os
    if os.path.exists("data/cleaned_alerts.csv"):
        df = pd.read_csv("data/cleaned_alerts.csv")
        processor = EventProcessor()
        clean_df, stats = processor.process_batch(df)
        print("Event Processor Batch Results:")
        for k, v in stats.items():
            print(f"  {k}: {v}")
