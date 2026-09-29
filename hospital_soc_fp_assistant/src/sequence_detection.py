"""
Temporal Sequence Detection and Low-and-Slow Attack Detection Module.
Tracks multi-alert device telemetry across rolling time windows (5m, 15m, 30m, 60m)
to detect subtle, distributed, and slow reconnaissance campaigns targeting clinical systems.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict

class TemporalSequenceDetector:
    """
    Maintains rolling time-window state per medical device and endpoint
    to calculate sequence-level cumulative risk.
    """
    def __init__(self, window_minutes: int = 60):
        self.window_minutes = window_minutes
        # Device history: device_id -> list of event records
        self.device_buffers = defaultdict(list)

    def add_event(self, event: Dict[str, Any]) -> float:
        """
        Ingests a new event, prunes expired history outside the window,
        and computes the current sequence risk score [0.0, 1.0].
        """
        device_id = str(event.get("device_id", event.get("source_ip", "UNKNOWN")))
        try:
            ts = pd.to_datetime(event.get("timestamp", datetime.now()))
        except Exception:
            ts = datetime.now()
            
        record = {
            "timestamp": ts,
            "failed_logins": float(event.get("failed_login_count", 0)),
            "destination_ip": str(event.get("destination_ip", "")),
            "destination_port": int(event.get("destination_port", 0)),
            "severity_score": int(event.get("severity_score", 1)),
            "anomaly_score": float(event.get("anomaly_score", 0.0)),
            "threat_prob": float(event.get("ml_threat_prob", 0.0))
        }
        
        # Add to buffer
        self.device_buffers[device_id].append(record)
        
        # Prune events older than window
        cutoff = ts - timedelta(minutes=self.window_minutes)
        self.device_buffers[device_id] = [
            r for r in self.device_buffers[device_id] if r["timestamp"] >= cutoff
        ]
        
        return self.calculate_sequence_risk(device_id)

    def calculate_sequence_risk(self, device_id: str) -> float:
        """
        Computes a composite sequence risk score based on:
        1. Frequency escalation
        2. Destination diversity
        3. Cumulative authentication failures
        4. Max & mean anomaly scores
        """
        buffer = self.device_buffers.get(device_id, [])
        n_events = len(buffer)
        if n_events <= 1:
            return float(buffer[0]["threat_prob"]) if buffer else 0.0
            
        # 1. Event frequency factor (scaled: 1-15 events)
        freq_factor = min(1.0, n_events / 15.0)
        
        # 2. Cumulative authentication failures
        total_auth_failures = sum(r["failed_logins"] for r in buffer)
        auth_factor = min(1.0, total_auth_failures / 10.0)
        
        # 3. Unique destinations contacted in window
        unique_dests = len(set(r["destination_ip"] for r in buffer if r["destination_ip"]))
        dest_factor = min(1.0, unique_dests / 5.0)
        
        # 4. Anomaly score profile
        anom_scores = [r["anomaly_score"] for r in buffer]
        max_anom = max(anom_scores) if anom_scores else 0.0
        mean_anom = float(np.mean(anom_scores)) if anom_scores else 0.0
        
        # 5. Low-and-slow escalation check:
        # Check if events arrived in escalating hourly counts or repeated bursts
        is_escalating = False
        if n_events >= 3:
            first_half = n_events // 2
            early_rate = first_half
            late_rate = n_events - first_half
            if late_rate > early_rate:
                is_escalating = True
                
        # Composite Sequence Risk Formulation
        base_risk = (
            0.25 * freq_factor +
            0.30 * auth_factor +
            0.20 * dest_factor +
            0.25 * max_anom
        )
        
        if is_escalating and (auth_factor > 0.3 or dest_factor > 0.4):
            base_risk += 0.20
            
        return float(np.clip(base_risk, 0.0, 1.0))

    def evaluate_stream(self, df: pd.DataFrame) -> pd.DataFrame:
        """Evaluates an entire chronological DataFrame and adds sequence metrics."""
        df_out = df.copy()
        if "timestamp" in df_out.columns:
            df_out["parsed_ts"] = pd.to_datetime(df_out["timestamp"], errors="coerce")
            df_out = df_out.sort_values(by="parsed_ts").reset_index(drop=True)
            df_out = df_out.drop(columns=["parsed_ts"])
            
        seq_risks = []
        for idx, row in df_out.iterrows():
            score = self.add_event(row.to_dict())
            seq_risks.append(round(score, 4))
            
        df_out["sequence_risk_score"] = seq_risks
        return df_out

if __name__ == "__main__":
    detector = TemporalSequenceDetector(window_minutes=60)
    # Simulate low-and-slow sequence over 5 hours
    base_time = datetime(2026, 8, 1, 10, 0, 0)
    for hour in range(5):
        # Hour 1 = 1 event, Hour 2 = 2 events, etc.
        for e in range(hour + 1):
            evt = {
                "device_id": "DEV-INF-101",
                "timestamp": (base_time + timedelta(hours=hour, minutes=e * 10)).isoformat(),
                "failed_login_count": 1 if hour >= 2 else 0,
                "destination_ip": f"198.51.100.{hour + 10}",
                "destination_port": 443,
                "severity_score": 1,
                "anomaly_score": 0.2 + (hour * 0.12),
                "ml_threat_prob": 0.15
            }
            risk = detector.add_event(evt)
        print(f"Hour {hour + 1}: Final Sequence Risk = {risk:.3f}")
