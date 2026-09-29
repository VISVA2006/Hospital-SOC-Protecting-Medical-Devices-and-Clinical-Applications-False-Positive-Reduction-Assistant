"""
Feedback Validation Module for Hospital SOC Assistant.
Guarantees data integrity for analyst feedback: checks minimum sample counts,
rejects duplicates, validates schema fields, and filters invalid dispositions.
"""

import os
import pandas as pd
from typing import Dict, Any, Tuple, List
from datetime import datetime

MIN_FEEDBACK_SAMPLES = 50

VALID_DISPOSITIONS = {
    "CONFIRM_FALSE_POSITIVE",
    "CONFIRM_TRUE_THREAT",
    "FALSE_POSITIVE",
    "TRUE_POSITIVE",
    "INVESTIGATE",
    "ESCALATE",
    "BENIGN",
    "NEEDS_INVESTIGATION"
}

REQUIRED_FEEDBACK_FIELDS = [
    "alert_id",
    "timestamp",
    "analyst_decision",
    "analyst_id"
]

class FeedbackValidator:
    """Validates analyst feedback records prior to ingestion and retraining."""
    
    def __init__(self, min_samples: int = MIN_FEEDBACK_SAMPLES):
        self.min_samples = min_samples

    def validate_record(self, record: Dict[str, Any]) -> Tuple[bool, str]:
        """Validates a single feedback record dictionary."""
        # 1. Check required fields
        for field in REQUIRED_FEEDBACK_FIELDS:
            if field not in record or record[field] is None or str(record[field]).strip() == "":
                return False, f"Missing required feedback field: {field}"
                
        # 2. Check disposition validity
        decision = str(record.get("analyst_decision", "")).strip().upper()
        if decision not in VALID_DISPOSITIONS:
            return False, f"Invalid analyst decision '{decision}'. Allowed: {sorted(list(VALID_DISPOSITIONS))}"
            
        # 3. Check timestamp format
        try:
            pd.to_datetime(record["timestamp"])
        except Exception:
            return False, f"Invalid timestamp format: {record['timestamp']}"
            
        return True, "Valid record"

    def validate_batch(self, feedback_df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Validates an entire batch of feedback records.
        Removes duplicates, filters invalid records, and computes validation metrics.
        """
        initial_count = len(feedback_df)
        if initial_count == 0:
            return feedback_df, {
                "initial_count": 0,
                "valid_count": 0,
                "duplicates_removed": 0,
                "invalid_removed": 0,
                "can_trigger_retraining": False,
                "reason": "Feedback dataset is empty."
            }
            
        # Deduplication: keep the latest feedback for each alert_id
        if "timestamp" in feedback_df.columns:
            feedback_df["parsed_ts"] = pd.to_datetime(feedback_df["timestamp"], errors="coerce")
            df_sorted = feedback_df.sort_values(by="parsed_ts", ascending=True)
            df_deduped = df_sorted.drop_duplicates(subset=["alert_id"], keep="last").copy()
            df_deduped = df_deduped.drop(columns=["parsed_ts"])
        else:
            df_deduped = feedback_df.drop_duplicates(subset=["alert_id"], keep="last").copy()
            
        dups_removed = initial_count - len(df_deduped)
        
        # Validate individual records
        valid_rows = []
        invalid_count = 0
        
        for _, row in df_deduped.iterrows():
            rec_dict = row.to_dict()
            is_valid, _ = self.validate_record(rec_dict)
            if is_valid:
                valid_rows.append(rec_dict)
            else:
                invalid_count += 1
                
        validated_df = pd.DataFrame(valid_rows)
        valid_count = len(validated_df)
        can_retrain = valid_count >= self.min_samples
        
        reason = (
            f"Validated {valid_count} samples (Threshold: {self.min_samples}). Eligible for retraining."
            if can_retrain else
            f"Insufficient feedback samples ({valid_count}/{self.min_samples}). Accumulating more analyst decisions."
        )
        
        stats = {
            "initial_count": initial_count,
            "valid_count": valid_count,
            "duplicates_removed": dups_removed,
            "invalid_removed": invalid_count,
            "can_trigger_retraining": can_retrain,
            "reason": reason
        }
        return validated_df, stats

if __name__ == "__main__":
    validator = FeedbackValidator()
    test_record = {
        "alert_id": "ALT-TEST-01",
        "timestamp": datetime.now().isoformat(),
        "analyst_decision": "CONFIRM_FALSE_POSITIVE",
        "analyst_id": "ANL-101"
    }
    valid, msg = validator.validate_record(test_record)
    print(f"Sample Record Validation: {valid} ({msg})")
