"""
Data Preprocessing Module for Hospital SOC Alerts.
Handles missing values, categorical encoding, feature engineering,
timestamp normalization, and audit logging without silently dropping security events.
"""

import os
import json
import pandas as pd
import numpy as np
from datetime import datetime

AUDIT_LOG_FILE = "data/preprocessing_audit_log.json"

SEVERITY_MAP = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

DEVICE_CRITICALITY_MAP = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def extract_time_features(df):
    """Extracts temporal features from timestamps."""
    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    rec_ts = pd.to_datetime(df["received_timestamp"], errors="coerce")
    
    df["hour_of_day"] = ts.dt.hour.fillna(12).astype(int)
    df["day_of_week"] = ts.dt.dayofweek.fillna(0).astype(int)
    df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype(int)
    
    # Latency between event generation and SIEM receipt in seconds
    latency = (rec_ts - ts).dt.total_seconds().fillna(0.0)
    # Ensure latency is not negative (clock skew guard)
    df["latency_seconds"] = latency.clip(lower=0.0)
    return df

def clean_and_impute(df, audit_log=None):
    """
    Cleans missing and invalid values with transparent imputation.
    Security events are NEVER silently dropped.
    """
    if audit_log is None:
        audit_log = {}
        
    initial_rows = len(df)
    audit_log["total_records_processed"] = initial_rows
    audit_log["missing_values_before"] = int(df.isna().sum().sum())
    
    # Impute categorical fields with 'Unknown'
    cat_imputes = {
        "patch_status": "Unknown",
        "antivirus_status": "Unknown",
        "user_role": "Clinical Staff",
        "firmware_version": "Unknown",
        "device_vendor": "Unknown",
        "device_model": "Unknown",
        "department": "General Hospital"
    }
    
    impute_counts = {}
    for col, default_val in cat_imputes.items():
        if col in df.columns:
            missing_count = int(df[col].isna().sum())
            if missing_count > 0:
                impute_counts[col] = missing_count
                df[col] = df[col].fillna(default_val)
    audit_log["categorical_imputations"] = impute_counts
    
    # Impute numerical fields
    num_imputes = {
        "failed_login_count": 0,
        "login_attempts": 0,
        "event_count": 1,
        "historical_alert_count": 10,
        "historical_false_positive_rate": 0.75,
        "source_port": 0,
        "destination_port": 0,
        "unusual_time": 0,
        "unusual_destination": 0,
        "known_scanner": 0,
        "maintenance_window": 0
    }
    
    for col, default_val in num_imputes.items():
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(default_val)
            
    # Mappings
    df["severity_score"] = df["severity"].map(SEVERITY_MAP).fillna(2).astype(int)
    df["device_criticality_score"] = df["device_criticality"].map(DEVICE_CRITICALITY_MAP).fillna(2).astype(int)
    
    # Check for invalid / out-of-range ports
    df["invalid_port_flag"] = ((df["destination_port"] < 0) | (df["destination_port"] > 65535)).astype(int)
    df["destination_port"] = df["destination_port"].clip(0, 65535)
    
    audit_log["records_retained"] = len(df)
    audit_log["records_dropped"] = 0  # Zero records dropped to guarantee security auditability
    
    return df, audit_log

def engineer_features(df):
    """Generates analytical and ML features."""
    df = extract_time_features(df)
    
    # Risk indicators
    df["is_critical_device"] = (df["device_criticality"] == "CRITICAL").astype(int)
    df["is_high_risk_combo"] = ((df["device_criticality"].isin(["CRITICAL", "HIGH"])) & (df["unusual_destination"] == 1)).astype(int)
    df["scanner_maintenance_combo"] = ((df["known_scanner"] == 1) & (df["maintenance_window"] == 1)).astype(int)
    df["high_failure_rate"] = np.where(df["login_attempts"] > 0, df["failed_login_count"] / df["login_attempts"], 0.0)
    
    # Binary target for false-positive modeling: 1 = False Positive/Benign, 0 = True Threat / Actionable
    # If disposition is available:
    if "analyst_disposition" in df.columns:
        df["is_false_positive_label"] = df["analyst_disposition"].isin(["FALSE_POSITIVE", "BENIGN"]).astype(int)
        
    return df

def preprocess_dataset(input_csv="data/raw_alerts.csv", output_csv="data/cleaned_alerts.csv"):
    """Complete preprocessing pipeline for raw alert records."""
    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Raw alerts file not found: {input_csv}")
        
    df = pd.read_csv(input_csv)
    audit_log = {
        "timestamp": datetime.now().isoformat(),
        "input_file": input_csv,
        "output_file": output_csv
    }
    
    df, audit_log = clean_and_impute(df, audit_log)
    df = engineer_features(df)
    
    # Save cleaned data
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    
    # Save audit log
    with open(AUDIT_LOG_FILE, "w") as f:
        json.dump(audit_log, f, indent=4)
        
    print(f"Preprocessed {len(df)} alerts -> {output_csv}")
    print(f"Audit log saved -> {AUDIT_LOG_FILE}")
    return df, audit_log

if __name__ == "__main__":
    preprocess_dataset()
