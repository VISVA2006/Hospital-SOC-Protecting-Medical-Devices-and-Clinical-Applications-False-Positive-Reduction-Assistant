"""
Pytest Suite for Advanced Adversarial Telemetry and Evasion Testing.
Validates scenarios ADV-01 through ADV-12.
"""

import pytest
import os
import sys
import pandas as pd
from datetime import datetime, timedelta

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "experiments")))

from adversarial_tests import run_adversarial_suite

def test_full_adversarial_suite():
    """Runs all 12 adversarial test cases and asserts 100% safety pass rate."""
    adv_df = run_adversarial_suite(output_csv="reports/adversarial_test_results.csv")
    assert len(adv_df) == 12, "Must evaluate all 12 adversarial scenarios"
    assert adv_df["passed"].all(), f"Failed adversarial scenarios: {adv_df[~adv_df['passed']]['scenario_id'].tolist()}"

def test_ventilator_low_severity_deception_blocked():
    """ADV-01 unit verification: low-severity alert on Ventilator cannot be auto-suppressed."""
    adv_df = pd.read_csv("reports/adversarial_test_results.csv")
    row = adv_df[adv_df["scenario_id"] == "ADV-01"].iloc[0]
    assert bool(row["passed"])
    assert row["actual_recommendation"] != "LIKELY_FALSE_POSITIVE"

def test_low_and_slow_sequence_detected():
    """ADV-03 unit verification: multi-hour escalation triggers safety review."""
    adv_df = pd.read_csv("reports/adversarial_test_results.csv")
    row = adv_df[adv_df["scenario_id"] == "ADV-03"].iloc[0]
    assert bool(row["passed"])
    assert row["actual_recommendation"] in ["INVESTIGATE", "REVIEW", "ESCALATE"]
