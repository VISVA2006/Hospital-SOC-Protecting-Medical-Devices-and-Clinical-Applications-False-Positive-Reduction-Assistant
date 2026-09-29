"""
Dedicated Clinical Safety Guardrail Engine for Hospital SOC.
Enforces deterministic medical safety invariants, patient protection policies,
and fail-safe fallbacks for IoMT devices and clinical workstations.
"""

import os
from typing import Dict, Any, Tuple, Optional

# Standard Critical Medical Device Types
DEFAULT_CRITICAL_DEVICES = {
    "VENTILATOR",
    "INFUSION PUMP",
    "PATIENT MONITOR",
    "ANESTHESIA MACHINE"
}

class ClinicalSafetyGuardrail:
    """
    Deterministic Safety Policy Arbiter:
    Ensures that automated false-positive suppression never imperils life-critical medical assets.
    """
    def __init__(
        self,
        critical_devices=None,
        threat_threshold: float = 0.40,
        anomaly_threshold: float = 0.65
    ):
        if critical_devices is None:
            self.critical_devices = DEFAULT_CRITICAL_DEVICES
        else:
            self.critical_devices = {str(d).strip().upper() for d in critical_devices}
        self.threat_threshold = threat_threshold
        self.anomaly_threshold = anomaly_threshold

    def evaluate(
        self,
        alert: Dict[str, Any],
        ml_is_threat: bool,
        ml_threat_prob: float,
        anomaly_score: float,
        is_novelty: bool = False,
        sequence_risk_score: float = 0.0
    ) -> Tuple[str, str, bool]:
        """
        Evaluates triage decision against clinical safety invariants.
        Returns:
            (recommendation: str, reason: str, requires_review: bool)
        """
        device_type = str(alert.get("device_type", "")).strip().upper()
        device_criticality = str(alert.get("device_criticality", "")).strip().upper()
        is_critical = (
            device_criticality == "CRITICAL" or
            device_type in self.critical_devices or
            "VENTILATOR" in device_type or
            "INFUSION" in device_type or
            "MONITOR" in device_type
        )
        
        unusual_dest = int(alert.get("unusual_destination", 0)) == 1
        unusual_time = int(alert.get("unusual_time", 0)) == 1
        severity = str(alert.get("severity", "LOW")).upper()
        
        # Invariant 1: ML identifies active threat
        if ml_is_threat or ml_threat_prob >= 0.50:
            if is_critical and (unusual_dest or severity in ["HIGH", "CRITICAL"]):
                return (
                    "ESCALATE",
                    f"Active threat detected on critical clinical asset ({device_type}). Emergency escalation initiated.",
                    True
                )
            return (
                "INVESTIGATE",
                f"ML model scored high threat probability ({ml_threat_prob:.2f}). Requires security triage.",
                True
            )
            
        # Invariant 2: Multi-alert sequence risk detected
        if sequence_risk_score >= 0.70:
            return (
                "INVESTIGATE",
                f"Elevated temporal sequence risk ({sequence_risk_score:.2f}) indicates potential low-and-slow reconnaissance.",
                True
            )
            
        # Invariant 3: Novelty or significant anomaly detected
        if is_novelty or anomaly_score > self.anomaly_threshold:
            return (
                "INVESTIGATE",
                f"Novel/anomalous telemetry pattern detected (Anomaly Score: {anomaly_score:.2f}). Preserved by novelty guardrail.",
                True
            )
            
        # Invariant 4: Critical medical asset exhibiting any unusual behavior
        if is_critical and (unusual_dest or unusual_time or sequence_risk_score >= 0.40):
            return (
                "REVIEW",
                f"Critical medical asset ({device_type}) exhibiting unusual telemetry. Automatic suppression prohibited by Clinical Safety Policy.",
                True
            )
            
        # Invariant 5: Model uncertainty / boundary probability
        if ml_threat_prob >= self.threat_threshold:
            return (
                "REVIEW",
                f"Model threat confidence is borderline ({ml_threat_prob:.2f}). Routed to human analyst for verification.",
                True
            )
            
        # Invariant 6: High-confidence routine false positive on clean/non-critical asset
        conf_pct = int((1.0 - ml_threat_prob) * 100)
        return (
            "LIKELY_FALSE_POSITIVE",
            f"Repetitive benign pattern ({conf_pct}% confidence). Safe candidate for suppression.",
            False
        )

    def fail_safe_fallback(self, alert: Dict[str, Any], error_reason: str) -> Tuple[str, str, bool]:
        """
        Fail-safe fallback invoked when model or feature extraction encounters an exception.
        Guarantees system fails open to human review, NEVER suppressing on error.
        """
        device_type = str(alert.get("device_type", "Unknown"))
        is_critical = str(alert.get("device_criticality", "")).upper() == "CRITICAL"
        rec = "ESCALATE" if is_critical else "REVIEW"
        return (
            rec,
            f"SYSTEM FAIL-SAFE TRIGGERED: Telemetry processing error ({error_reason}). Auto-suppression blocked.",
            True
        )
