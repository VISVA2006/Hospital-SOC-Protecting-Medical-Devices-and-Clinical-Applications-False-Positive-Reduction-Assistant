"""
Pydantic Schemas for Hospital SOC Assistant REST API.
Validates telemetry input fields, ranges, and structures triage responses.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime

class AlertInputSchema(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier (e.g. ALT-10001)")
    event_id: Optional[str] = Field(None, description="Underlying security event identifier")
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.now().isoformat(), description="ISO timestamp")
    received_timestamp: Optional[str] = Field(None, description="Receipt timestamp")
    alert_type: str = Field("Unknown Alert", description="Categorical alert type")
    severity: str = Field("LOW", description="Alert severity: LOW, MEDIUM, HIGH, CRITICAL")
    source_ip: str = Field("0.0.0.0", description="Source IPv4 address")
    destination_ip: str = Field("0.0.0.0", description="Destination IPv4 address")
    protocol: str = Field("TCP", description="Transport/application protocol")
    source_port: int = Field(0, ge=0, le=65535, description="Source port (0-65535)")
    destination_port: int = Field(0, ge=0, le=65535, description="Destination port (0-65535)")
    failed_login_count: int = Field(0, ge=0, description="Count of failed authentications")
    login_attempts: int = Field(0, ge=0, description="Count of total login attempts")
    event_count: int = Field(1, ge=1, description="Event occurrence count")
    device_id: Optional[str] = Field(None, description="Clinical asset tag")
    device_type: str = Field("Endpoint", description="Medical device classification")
    device_criticality: str = Field("LOW", description="Clinical criticality: LOW, MEDIUM, HIGH, CRITICAL")
    unusual_time: int = Field(0, ge=0, le=1, description="Binary flag: 1 if off-hours")
    unusual_destination: int = Field(0, ge=0, le=1, description="Binary flag: 1 if unseen IP")
    historical_alert_count: int = Field(10, ge=0, description="Device historical alert count")
    historical_false_positive_rate: float = Field(0.75, ge=0.0, le=1.0, description="Historical FP rate")
    known_scanner: int = Field(0, ge=0, le=1, description="1 if authorized scanner IP")
    maintenance_window: int = Field(0, ge=0, le=1, description="1 if during approved maintenance")
    network_segment: str = Field("Medical-Device-VLAN", description="Network VLAN name")
    detection_source: str = Field("Network NIDS", description="Sensor origin")

    @field_validator("severity", "device_criticality")
    @classmethod
    def validate_enum_severity(cls, v: str) -> str:
        v_upper = v.strip().upper()
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v_upper not in allowed:
            raise ValueError(f"Value must be one of {allowed}, got '{v}'")
        return v_upper

class AlertAnalysisResponse(BaseModel):
    alert_id: str
    recommendation: str
    ml_threat_probability: float
    anomaly_score: float
    is_novelty: bool
    sequence_risk_score: float
    requires_human_review: bool
    evidence_bullets: List[str]
    clinical_guardrail_reason: str
    model_version: str
    timestamp: str

class FeedbackInputSchema(BaseModel):
    alert_id: str
    analyst_decision: str
    analyst_id: str = "ANL-CURRENT"
    override_reason: Optional[str] = ""

class RetrainingResponse(BaseModel):
    status: str
    candidate_version: Optional[str] = None
    promotion_eligible: bool = False
    metrics: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
