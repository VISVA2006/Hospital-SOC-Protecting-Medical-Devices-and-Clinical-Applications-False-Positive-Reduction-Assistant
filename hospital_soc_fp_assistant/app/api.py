"""
FastAPI Microservice for Hospital SOC False-Positive Reduction Assistant.
Provides enterprise endpoints for alert triage, batch stream processing,
analyst feedback ingestion, candidate retraining, and model governance.
"""

import os
import sys
import json
import pandas as pd
from typing import List, Optional
from datetime import datetime
from fastapi import FastAPI, HTTPException, Header, Depends, Query, status
from fastapi.responses import JSONResponse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from schemas import AlertInputSchema, AlertAnalysisResponse, FeedbackInputSchema, RetrainingResponse
from services import TriageService

app = FastAPI(
    title="Hospital SOC False-Positive Reduction Assistant API",
    description="Defensive cybersecurity service for IoMT device alert triage, clinical safety guardrails, and explainable AI.",
    version="2.0.0"
)

# Initialize Core Triage Service
service = TriageService()

# Optional defensive API key validation
EXPECTED_API_KEY = os.environ.get("HOSPITAL_SOC_API_KEY", "clinical-soc-secure-key-2026")

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Validates API Key if configured in environment."""
    if os.environ.get("ENFORCE_API_KEY", "false").lower() == "true":
        if not x_api_key or x_api_key != EXPECTED_API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-API-KEY header."
            )
    return True

@app.get("/health", tags=["System"])
def health_check():
    """Returns system status, active model version, and operational state."""
    champ = service.registry.get_champion()
    return {
        "status": "HEALTHY",
        "service": "Hospital SOC False-Positive Reduction Assistant",
        "active_model_version": champ["model_version"] if champ else "v1.0",
        "clinical_guardrail_active": True,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/alerts/analyze", response_model=AlertAnalysisResponse, tags=["Triage"])
def analyze_alert(alert: AlertInputSchema, authenticated: bool = Depends(verify_api_key)):
    """
    Triages a single incoming security alert.
    Applies supervised ML, Isolation Forest anomaly detection,
    multi-alert sequence tracking, and clinical safety guardrails.
    """
    try:
        result = service.analyze_single_alert(alert.model_dump())
        return AlertAnalysisResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal triage error: {str(e)}"
        )

@app.post("/alerts/batch", response_model=List[AlertAnalysisResponse], tags=["Triage"])
def analyze_batch(alerts: List[AlertInputSchema], authenticated: bool = Depends(verify_api_key)):
    """Triages a batch of alerts sequentially maintaining sequence history."""
    if len(alerts) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch limit exceeded (maximum 500 alerts per request)."
        )
    results = []
    for a in alerts:
        res = service.analyze_single_alert(a.model_dump())
        results.append(AlertAnalysisResponse(**res))
    return results

@app.post("/feedback", tags=["Feedback"])
def record_feedback(feedback: FeedbackInputSchema, authenticated: bool = Depends(verify_api_key)):
    """Logs human analyst triage confirmation or override justification."""
    try:
        logged = service.record_analyst_decision(feedback.model_dump())
        return {
            "status": "RECORDED",
            "alert_id": feedback.alert_id,
            "decision": feedback.analyst_decision,
            "override": bool(logged.get("override_flag", 0)),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record analyst feedback: {str(e)}"
        )

@app.get("/alerts/{alert_id}", tags=["Investigation"])
def get_alert_by_id(alert_id: str, authenticated: bool = Depends(verify_api_key)):
    """Retrieves full telemetry context and ground truth for an alert ID."""
    clean_path = "data/cleaned_alerts.csv"
    if not os.path.exists(clean_path):
        raise HTTPException(status_code=404, detail="Alert database not initialized.")
        
    df = pd.read_csv(clean_path)
    match = df[df["alert_id"] == alert_id]
    if len(match) == 0:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
        
    row = match.iloc[0].to_dict()
    # Sanitize NaN values for clean JSON
    clean_row = {k: (None if pd.isna(v) else v) for k, v in row.items()}
    return clean_row

@app.get("/models/current", tags=["Governance"])
def get_current_model(authenticated: bool = Depends(verify_api_key)):
    """Returns metadata for the currently active CHAMPION model."""
    champ = service.registry.get_champion()
    if not champ:
        raise HTTPException(status_code=404, detail="No active champion model in registry.")
    return champ

@app.get("/metrics", tags=["Evaluation"])
def get_evaluation_metrics(authenticated: bool = Depends(verify_api_key)):
    """Returns current empirical evaluation metrics and baseline comparison."""
    metrics_path = "results/metrics.json"
    if not os.path.exists(metrics_path):
        raise HTTPException(status_code=404, detail="Metrics report not generated.")
    with open(metrics_path, "r", encoding="utf-8") as f:
        return json.load(f)

@app.get("/explanations/{alert_id}", tags=["Investigation"])
def get_explanation_for_alert(alert_id: str, authenticated: bool = Depends(verify_api_key)):
    """Returns explainable AI reasoning and evidence bullets for an alert."""
    alert_data = get_alert_by_id(alert_id, authenticated)
    analysis = service.analyze_single_alert(alert_data)
    return {
        "alert_id": alert_id,
        "recommendation": analysis["recommendation"],
        "confidence": int((1.0 - analysis["ml_threat_probability"]) * 100) if analysis["recommendation"] == "LIKELY_FALSE_POSITIVE" else int(analysis["ml_threat_probability"] * 100),
        "evidence_bullets": analysis["evidence_bullets"],
        "guardrail_reason": analysis["clinical_guardrail_reason"]
    }

@app.get("/audit/{alert_id}", tags=["Audit"])
def get_audit_trail_for_alert(alert_id: str, authenticated: bool = Depends(verify_api_key)):
    """Returns preprocessing and analyst decision audit history for an alert."""
    feedback_path = "data/analyst_feedback.csv"
    feedback_match = None
    if os.path.exists(feedback_path):
        fb_df = pd.read_csv(feedback_path)
        m = fb_df[fb_df["alert_id"] == alert_id]
        if len(m) > 0:
            feedback_match = m.iloc[-1].to_dict()
            
    return {
        "alert_id": alert_id,
        "analyst_feedback_record": feedback_match,
        "retrieved_timestamp": datetime.now().isoformat()
    }

@app.post("/models/retrain", response_model=RetrainingResponse, tags=["Governance"])
def trigger_retraining(authenticated: bool = Depends(verify_api_key)):
    """
    Triggers replay-based candidate model retraining.
    Does NOT automatically deploy or promote the candidate model.
    Runs evaluation against promotion safety gates.
    """
    result = service.trigger_retraining()
    if result.get("status") == "SUCCESS":
        return RetrainingResponse(
            status="SUCCESS",
            candidate_version=result.get("candidate_version"),
            promotion_eligible=result.get("promotion_eligible", False),
            metrics=result.get("candidate_metrics"),
            reason="Candidate model trained and validated on replay dataset."
        )
    else:
        return RetrainingResponse(
            status="ABORTED",
            promotion_eligible=False,
            reason=result.get("reason", "Retraining could not be completed.")
        )
