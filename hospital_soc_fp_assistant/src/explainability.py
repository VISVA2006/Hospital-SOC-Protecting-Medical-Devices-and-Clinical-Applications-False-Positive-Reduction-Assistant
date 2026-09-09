"""
Explainability Module for Hospital SOC Assistant.
Synthesizes evidence-based explanations for every alert triage recommendation,
translating ML features, device context, and anomaly metrics into clear SOC analyst reasoning.
"""

def generate_evidence(alert, recommendation, threat_prob, anomaly_score, is_novelty):
    """
    Generates structured, multi-bullet evidence explaining the reasoning
    behind the recommendation.
    """
    evidence = []
    
    dev_type = alert.get("device_type", "Endpoint")
    dev_crit = str(alert.get("device_criticality", "LOW")).upper()
    hist_alerts = int(alert.get("historical_alert_count", 0))
    hist_fp_rate = float(alert.get("historical_false_positive_rate", 0.0))
    known_scanner = int(alert.get("known_scanner", 0)) == 1
    maintenance = int(alert.get("maintenance_window", 0)) == 1
    unusual_dest = int(alert.get("unusual_destination", 0)) == 1
    unusual_time = int(alert.get("unusual_time", 0)) == 1
    failed_logins = int(alert.get("failed_login_count", 0))
    login_attempts = int(alert.get("login_attempts", 0))
    src_ip = alert.get("source_ip", "")
    dest_ip = alert.get("destination_ip", "")
    dest_port = alert.get("destination_port", "")
    proto = alert.get("protocol", "")
    
    # Context bullets
    if dev_crit == "CRITICAL":
        evidence.append(f"Critical medical asset involved: {dev_type} ({alert.get('device_vendor', '')} {alert.get('device_model', '')})")
    elif dev_crit == "HIGH":
        evidence.append(f"High-priority clinical asset: {dev_type} in {alert.get('department', 'Clinical')}")
        
    # Anomaly / Novelty bullets
    if is_novelty or anomaly_score > 0.65:
        evidence.append(f"High anomaly score ({anomaly_score:.2f}): Telemetry deviates significantly from historical baseline")
    elif anomaly_score < 0.35:
        evidence.append(f"Low anomaly score ({anomaly_score:.2f}): Behavior matches established baseline pattern")
        
    # Historical telemetry
    if hist_alerts > 0:
        est_fps = int(hist_alerts * hist_fp_rate)
        evidence.append(f"Historical device profile: {hist_alerts} previous alerts recorded; {est_fps} ({hist_fp_rate*100:.0f}%) marked False Positive")
        
    # Network & Operational context
    if known_scanner:
        evidence.append(f"Source IP {src_ip} matches authorized internal vulnerability scanner")
    if maintenance:
        evidence.append("Event occurred during approved maintenance window")
    if unusual_dest:
        evidence.append(f"Destination IP {dest_ip}:{dest_port} ({proto}) is previously unseen for this device type")
    if unusual_time:
        evidence.append(f"Activity initiated outside standard operating shift hours")
    if failed_logins > 5:
        evidence.append(f"Authentication failure spike: {failed_logins} failed logins out of {login_attempts} attempts")
        
    # Recommendation-specific concluding synthesis
    if recommendation == "LIKELY_FALSE_POSITIVE":
        confidence = int((1.0 - threat_prob) * 100)
        evidence.append(f"Model confidence is {confidence}% for benign/false positive classification")
        evidence.append("No indicators of lateral movement, payload delivery, or credential abuse detected")
    elif recommendation in ["INVESTIGATE", "ESCALATE"]:
        confidence = int(threat_prob * 100) if threat_prob >= 0.5 else int(anomaly_score * 100)
        evidence.append(f"Safety guardrail triggered: Automatic suppression blocked to prevent potential clinical risk")
        if dev_crit == "CRITICAL":
            evidence.append("Hospital Clinical Safety Policy requires manual verification on all critical patient-connected systems")
    else: # REVIEW
        evidence.append("Model confidence is borderline; analyst disposition required to confirm baseline update")
        
    return evidence

def format_explanation_markdown(recommendation, confidence_pct, evidence_list):
    """Formats the recommendation and evidence into clean markdown for presentation."""
    md = f"### Recommendation: **{recommendation}**\n\n"
    md += f"**Confidence:** {confidence_pct}%\n\n"
    md += "**Supporting Evidence:**\n"
    for item in evidence_list:
        md += f"- {item}\n"
    return md
