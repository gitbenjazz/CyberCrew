# tools/severity_engine.py

"""
Auto-Severity Engine
Compatible with threat data returned by tools/threat_tools.py
"""

def compute_severity(log_text: str, threat: dict) -> dict:
    severity_score = 0
    reasons = []

    # Normalize log
    log_lower = log_text.lower()

    # ==========================================
    # 1. Threat Intel rules (your threat format)
    # ==========================================
    rep = threat.get("reputation", "low")
    details = threat.get("details", "")

    if rep == "high":
        severity_score += 50
        reasons.append("Threat Intel: HIGH reputation IP")
    elif rep == "medium":
        severity_score += 25
        reasons.append("Threat Intel: medium reputation IP")

    # Hosting providers / Data Centers → more suspicious
    if isinstance(details, str) and (
        "hosting" in details.lower() or
        "data center" in details.lower() or
        "transit" in details.lower()
    ):
        severity_score += 10
        reasons.append("IP hosted in a data center (possible botnet)")

    # ==========================================
    # 2. Log content heuristics
    # ==========================================
    if "failed password" in log_lower:
        severity_score += 20
        reasons.append("Failed SSH authentication")

    if "invalid user" in log_lower:
        severity_score += 15
        reasons.append("Invalid user login attempt")

    if "pam_unix" in log_lower and "authentication failure" in log_lower:
        severity_score += 15
        reasons.append("PAM authentication failure")

    if "sudo" in log_lower and ("failed" in log_lower or "authentication failure" in log_lower):
        severity_score += 30
        reasons.append("Failed sudo elevation attempt")

    # ==========================================
    # 3. Severity mapping
    # ==========================================
    if severity_score >= 70:
        severity = "critical"
    elif severity_score >= 40:
        severity = "high"
    elif severity_score >= 20:
        severity = "medium"
    else:
        severity = "low"

    return {
        "severity": severity,
        "score": severity_score,
        "reasons": reasons,
    }
