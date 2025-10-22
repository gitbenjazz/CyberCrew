import random

def lookup_threat(ip):
    """Mock threat lookup (could connect to VirusTotal or AbuseIPDB)."""
    risk_levels = ["low", "medium", "high"]
    return {
        "ip": ip,
        "reputation": random.choice(risk_levels),
        "source": "Local Mock DB"
    }
