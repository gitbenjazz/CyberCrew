import ipaddress

import requests
import os

<<<<<<< HEAD
=======
import requests
import os
>>>>>>> feature/OpenAI_switch

def lookup_threat(ip):
    api_key = os.getenv("c626c4a0046e589880dabea0e0bc70df4cd69e6eafda72e274ff1a2f47b58b161f1bdf98e990e939")
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    
    resp = requests.get(url, headers=headers, params=params)
    data = resp.json()["data"]

    return {
        "ip": ip,
        "reputation": (
            "high" if data["abuseConfidenceScore"] > 75 else
            "medium" if data["abuseConfidenceScore"] > 25 else
            "low"
        ),
        "source": "AbuseIPDB",
        "details": data.get("usageType", "unknown usage"),
    }


def lookup_threat_old(ip):
    """Enhanced local lookup that mimics a real threat intelligence check."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "reputation": "unknown", "source": "invalid"}

    # 1️⃣ Internal/private IPs → low risk
    if ip_obj.is_private:
        return {
            "ip": ip,
            "reputation": "low",
            "source": "RFC1918 Private Network"
        }

    # 2️⃣ Known test/documentation networks (203.0.113.*, 198.51.100.*, 192.0.2.*)
    if ip.startswith("203.0.113.") or ip.startswith("198.51.100.") or ip.startswith("192.0.2."):
        return {
            "ip": ip,
            "reputation": "medium",
            "source": "Reserved TEST-NET (documentation range)"
        }

    # 3️⃣ Everything else = high by default for demo
    return {
        "ip": ip,
        "reputation": "high",
        "source": "Simulated Threat DB"
    }
