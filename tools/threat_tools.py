import ipaddress

import requests
import os


def lookup_threat(ip):
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
