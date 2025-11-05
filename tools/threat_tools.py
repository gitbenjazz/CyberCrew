import ipaddress
import requests
import os

def lookup_threat(ip):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {
            "ip": ip,
            "reputation": "unknown",
            "source": "missing API key"
        }

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        resp = requests.get(url, headers=headers, params=params, timeout=10)

        # Defensive parsing
        if resp.status_code != 200:
            return {
                "ip": ip,
                "reputation": "unknown",
                "source": f"HTTP {resp.status_code}",
                "details": resp.text[:100]
            }

        json_data = resp.json()

        print("DEBUG API response:", json_data)


        if "data" not in json_data:
            return {
                "ip": ip,
                "reputation": "unknown",
                "source": "API format error",
                "details": json_data
            }

        data = json_data["data"]
        score = data.get("abuseConfidenceScore", 0)

        return {
            "ip": ip,
            "reputation": (
                "high" if score > 75 else
                "medium" if score > 25 else
                "low"
            ),
            "source": "AbuseIPDB",
            "details": data.get("usageType", "unknown usage")
        }

    except Exception as e:
        return {
            "ip": ip,
            "reputation": "unknown",
            "source": "exception",
            "details": str(e)
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
