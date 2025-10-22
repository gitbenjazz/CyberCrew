import re
from datetime import datetime

def parse_logs(file_path="data/sample_logs/auth.log"):
    """Simple parser that extracts failed logins and suspicious activity."""
    incidents = []
    pattern = r"(?P<date>\w{3} \d+ \d{2}:\d{2}:\d{2}) .*Failed password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    with open(file_path, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                incidents.append({
                    "date": match.group("date"),
                    "user": match.group("user"),
                    "ip": match.group("ip")
                })
    return incidents
