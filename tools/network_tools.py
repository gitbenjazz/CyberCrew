def suggest_fix(ip, severity="medium"):
    """Suggest firewall command to block suspicious IP."""
    severity = severity.lower().strip()

    if severity == "high":
        action = "block"
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        reason = "High reputation risk — IP blocked immediately."

    elif severity == "medium":
        action = "limit"
        cmd = f"iptables -A INPUT -s {ip} -m limit --limit 10/minute -j ACCEPT"
        reason = "Medium risk — connection rate-limited for observation."

    elif severity == "low" or severity == "safe":
        action = "monitor"
        cmd = f"# No blocking rule generated for {ip} (low/safe risk). Monitor only."
        reason = "Low or safe risk — monitored, no mitigation applied."

    else:
        action = "unknown"
        cmd = f"# Unrecognized severity for {ip}: {severity}"
        reason = "Unable to determine mitigation."

    return {
        "ip": ip,
        "severity": severity,
        "action": action,
        "command": cmd,
        "reason": reason
    }
