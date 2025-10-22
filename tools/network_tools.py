def suggest_fix(ip, severity="medium"):
    """Suggest firewall command to block suspicious IP."""
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    return {
        "action": "block",
        "ip": ip,
        "command": cmd,
        "reason": f"Based on severity: {severity}"
    }
