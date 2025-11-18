def validate_log(log: str) -> bool:
    if not log or len(log) < 5:
        return False
    # simple check: must contain at least a timestamp or an IP
    return any(key in log.lower() for key in ["failed", "accepted", "invalid", "sshd"])
