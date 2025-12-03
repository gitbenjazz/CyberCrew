# ingestion/validator.py

def validate_log(log: str) -> str:
    """
    Return a cleaned/normalized log string.
    Raise ValueError if log is invalid.
    """

    if not log or len(log.strip()) < 5:
        raise ValueError("Log is too short")

    # Very simple sanity checks — expand later
    keywords = ["failed", "accepted", "invalid", "sshd"]
    if not any(k in log.lower() for k in keywords):
        raise ValueError("Log does not appear to be a valid auth/SSH log")

    # Return the original log (normalized)
    return log.strip()
