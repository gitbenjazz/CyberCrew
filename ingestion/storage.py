import os
from datetime import datetime

LOG_DIR = "logs/ingested"
os.makedirs(LOG_DIR, exist_ok=True)

def store_log(log: str) -> str:
    filename = datetime.now().strftime("%Y%m%d_%H%M%S_%f.log")
    path = os.path.join(LOG_DIR, filename)
    with open(path, "w") as f:
        f.write(log)
    return path
