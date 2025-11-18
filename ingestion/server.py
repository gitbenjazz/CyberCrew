from fastapi import FastAPI
from pydantic import BaseModel

from ingestion.validator import validate_log
from ingestion.storage import store_log
from cybercrew_runtime import analyze_log   # <=== NEW IMPORT

app = FastAPI()

class LogEntry(BaseModel):
    log: str

@app.post("/ingest/log")
async def ingest_log(entry: LogEntry):
    log = entry.log

    if not validate_log(log):
        return {"status": "error", "reason": "invalid format"}

    # 1. Save the raw log
    path = store_log(log)

    # 2. Run CyberCrew
    analysis = analyze_log(log)

    # 3. Return everything
    return {
        "status": "ok",
        "stored_in": path,
        "cybercrew_result": analysis
    }
