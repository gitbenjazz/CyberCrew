# ingestion/server.py

from fastapi import FastAPI
from pydantic import BaseModel

from ingestion.validator import validate_log
from ingestion.storage import store_log

from cybercrew_runtime import analyze_log


app = FastAPI()


class LogEntry(BaseModel):
    log: str


@app.post("/ingest/log")
async def ingest_log(entry: LogEntry):
    log_text = entry.log

    # 1. Validate
    if not validate_log(log_text):
        return {"status": "error", "reason": "invalid log format"}

    # 2. Store raw log
    stored_path = store_log(log_text)

    # 3. Run CyberCrew runtime pipeline (now includes severity+intel)
    analysis = analyze_log(log_text)

    return {
        "status": "ok",
        "stored_in": stored_path,
        "cybercrew_result": analysis,
    }
