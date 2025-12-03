# ingestion/server.py

import logging
from datetime import datetime
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional

# Incident Management
from incident_storage.incident_manager import IncidentManager

# Log validation & analysis components
from ingestion.validator import validate_log
from cybercrew_runtime import analyze_log

# -----------------------------
# Logging Setup
# -----------------------------
logger = logging.getLogger("ingestion_server")
logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# -----------------------------
# FastAPI Init
# -----------------------------
app = FastAPI(title="CyberCrew Ingestion Server")

# -----------------------------
# Pydantic Input Model
# -----------------------------
class LogInput(BaseModel):
    log: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    transport: Optional[str] = None

# ---------------------------------------------------------
# BACKGROUND PROCESS (FULL PIPELINE)
# ---------------------------------------------------------
def process_log_background(log_input: LogInput):
    """
    Complete CyberCrew pipeline:
    - Validate log
    - Create incident in DB
    - Add initial event
    - Run analysis (LLM + threat intel)
    - Update severity
    - Add timeline events
    """

    manager = IncidentManager()

    try:
        logger.info(f"🚀 Starting background processing for: {log_input.log}")

        # 1. Validate & normalize log
        try:
            clean_log = validate_log(log_input.log)

        except Exception as e:
            logger.error(f"❌ Invalid log ignored: {e}")
            return

        # 2. Generate unique reference (timestamp-based)
        reference = datetime.utcnow().strftime("INC-%Y%m%d-%H%M%S-%f")

        # 3. Create new incident record
        incident = manager.create_incident(reference=reference, description=clean_log)

        manager.add_event(
            incident_id=incident.id,
            agent="Ingestion",
            event_type="log_received",
            content=f"Log received from {log_input.source_ip}, transport={log_input.transport}"
        )

        # 4. Run the full analysis pipeline
        analysis = analyze_log(clean_log)

        # 5. Store analysis as timeline event
        manager.add_event(
            incident_id=incident.id,
            agent="AnalysisEngine",
            event_type="analysis_result",
            content=str(analysis)
        )

        # 6. Update severity if present
        severity = analysis.get("severity") if isinstance(analysis, dict) else None
        if severity:
            manager.update_severity(incident.id, severity)

        # 7. Mark pipeline completed
        manager.update_pipeline_status(incident.id, "completed")

        logger.info(f"✅ Incident {incident.reference} fully processed")

    except Exception as e:
        logger.error(f"❌ Error in background processing: {e}")


# ---------------------------------------------------------
# MAIN INGESTION ENDPOINT
# ---------------------------------------------------------
@app.post("/ingest/log")
async def ingest_log(log_input: LogInput, background_tasks: BackgroundTasks):
    """
    The ingestion server must return *immediately* (for syslog listener).
    Heavy work runs as a background task.
    """
    logger.info(f"📥 Received log: {log_input.log}")

    # Schedule background pipeline
    background_tasks.add_task(process_log_background, log_input)

    # FAST response back to syslog listener
    return {"status": "received"}


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}
