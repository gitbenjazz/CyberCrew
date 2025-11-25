# incident_storage/incident_manager.py
from datetime import datetime

from .database import SessionLocal, engine, Base
from .models import Incident, IncidentEvent

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)


class IncidentManager:
    def __init__(self):
        self.db = SessionLocal()

    # -------------------------
    # Incident lifecycle
    # -------------------------
    def create_incident(self, reference: str, description: str, severity: str | None = None):
        incident = Incident(
            reference=reference,
            description=description,
            severity=severity,
            pipeline_status="running",
            remediation_status="open",
        )
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident

    def update_pipeline_status(self, incident_id: int, status: str):
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
        incident.pipeline_status = status
        incident.updated_at = datetime.utcnow()
        self.db.commit()

    def update_severity(self, incident_id: int, severity: str):
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
        incident.severity = severity
        incident.updated_at = datetime.utcnow()
        self.db.commit()

    def update_remediation_status(self, incident_id: int, status: str):
        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            return
        incident.remediation_status = status
        incident.updated_at = datetime.utcnow()
        self.db.commit()

    # -------------------------
    # Events / timeline
    # -------------------------
    def add_event(self, incident_id: int, agent: str, event_type: str, content: str):
        event = IncidentEvent(
            incident_id=incident_id,
            agent=agent,
            event_type=event_type,
            content=content,
        )
        self.db.add(event)

        incident = self.db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            incident.updated_at = datetime.utcnow()

        self.db.commit()
        return event

    # -------------------------
    # Queries
    # -------------------------
    def get_incident(self, incident_id: int):
        return self.db.query(Incident).filter(Incident.id == incident_id).first()

    def list_incidents(self, pipeline_status: str | None = None):
        q = self.db.query(Incident)
        if pipeline_status:
            q = q.filter(Incident.pipeline_status == pipeline_status)
        return q.order_by(Incident.created_at.desc()).all()
