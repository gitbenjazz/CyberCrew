# incident_storage/models.py
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    # New fields
    reference = Column(String, unique=True, index=True, nullable=False)
    pipeline_status = Column(String, default="running", nullable=False)      # running/completed/failed
    remediation_status = Column(String, default="open", nullable=False)     # open/closed/suppressed (later)
    severity = Column(String, nullable=True)                                # high/medium/low (later)

    description = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )

    events = relationship("IncidentEvent", back_populates="incident")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)

    agent = Column(String, nullable=False)
    event_type = Column(String, nullable=False)  # log_analysis / threat_intel / mitigation / final_report
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    incident = relationship("Incident", back_populates="events")
