# cybercrew_runtime.py

import os
from datetime import datetime
from crewai import Crew, Task, LLM

# Agents (without incident_manager injection)
from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander

# New Incident Storage
from incident_storage.incident_manager import IncidentManager


# ======================================================
# Helper: extract content from TaskOutput (CrewAI 1.5+)
# ======================================================
def extract_output(output):
    try:
        return output.raw_output[-1]["content"]
    except:
        return str(output)


# ======================================================
# Helper: generate reference (INC-YYYYMMDD-HHMMSS)
# ======================================================
def generate_reference():
    return "INC-" + datetime.utcnow().strftime("%Y%m%d-%H%M%S")


# ======================================================
# Runtime pipeline for a single LOG ENTRY (string)
# ======================================================
def analyze_log(log: str):
    """Run a lightweight CyberCrew pipeline on a single log entry (string)."""

    # -------------------------------------------------------------
    # 1. Initialize LLM
    # -------------------------------------------------------------
    model_name = os.getenv("CREWAI_MODEL", "gpt-4o-mini")
    provider = os.getenv("LLM_PROVIDER", "openai").lower()

    if provider == "ollama":
        llm = LLM(model=f"ollama/{model_name}")
    else:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY missing!")
        llm = LLM(model=model_name, api_key=api_key)

    # -------------------------------------------------------------
    # 2. Create a new Incident in the DB
    # -------------------------------------------------------------
    incident_manager = IncidentManager()

    reference = generate_reference()
    incident = incident_manager.create_incident(
        reference=reference,
        description="Runtime ingestion of a single log entry",
        severity=None,   # severity computed later
    )
    incident_id = incident.id

    print(f"🆕 New runtime incident created: ID = {incident_id} | REF = {reference}")

    # -------------------------------------------------------------
    # 3. Create agents (NO incident_manager injection!)
    # -------------------------------------------------------------
    log_analyst = create_log_analyst(llm)
    threat_intel = create_threat_intel(llm)
    network_engineer = create_network_engineer(llm)
    incident_commander = create_incident_commander(llm)

    # -------------------------------------------------------------
    # 4. Define internal callbacks to store events
    # -------------------------------------------------------------
    def cb_log(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Log Analyst",
            event_type="log_analysis",
            content=final,
        )
        return final

    def cb_intel(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Threat Intel",
            event_type="threat_intel",
            content=final,
        )
        return final

    def cb_mitigation(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Network Engineer",
            event_type="mitigation",
            content=final,
        )
        return final

    def cb_final(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Incident Commander",
            event_type="final_report",
            content=final,
        )
        # Mark pipeline completed
        incident_manager.update_pipeline_status(incident_id, "completed")
        return final

    # -------------------------------------------------------------
    # 5. Define Tasks
    # -------------------------------------------------------------
    t1 = Task(
        description=f"Analyze SSH log and extract suspicious indicators.\n\nLog entry:\n{log}",
        agent=log_analyst,
        expected_output="JSON list of indicators (IPs, users, dates).",
        callback=cb_log,
    )

    t2 = Task(
        description="Enrich indicators with threat intelligence.",
        agent=threat_intel,
        expected_output="JSON threat intel enrichment.",
        context=[t1],
        callback=cb_intel,
    )

    t3 = Task(
        description="Generate firewall or ACL mitigation rules.",
        agent=network_engineer,
        expected_output="JSON firewall/ACL commands.",
        context=[t2],
        callback=cb_mitigation,
    )

    t4 = Task(
        description="Produce an incident summary report.",
        agent=incident_commander,
        expected_output="Markdown formatted incident summary.",
        context=[t3],
        callback=cb_final,
    )

    # -------------------------------------------------------------
    # 6. Execute Crew
    # -------------------------------------------------------------
    crew = Crew(
        agents=[log_analyst, threat_intel, network_engineer, incident_commander],
        tasks=[t1, t2, t3, t4],
        verbose=True,
        tracing=True,
    )

    report = crew.kickoff()

    return report
