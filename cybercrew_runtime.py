# cybercrew_runtime.py

import os
from datetime import datetime
from crewai import Crew, Task, LLM

# Agents
from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander

# Incident Storage
from incident_storage.incident_manager import IncidentManager

# Threat Intel
from tools.threat_tools import lookup_threat

# Auto-Severity Engine
from tools.severity_engine import compute_severity


# ======================================================
# Helper: extract content from TaskOutput
# ======================================================
def extract_output(output):
    try:
        return output.raw_output[-1]["content"]
    except:
        return str(output)


# ======================================================
# Helper: generate reference
# ======================================================
def generate_reference():
    return "INC-" + datetime.utcnow().strftime("%Y%m%d-%H%M%S")


# ======================================================
# Extract first IP from log
# ======================================================
def extract_ip(log: str):
    for token in log.split():
        if token.count(".") == 3:
            return token.strip()
    return None


# ======================================================
# Main runtime pipeline
# ======================================================
def analyze_log(log: str):
    """Run CyberCrew pipeline on a single log entry."""

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
    # 2. Threat Intel + Severity BEFORE pipeline
    # -------------------------------------------------------------
    ip = extract_ip(log)

    if ip:
        threat_info = lookup_threat(ip)
    else:
        threat_info = {"reputation": "unknown", "details": "No IP found"}

    severity_info = compute_severity(log, threat_info)

    print(f"🛡 Threat Intel: {threat_info}")
    print(f"🔥 Auto-Severity: {severity_info}")

    # -------------------------------------------------------------
    # 3. Create Incident in DB
    # -------------------------------------------------------------
    incident_manager = IncidentManager()

    reference = generate_reference()
    incident = incident_manager.create_incident(
        reference=reference,
        description="Runtime ingestion of a single log entry",
        severity=severity_info.get("severity"),
    )
    incident_id = incident.id

    print(f"🆕 New incident created: ID={incident_id} REF={reference}")

    # -------------------------------------------------------------
    # 4. Create Agents
    # -------------------------------------------------------------
    log_analyst = create_log_analyst(llm)
    threat_intel_agent = create_threat_intel(llm)
    network_engineer = create_network_engineer(llm)
    incident_commander = create_incident_commander(llm)

    # -------------------------------------------------------------
    # 5. Callbacks
    # -------------------------------------------------------------
    def cb_log(output):
        final = extract_output(output)
        incident_manager.add_event(incident_id, "Log Analyst", "log_analysis", final)
        return final

    def cb_intel(output):
        final = extract_output(output)
        incident_manager.add_event(incident_id, "Threat Intel", "threat_intel", final)
        return final

    def cb_mitigation(output):
        final = extract_output(output)
        incident_manager.add_event(incident_id, "Network Engineer", "mitigation", final)
        return final

    def cb_final(output):
        final = extract_output(output)
        incident_manager.add_event(incident_id, "Incident Commander", "final_report", final)
        incident_manager.update_pipeline_status(incident_id, "completed")
        return final

    # -------------------------------------------------------------
    # 6. Tasks (FIX: added expected_output)
    # -------------------------------------------------------------
    t1 = Task(
        description=f"Analyze the following SSH log:\n{log}",
        expected_output="JSON list of extracted indicators (IPs, usernames, timestamps).",
        agent=log_analyst,
        callback=cb_log,
    )

    t2 = Task(
        description=f"Perform threat intelligence enrichment using: {threat_info}",
        expected_output="JSON describing threat intel context (risk level, provider data).",
        agent=threat_intel_agent,
        context=[t1],
        callback=cb_intel,
    )

    t3 = Task(
        description=f"Generate mitigation steps based on log + threat intel.\nLog: {log}\nThreat: {threat_info}",
        expected_output="JSON containing recommended firewall/ACL/network mitigation actions.",
        agent=network_engineer,
        context=[t2],
        callback=cb_mitigation,
    )

    t4 = Task(
        description=(
            f"Produce final incident summary.\n"
            f"Severity: {severity_info}\n"
            f"Threat Intel: {threat_info}\n"
            f"Log: {log}"
        ),
        expected_output="Markdown formatted final incident report.",
        agent=incident_commander,
        context=[t3],
        callback=cb_final,
    )

    # -------------------------------------------------------------
    # 7. Execute Crew
    # -------------------------------------------------------------
    crew = Crew(
        agents=[log_analyst, threat_intel_agent, network_engineer, incident_commander],
        tasks=[t1, t2, t3, t4],
        verbose=True,
        tracing=True,
    )

    crew_report = crew.kickoff()

    return {
        "incident_id": incident_id,
        "reference": reference,
        "ip": ip,
        "severity": severity_info,
        "threat_intel": threat_info,
        "crew_report": crew_report,
    }
