# cybercrew_runtime.py

from crewai import Crew, Task, LLM
from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander
import os

def analyze_log(log: str):
    """Run the full CyberCrew pipeline on a single log entry."""

    # === 1. Initialize LLM ===
    model_name = os.getenv("CREWAI_MODEL")
    api_key = os.getenv("OPENAI_API_KEY")

    if not model_name or not api_key:
        raise ValueError("Missing LLM config (CREWAI_MODEL or OPENAI_API_KEY).")

    llm = LLM(model=model_name, api_key=api_key)

    # === 2. Create agents ===
    log_analyst = create_log_analyst(llm)
    threat_intel = create_threat_intel(llm)
    network_engineer = create_network_engineer(llm)
    incident_commander = create_incident_commander(llm)

    # === 3. Create tasks ===
    t1 = Task(
        description=f"Analyze SSH log and extract key indicators.\nLog: {log}",
        agent=log_analyst,
        expected_output="Extracted data for threat intel"
    )

    t2 = Task(
        description="Enrich indicators with threat intelligence.",
        agent=threat_intel,
        expected_output="Threat scores + IP reputation"
    )

    t3 = Task(
        description="Generate firewall/ACL mitigation rules.",
        agent=network_engineer,
        expected_output="Firewall configuration commands"
    )

    t4 = Task(
        description="Prepare an incident commander summary.",
        agent=incident_commander,
        expected_output="Incident report summarizing all actions."
    )

    # === 4. Build the crew ===
    crew = Crew(
        agents=[log_analyst, threat_intel, network_engineer, incident_commander],
        tasks=[t1, t2, t3, t4],
        verbose=True
    )

    # === 5. Run workflow ===
    result = crew.kickoff()   # <-- THIS is the correct method

    return result
