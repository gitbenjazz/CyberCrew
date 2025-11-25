# main.py
import os
from datetime import datetime
from dotenv import load_dotenv
from crewai import Crew, Task, LLM

from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander

from incident_storage.incident_manager import IncidentManager


# ======================================================
#  ENVIRONMENT
# ======================================================
def load_environment():
    env = os.getenv("ENV", "dev").lower()
    env_file = {"dev": ".env", "prod": ".env"}.get(env)

    if not env_file:
        raise ValueError(f"Unknown environment: {env}")

    load_dotenv(dotenv_path=env_file, override=False)
    print(f"Environment '{env}' loaded.")


# ======================================================
#  TEMPERATURE
# ======================================================
def get_temperature():
    try:
        return float(os.getenv("PIPELINE_TEMPERATURE", "0.2"))
    except ValueError:
        print("⚠️ Invalid PIPELINE_TEMPERATURE. Using 0.2")
        return 0.2


# ======================================================
#  LLM
# ======================================================
def initialize_llm():
    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    model_name = os.getenv("CREWAI_MODEL", "gpt-4o-mini")

    if provider == "ollama":
        print(f"Using local Ollama model: {model_name}")
        return LLM(model=f"ollama/{model_name}")

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("Missing OPENAI_API_KEY")

    print(f"Using OpenAI model: {model_name}")
    return LLM(model=model_name, api_key=api_key)


# ======================================================
#  AGENTS
# ======================================================
def create_agents(llm):
    return {
        "log_analyst": create_log_analyst(llm),
        "threat_intel": create_threat_intel(llm),
        "network_engineer": create_network_engineer(llm),
        "incident_commander": create_incident_commander(llm),
    }


# ======================================================
#  OUTPUT EXTRACTOR (CrewAI 1.5+)
# ======================================================
def extract_output(output):
    """
    output.raw_output = [{"role": "assistant", "content": "..."}]
    """
    try:
        return output.raw_output[-1]["content"]
    except Exception:
        return str(output)


# ======================================================
#  REFERENCE GENERATION (Option A)
# ======================================================
def generate_reference() -> str:
    # Example: INC-20251122-223015
    return "INC-" + datetime.utcnow().strftime("%Y%m%d-%H%M%S")


# ======================================================
#  PIPELINE
# ======================================================
def run_pipeline(log_path: str, temperature: float = None):

    if not os.path.exists(log_path):
        raise FileNotFoundError(f"File not found: {log_path}")

    load_environment()
    llm = initialize_llm()
    if temperature is None:
        temperature = get_temperature()

    incident_manager = IncidentManager()

    # ---- Create incident with new schema ----
    reference = generate_reference()
    incident = incident_manager.create_incident(
        reference=reference,
        description=f"Ingestion from log file: {log_path}",
        severity=None,  # we'll compute later from Threat Intel
    )
    incident_id = incident.id
    print(f"🆕 Incident created: ID = {incident_id} | REF = {reference}")

    agents = create_agents(llm)

    # ======================================================
    # CALLBACKS
    # ======================================================

    # ---- Log Analyst ----
    def cb_log(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Log Analyst",
            event_type="log_analysis",
            content=final,
        )
        return final

    # ---- Threat Intel ----
    def cb_intel(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Threat Intel",
            event_type="threat_intel",
            content=final,
        )
        # NOTE: later we can parse 'final' here to compute severity
        return final

    # ---- Network Engineer ----
    def cb_mitigation(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Network Engineer",
            event_type="mitigation",
            content=final,
        )
        return final

    # ---- Final report ----
    def cb_final(output):
        final = extract_output(output)
        incident_manager.add_event(
            incident_id,
            agent="Incident Commander",
            event_type="final_report",
            content=final,
        )
        # Pipeline successfully completed
        incident_manager.update_pipeline_status(incident_id, "completed")
        return final

    # ======================================================
    # TASKS
    # ======================================================
    task1 = Task(
        description=f"Analyze SSH logs in {log_path} and extract suspicious IPs.",
        agent=agents["log_analyst"],
        expected_output="JSON list of suspicious IPs.",
        callback=cb_log,
    )

    task2 = Task(
        description="Enrich suspicious IPs with threat intelligence.",
        agent=agents["threat_intel"],
        expected_output="JSON enriched IP data.",
        context=[task1],
        callback=cb_intel,
    )

    task3 = Task(
        description="Generate firewall mitigation actions.",
        agent=agents["network_engineer"],
        expected_output="JSON ACL/firewall commands.",
        context=[task2],
        callback=cb_mitigation,
    )

    task4 = Task(
        description="Produce the final incident report.",
        agent=agents["incident_commander"],
        expected_output="Markdown formatted incident report.",
        context=[task3],
        callback=cb_final,
    )

    # ======================================================
    # CREW
    # ======================================================
    crew = Crew(
        agents=list(agents.values()),
        tasks=[task1, task2, task3, task4],
        verbose=True,
        tracing=True,
        temperature=temperature,
    )

    print("\n=== Running CrewAI pipeline ===")
    return crew.kickoff()


# ======================================================
# CLI
# ======================================================
if __name__ == "__main__":
    LOG_PATH = "data/sample_logs/auth.log"
    try:
        report = run_pipeline(LOG_PATH)
        print("\n=== FINAL REPORT ===")
        print(report)
    except Exception as e:
        print("❌ Error:", e)
