# main.py
import os
from dotenv import load_dotenv
from crewai import Crew, Task, LLM

from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander


# -------------------------------------------------------
# 0. Environment loading
# -------------------------------------------------------
def load_environment():
    """Load environment variables depending on ENV."""
    env = os.getenv("ENV", "dev").lower()
    env_file = {"dev": ".env", "prod": ".env"}.get(env)

    if not env_file:
        raise ValueError(f"Unknown environment: {env}")

    load_dotenv(dotenv_path=env_file, override=True)
    print(f"Environment '{env}' loaded.")


# -------------------------------------------------------
# 1. Temperature handling
# -------------------------------------------------------
def get_temperature():
    """Return pipeline temperature from env or default to 0.2."""
    try:
        return float(os.getenv("PIPELINE_TEMPERATURE", "0.2"))
    except ValueError:
        print("⚠️ Invalid PIPELINE_TEMPERATURE value. Using default 0.2")
        return 0.2


# -------------------------------------------------------
# 2. Model initialization (OpenAI default)
# -------------------------------------------------------
def initialize_llm():
    """
    Initializes LLM using env variables:

        LLM_PROVIDER = 'openai' | 'ollama'
        CREWAI_MODEL = model name (gpt-4o-mini, llama3, etc.)

    Default provider: openai
    """
    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    model_name = os.getenv("CREWAI_MODEL", "gpt-4o-mini")

    if provider == "ollama":
        print(f"Using local Ollama model: {model_name}")
        return LLM(model=f"ollama/{model_name}")

    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY missing! You must export it before running the code."
            )
        print(f"Using OpenAI model: {model_name}")
        return LLM(model=model_name, api_key=api_key)

    else:
        raise ValueError(f"Invalid LLM_PROVIDER: {provider}")


# -------------------------------------------------------
# 3. Agent factory
# -------------------------------------------------------
def create_agents(llm):
    """Instantiate all agents with the selected LLM."""
    print("\n=== Creating Agents ===")
    return {
        "log_analyst": create_log_analyst(llm),
        "threat_intel": create_threat_intel(llm),
        "network_engineer": create_network_engineer(llm),
        "incident_commander": create_incident_commander(llm),
    }


# -------------------------------------------------------
# 4. Main pipeline
# -------------------------------------------------------
def run_pipeline(log_path: str, temperature: float = None):
    """
    Runs the 4-step CrewAI pipeline for a given log file.
    This can be called by CLI, API or ingestion server.
    """
    if not (os.path.exists(log_path) and os.path.getsize(log_path) > 0):
        raise FileNotFoundError(f"Invalid or empty log file: {log_path}")

    # load environment + choose model
    load_environment()
    llm = initialize_llm()

    # temperature from caller OR from env
    if temperature is None:
        temperature = get_temperature()

    agents = create_agents(llm)

    # Tasks
    task1 = Task(
        description=f"Analyze SSH logs in {log_path} and extract suspicious IPs.",
        agent=agents["log_analyst"],
        expected_output="JSON list of suspicious IPs and users."
    )

    task2 = Task(
        description="Enrich suspicious IPs with threat intelligence feeds.",
        agent=agents["threat_intel"],
        expected_output="JSON with enriched IPs + reputation.",
        context=[task1],
    )

    task3 = Task(
        description="Generate firewall recommendations.",
        agent=agents["network_engineer"],
        expected_output="JSON list of ACL/Firewall mitigations.",
        context=[task2],
    )

    task4 = Task(
        description="Create a Markdown incident report summarizing findings.",
        agent=agents["incident_commander"],
        expected_output="Markdown incident summary.",
        context=[task3],
    )

    # Crew
    crew = Crew(
        agents=list(agents.values()),
        tasks=[task1, task2, task3, task4],
        verbose=True,
        tracing=True,
        temperature=temperature
    )

    print("\n=== Running CrewAI pipeline ===")
    return crew.kickoff()


# -------------------------------------------------------
# 5. CLI runner
# -------------------------------------------------------
if __name__ == "__main__":
    LOG_PATH = "data/sample_logs/auth.log"
    try:
        report = run_pipeline(LOG_PATH)
        print("\n=== FINAL INCIDENT REPORT ===")
        print(report)
    except Exception as e:
        print("❌ Error:", e)
