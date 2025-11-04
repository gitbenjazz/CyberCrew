# main.py
from crewai import Crew, Task, LLM
from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander
import os


from dotenv import load_dotenv

env = os.getenv("ENV", "dev").lower()

# Map environment to file
env_file = {
    "dev": ".env",
    "prod": ".env",
}.get(env)

if env_file:
    load_dotenv(dotenv_path=env_file,override=True)
    print(f"env {env} loaded")

else:
    raise ValueError(f"Unknown environment: {env}")


# === 1. Initialize LLM ===
print("=== Initializing LLM ===")
try:
    if os.environ.get("MODEL_TO_USE") == "LLAMA":
        model_llm = LLM(model="ollama/llama3")
        print("✅ LLM configured: ollama/llama3")
    elif os.environ.get("MODEL_TO_USE") == "OPENAI":
        model_llm = LLM(
            model=os.getenv("CREWAI_MODEL"), #"gpt-4o-mini",
            api_key=os.getenv("OPENAI_API_KEY")  # expects env var
        )
        print("✅ LLM configured: gpt-4o-mini")


except Exception as e:
    print("❌ Failed to initialize LLM:", e)
    model_llm = None

# === 2. Create Agents ===
print("=== Creating Agents ===")
log_analyst = create_log_analyst(model_llm)
threat_intel = create_threat_intel(model_llm)
network_engineer = create_network_engineer(model_llm)
incident_commander = create_incident_commander(model_llm)
print("✅ All agents created with LLM attached")

# === 3. Load Logs ===
log_path = "data/sample_logs/auth.log"
if os.path.exists(log_path):
    print(f"📄 Loaded log file: {log_path}")
else:
    raise FileNotFoundError(f"❌ Log file not found: {log_path}")

# === 4. Define Tasks ===

# Step 1: Log Analyst parses the raw log file
task_log_analysis = Task(
    description=f"Analyze SSH logs in {log_path} and extract all suspicious IP addresses or failed login attempts.",
    agent=log_analyst,
    expected_output="A JSON list of suspicious IPs and users detected in the logs."
)

# Step 2: Threat Intel enriches the detected IPs
task_threat_intel = Task(
    description="Cross-reference the suspicious IPs with public threat intelligence databases "
                "and assign a reputation score (low, medium, high).",
    agent=threat_intel,
    expected_output="A JSON list of enriched IPs with reputation and risk context.",
    context=[task_log_analysis],  # <── depends on previous task output
)

# Step 3: Network Engineer suggests mitigations
task_network_mitigation = Task(
    description="Generate firewall or ACL rules to block or mitigate threats "
                "based on the reputation levels of suspicious IPs.",
    agent=network_engineer,
    expected_output="A JSON list of firewall rules or commands with reasons.",
    context=[task_threat_intel],
)

# Step 4: Incident Commander summarizes everything
task_incident_report = Task(
    description="Correlate all findings into a complete incident report including "
                "the list of suspicious IPs, threat intel data, and mitigation actions.",
    agent=incident_commander,
    expected_output="A Markdown-formatted incident report for management and SOC records.",
    context=[task_network_mitigation],
)

tasks = [task_log_analysis, task_threat_intel, task_network_mitigation, task_incident_report]

# === 5. Initialize Crew ===
print("=== Initializing Crew ===")
crew = Crew(
    agents=[log_analyst, threat_intel, network_engineer, incident_commander],
    tasks=tasks,
    verbose=True,
    tracing=True,
)

# === 6. Run Crew ===
print("=== Running Crew ===")
try:
    final_report = crew.kickoff()
except Exception as e:
    print("⚠️ Error during Crew run:", e)
    final_report = None

# === 7. Output ===
print("\n=== FINAL INCIDENT REPORT ===")
print(final_report or "No report generated.")
