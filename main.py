# main.py
import os
from dotenv import load_dotenv
from crewai import Crew, Task, LLM
from agents.log_analyst import create_log_analyst
from agents.threat_intel import create_threat_intel
from agents.network_engineer import create_network_engineer
from agents.incident_commander import create_incident_commander

# === 0. Load Environment ===
env = os.getenv("ENV", "dev").lower()
env_file = { "dev": ".env", "prod": ".env" }.get(env)

if env_file:
    load_dotenv(dotenv_path=env_file, override=True)
    print(f"Environment '{env}' loaded.")
else:
    raise ValueError(f"Unknown environment: {env}")


model_llm = None

if os.getenv("AUTO_INITIALIZE")=="TRUE" :
    model_name = os.getenv("CREWAI_MODEL")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY not found in environment!")
    model_llm = LLM(model=model_name, api_key=api_key)
    print(f"✅ LLM configured: {model_name}")

else:
    # === 1. Choose LLM source ===
    print("\n=== Choose LLM Provider ===")
    print("1️⃣  Ollama local model")
    print("2️⃣  OpenAI API")
    choice = input("Enter your choice [1/2]: ").strip()


    try:
        if choice == "1":
            print("\nAvailable Ollama models:")
            os.system("ollama list")
            model_name = input("\nType the Ollama model name (e.g. llama3): ").strip() or "llama3"

            model_llm = LLM(model=f"ollama/{model_name}")
            print(f"✅ LLM configured: ollama/{model_name}")

        elif choice == "2":
            model_name = os.getenv("CREWAI_MODEL", "gpt-4o-mini")
            api_key = os.getenv("OPENAI_API_KEY")

            if not api_key:
                raise ValueError("OPENAI_API_KEY not found in environment!")

            model_llm = LLM(model=model_name, api_key=api_key)
            print(f"✅ LLM configured: {model_name}")

        else:
            raise ValueError("Invalid choice. Please select 1 or 2.")

    except Exception as e:
        print(f"❌ Failed to initialize LLM: {e}")
        exit(1)

# === Choose Temperature 
# === 1.5 Choose Temperature ===
print("\n=== Choose LLM Temperature ===")
print("0️⃣  Deterministic (0.0) → Identical results, good for debugging")
print("1️⃣  Balanced (0.2) → Slight flexibility, stable behavior")
print("2️⃣  Creative (0.4) → More reasoning freedom, less consistency")
choice_temp = input("Enter your choice [0/1/2]: ").strip()

temp_map = {
    "0": 0.0,
    "1": 0.2,
    "2": 0.4
}
temperature = temp_map.get(choice_temp, 0.2)
print(f"🌡️  Temperature set to {temperature}")



# === 2. Create Agents ===
print("\n=== Creating Agents ===")
log_analyst = create_log_analyst(model_llm)
threat_intel = create_threat_intel(model_llm)
network_engineer = create_network_engineer(model_llm)
incident_commander = create_incident_commander(model_llm)
print("✅ All agents created successfully.")

# === 3. Load Logs ===
log_path = "data/sample_logs/auth.log"
if os.path.exists(log_path):
    print(f"📄 Log file loaded: {log_path}")
else:
    raise FileNotFoundError(f"❌ Log file not found: {log_path}")

# === 4. Define Tasks ===
task_log_analysis = Task(
    description=f"Analyze SSH logs in {log_path} and extract all suspicious IPs or failed login attempts.",
    agent=log_analyst,
    expected_output="A JSON list of suspicious IPs and users detected in the logs."
)

task_threat_intel = Task(
    description="Cross-reference suspicious IPs with public threat intelligence databases "
                "and assign a reputation score (low, medium, high).",
    agent=threat_intel,
    expected_output="A JSON list of enriched IPs with reputation and risk context.",
    context=[task_log_analysis],
)

task_network_mitigation = Task(
    description="Generate firewall or ACL rules to mitigate threats "
                "based on IP reputation levels.",
    agent=network_engineer,
    expected_output="A JSON list of firewall rules or commands with reasons.",
    context=[task_threat_intel],
)

task_incident_report = Task(
    description="Summarize all findings into a Markdown incident report "
                "including suspicious IPs, threat intel data, and mitigation actions.",
    agent=incident_commander,
    expected_output="Markdown-formatted incident report for management.",
    context=[task_network_mitigation],
)

tasks = [task_log_analysis, task_threat_intel, task_network_mitigation, task_incident_report]
# === Verifier Input 


def verify_inputs():
    required_files = ["data/sample_logs/auth.log"]
    for f in required_files:
        if not os.path.exists(f):
            raise FileNotFoundError(f"Missing required file: {f}")
        if os.path.getsize(f) == 0:
            raise ValueError(f"File is empty: {f}")
    print("✅ Input verification passed")

verify_inputs()


# === 5. Initialize Crew ===
print("\n=== Initializing Crew ===")
crew = Crew(
    agents=[log_analyst, threat_intel, network_engineer, incident_commander],
    tasks=tasks,
    verbose=True,
    tracing=True,
    temperature=temperature 
)

# === 6. Run Crew ===
print("\n=== Running Crew ===")
try:
    final_report = crew.kickoff()
except Exception as e:
    print("⚠️ Error during Crew run:", e)
    final_report = None

# === 7. Output ===
print("\n=== FINAL INCIDENT REPORT ===")
print(final_report or "No report generated.")
