# agents/log_analyst.py
from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.log_tools import parse_logs  # ✅ import your local tool
import json
import os


class ParseLogsTool(BaseTool):
    """Tool that parses SSH authentication logs and extracts suspicious IPs."""

    # ✅ must include ": str" and "=" for Pydantic to parse correctly
    name: str = "parse_logs"
    description: str = (
        "Parse SSH authentication logs and extract suspicious IPs. "
        "Return a JSON list of suspicious entries with keys 'date', 'user', and 'ip'. "
        "If suspicious IPs are already present in the input, just return them as-is."
    )

    def _run(self, input_text: str) -> str:
        """Synchronous execution entrypoint for the tool."""
        import json
        import os

        # 🧠 Stop infinite loops: if the input already contains parsed data, return it
        if any(k in input_text for k in ["\"ip\"", "\"user\"", "\"date\""]):
            try:
                data = json.loads(input_text)
                if isinstance(data, list):
                    return json.dumps(data, indent=2)
            except Exception:
                pass
            return input_text  # Already structured, no need to re-parse

        # 🧩 Handle file path input
        clean_input = input_text.strip().replace("{", "").replace("}", "").replace("\"", "")
        if os.path.exists(clean_input):
            try:
                incidents = parse_logs(file_path=clean_input)
                return json.dumps(incidents, indent=2)
            except Exception as e:
                return json.dumps({"error": f"Failed to parse logs: {str(e)}"}, indent=2)

        # 🧩 Handle raw log text input
        tmp_path = "data/tmp_log.txt"
        os.makedirs("data", exist_ok=True)
        with open(tmp_path, "w") as f:
            f.write(input_text)

        try:
            incidents = parse_logs(file_path=tmp_path)
            return json.dumps(incidents, indent=2)
        except Exception as e:
            return f"❌ Error parsing logs: {e}"

    async def _arun(self, input_text: str) -> str:
        """Asynchronous version of _run."""
        return self._run(input_text)


def create_log_analyst(llm):
    """Factory function to create the Log Analyst agent."""
    return Agent(
        role="Log Analyst",
        goal="Detect anomalies, brute-force attempts, and suspicious SSH activity from system logs.",
        tools=[ParseLogsTool()],
        backstory=(
            "You are a cybersecurity analyst who inspects SSH authentication logs. "
            "You detect brute-force attacks, failed logins, and repeated access attempts from unknown IPs."
        ),
        llm=llm,
    )
