# agents/threat_intel.py
from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.threat_tools import lookup_threat
import json


class LookupThreatTool(BaseTool):
    name: str = "lookup_threat"
    description: str = (
        "Looks up suspicious IPs or domains using threat intelligence sources "
        "(e.g., VirusTotal, AbuseIPDB, or local mock database)."
    )

    def _run(self, input_text: str) -> str:
        """
        Accepts:
          - A single IP (string)
          - A JSON array or dict from Log Analyst (list of IPs or objects)
        Returns JSON with reputation and source info.
        """
        try:
            data = json.loads(input_text)
        except Exception:
            data = input_text  # fallback to plain text

        results = []

        # Case 1: list of dicts from Log Analyst [{"ip": "...", "user": "..."}]
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip")
                if ip:
                    results.append(lookup_threat(ip))

        # Case 2: dict of IPs {"203.0.113.56": "root", "198.51.100.23": "admin"}
        elif isinstance(data, dict):
            for ip in data.keys():
                results.append(lookup_threat(ip))

        # Case 3: plain string (one IP)
        elif isinstance(data, str) and data.strip():
            results.append(lookup_threat(data.strip()))

        else:
            return "❌ No valid IPs provided for lookup."

        return json.dumps(results, indent=2)

    async def _arun(self, input_text: str) -> str:
        return self._run(input_text)


def create_threat_intel(llm):
    """
    Factory that builds the Threat Intelligence agent once the LLM is initialized.
    This agent enriches suspicious IPs with threat context and reputation data.
    """
    return Agent(
        role="Threat Intelligence Specialist",
        goal=(
            "Enrich suspicious IPs from the log analyst with external threat intelligence "
            "data such as reputation, known malicious activity, and attack type."
        ),
        backstory=(
            "You query open-source and internal threat intelligence databases "
            "to determine whether an IP is associated with malicious campaigns, "
            "botnets, or prior attack patterns."
        ),
        tools=[LookupThreatTool()],
        llm=llm,
    )
