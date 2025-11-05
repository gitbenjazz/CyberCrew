from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.threat_tools import lookup_threat
import json
import re


class LookupThreatTool(BaseTool):
    name: str = "lookup_threat"
    description: str = (
        "Looks up suspicious IPs or domains using threat intelligence sources "
        "(e.g., VirusTotal, AbuseIPDB, or local mock database)."
        " Always return results as a strict JSON list."
    )

    def _run(self, input_text: str) -> str:
        """
        Accepts:
          - A single IP (string)
          - A JSON array or dict from Log Analyst (list of IPs or objects)
          - Or unstructured text (fallback)
        Returns: JSON list with reputation and source info.
        """
        try:
            data = json.loads(input_text)
        except Exception:
            # Try to extract any IPs from unstructured text
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
            ips = re.findall(ip_pattern, str(input_text))
            data = [{"ip": ip} for ip in ips] if ips else []

        results = []

        # Case 1: list of dicts from Log Analyst [{"ip": "...", "user": "..."}]
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip") if isinstance(item, dict) else str(item)
                if ip:
                    results.append(lookup_threat(ip))

        # Case 2: dict of IPs {"203.0.113.56": "root"}
        elif isinstance(data, dict):
            for ip in data.keys():
                results.append(lookup_threat(ip))

        # Case 3: single IP string
        elif isinstance(data, str) and data.strip():
            results.append(lookup_threat(data.strip()))

        if not results:
            return json.dumps([{"error": "No valid IPs found"}], indent=2)

        return json.dumps(results, indent=2)

    async def _arun(self, input_text: str) -> str:
        return self._run(input_text)


def create_threat_intel(llm):
    """
    Factory that builds the Threat Intelligence agent once the LLM is initialized.
    Forces structured JSON output for clean downstream consumption.
    """
    return Agent(
        role="Threat Intelligence Specialist",
        goal=(
            "Enrich suspicious IPs from the Log Analyst with external threat intelligence "
            "data (reputation, known malicious activity, and attack type). "
            "You MUST output ONLY a JSON array of results, no prose or explanations."
        ),
        backstory=(
            "You are an expert analyst who queries open-source and internal threat "
            "intelligence databases to determine whether IPs are malicious. "
            "Your results must be formatted strictly as JSON for machine consumption."
        ),
        tools=[LookupThreatTool()],
        llm=llm,
    )
