from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.threat_tools import lookup_threat
import json
import re


class LookupThreatTool(BaseTool):
    name: str = "lookup_threat"
    description: str = (
        "Look up suspicious IPs using threat intelligence sources "
        "and return strict JSON."
    )

    def _run(self, input_text: str) -> str:
        try:
            data = json.loads(input_text)
        except:
            # Fallback: extract IPs
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
            ips = re.findall(ip_pattern, input_text)
            data = [{"ip": ip} for ip in ips]

        results = []
        for item in data:
            ip = item.get("ip")
            if ip:
                results.append(lookup_threat(ip))

        return json.dumps(results, indent=2)


def create_threat_intel(llm):
    return Agent(
        role="Threat Intelligence Specialist",
        goal="Enrich suspicious IPs with threat intelligence.",
        backstory="You correlate IPs with multiple threat intelligence feeds.",
        tools=[LookupThreatTool()],
        llm=llm,
    )
