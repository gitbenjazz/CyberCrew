from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.network_tools import suggest_fix
import json
import re


class SuggestFixTool(BaseTool):
    name: str = "suggest_fix"
    description: str = "Generate firewall mitigation commands based on severity."

    def _run(self, input_text: str) -> str:
        try:
            data = json.loads(input_text)
        except:
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
            ips = re.findall(ip_pattern, input_text)
            data = [{"ip": ip, "reputation": "low"} for ip in ips]

        actions = []
        for entry in data:
            ip = entry.get("ip")
            sev = entry.get("reputation", "medium")
            if ip:
                actions.append(suggest_fix(ip, sev))

        return json.dumps(actions, indent=2)


def create_network_engineer(llm):
    return Agent(
        role="Network Automation Engineer",
        goal="Transform threat intel into deterministic firewall rules.",
        backstory="You generate ACL and firewall mitigations.",
        tools=[SuggestFixTool()],
        llm=llm,
    )
