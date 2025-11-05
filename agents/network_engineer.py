from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.network_tools import suggest_fix
import json
import re


class SuggestFixTool(BaseTool):
    name: str = "suggest_fix"
    description: str = (
        "Generates firewall mitigation commands (iptables, ACLs, etc.) "
        "to block or limit access from suspicious IP addresses, "
        "STRICTLY according to the provided severity level (low, medium, high)."
    )

    def _run(self, input_text: str) -> str:
        """
        Accepts either:
          - a JSON list/dict of IPs with reputation
          - or unstructured text (fallback)
        Returns JSON with recommended mitigation commands.
        """
        try:
            data = json.loads(input_text)
        except Exception:
            # fallback: extract IPs and assume low risk
            ip_pattern = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"
            ips = re.findall(ip_pattern, str(input_text))
            data = [{"ip": ip, "reputation": "low"} for ip in ips]

        actions = []
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip")
                severity = item.get("reputation", "medium")
                if ip:
                    actions.append(suggest_fix(ip, severity))

        elif isinstance(data, dict):
            for ip, severity in data.items():
                actions.append(suggest_fix(ip, severity))

        else:
            return json.dumps([{"error": "No valid IPs provided"}], indent=2)

        return json.dumps(actions, indent=2)

    async def _arun(self, input_text: str) -> str:
        return self._run(input_text)


def create_network_engineer(llm):
    """
    Factory for Network Engineer agent.
    The agent simply calls suggest_fix() and outputs its JSON result without modification.
    """
    return Agent(
        role="Network Automation Engineer",
        goal=(
            "Convert IP reputation data into actionable network configurations. "
            "Use the suggest_fix tool and OUTPUT ONLY its JSON results. "
            "Do NOT make decisions beyond the severity mapping already handled by the tool."
        ),
        backstory=(
            "You are a disciplined automation engineer. "
            "Your job is to translate risk data into firewall commands deterministically. "
            "You do NOT reason about threats — you only execute the suggest_fix tool output as-is."
        ),
        tools=[SuggestFixTool()],
        llm=llm,
    )
