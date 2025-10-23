# agents/network_engineer.py
from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.network_tools import suggest_fix
import json


class SuggestFixTool(BaseTool):
    name: str = "suggest_fix"
    description: str = (
        "Generates firewall mitigation commands (iptables, ACLs, etc.) "
        "to block or limit access from suspicious IP addresses."
    )

    def _run(self, input_text: str) -> str:
        """
        Accepts either:
          - a single IP (string)
          - or a JSON/dict/list of multiple IPs (from the Threat Intel output)
        Returns JSON with recommended mitigation commands.
        """
        try:
            # Try to decode JSON input from previous agent
            data = json.loads(input_text)
        except Exception:
            data = input_text  # if it’s raw text or a single IP

        actions = []

        # Case 1: a list of IP dicts [{'ip': '1.2.3.4', 'reputation': 'high'}, ...]
        if isinstance(data, list):
            for item in data:
                ip = item.get("ip")
                severity = item.get("reputation", "medium")
                if ip:
                    actions.append(suggest_fix(ip, severity))

        # Case 2: a dict of IPs {'203.0.113.56': 'high', '198.51.100.23': 'medium'}
        elif isinstance(data, dict):
            for ip, severity in data.items():
                actions.append(suggest_fix(ip, severity))

        # Case 3: a single IP (string)
        elif isinstance(data, str) and data.strip():
            actions.append(suggest_fix(data.strip()))

        else:
            return "❌ No valid IPs provided to suggest_fix."

        return json.dumps(actions, indent=2)

    async def _arun(self, input_text: str) -> str:
        return self._run(input_text)


def create_network_engineer(llm):
    """
    Factory function to create the Network Engineer agent.
    This agent generates actionable remediation commands from threat data.
    """
    return Agent(
        role="Network Engineer",
        goal=(
            "Generate firewall and ACL remediation commands to mitigate or block "
            "threats based on the suspicious IPs and their severity."
        ),
        backstory=(
            "You are a senior network security engineer skilled in defensive "
            "infrastructure configuration across Cisco, Palo Alto, and Linux environments. "
            "You translate risk assessments into precise network actions."
        ),
        tools=[SuggestFixTool()],
        llm=llm,
    )
