from crewai import Agent
from crewai.tools.base_tool import BaseTool
from tools.log_tools import parse_logs
import json
import os


class ParseLogsTool(BaseTool):
    name: str = "parse_logs"
    description: str = "Parse SSH logs and extract suspicious IPs as JSON."

    def _run(self, input_text: str) -> str:
        # If JSON already present
        if any(k in input_text for k in ["\"ip\"", "\"user\"", "\"date\""]):
            return input_text

        if os.path.exists(input_text):
            incidents = parse_logs(input_text)
            return json.dumps(incidents, indent=2)

        tmp = "data/tmp_log.txt"
        os.makedirs("data", exist_ok=True)
        with open(tmp, "w") as f:
            f.write(input_text)

        incidents = parse_logs(tmp)
        return json.dumps(incidents, indent=2)


def create_log_analyst(llm):
    return Agent(
        role="Log Analyst",
        goal="Analyze logs and extract suspicious IPs.",
        backstory="You detect brute-force attempts and suspicious SSH activity.",
        tools=[ParseLogsTool()],
        llm=llm,
    )
