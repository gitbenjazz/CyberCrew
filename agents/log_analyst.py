from crewai import Agent
from tools.log_tools import parse_logs

log_analyst = Agent(
    role="Log Analyst",
    goal="Detect anomalies, brute-force attempts or unusual traffic from logs.",
    tools=[parse_logs],
    backstory=(
        "You are a cybersecurity analyst specialized in log correlation and "
        "detecting anomalies in SSH, firewall, and web logs."
    )
)
