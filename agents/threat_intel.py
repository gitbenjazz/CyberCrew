from crewai import Agent
from tools.threat_tools import lookup_threat

threat_intel = Agent(
    role="Threat Intelligence",
    goal="Enrich suspicious IPs with threat intelligence data.",
    tools=[lookup_threat],
    backstory="You query open-source or local threat intelligence databases."
)
