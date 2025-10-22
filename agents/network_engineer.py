from crewai import Agent
from tools.network_tools import suggest_fix

network_engineer = Agent(
    role="Network Engineer",
    goal="Generate network mitigation plans like blocking IPs or adjusting ACLs.",
    tools=[suggest_fix],
    backstory="You specialize in Cisco, Palo Alto, Checkpoint, Juniper, and Linux firewalls."
)
