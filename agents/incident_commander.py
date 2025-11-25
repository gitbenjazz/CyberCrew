from crewai import Agent
from textwrap import dedent


def create_incident_commander(llm):
    return Agent(
        role="Incident Commander",
        goal="Produce a clean, structured final incident report.",
        backstory="You summarize all SOC findings for management.",
        llm=llm,
        prompt_template=dedent("""
            Create a structured incident report with:

            1. Incident Summary  
            2. Suspicious IPs  
            3. Threat Intel Findings  
            4. Network Mitigations  
            5. Executive Summary  

            Output only Markdown.
        """),
    )
