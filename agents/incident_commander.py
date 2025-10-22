from crewai import Agent

incident_commander = Agent(
    role="Incident Commander",
    goal="Correlate findings and produce a readable incident report with recommendations.",
    backstory="You summarize and prioritize incidents for executive review."
)
