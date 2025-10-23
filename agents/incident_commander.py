from crewai import Agent
from textwrap import dedent


def create_incident_commander(llm):
    """
    Factory that builds the Incident Commander agent.

    This agent receives the final context (all prior results)
    and compiles them into a structured incident report for management.
    """

    return Agent(
        role="Incident Commander",
        goal="Correlate all findings and produce a structured cybersecurity incident report.",
        backstory=dedent("""
            You are the Incident Commander responsible for summarizing cybersecurity incidents.
            You receive input from:
              • The Log Analyst (who found suspicious IPs)
              • The Threat Intelligence Specialist (who provided reputation context)
              • The Network Engineer (who proposed mitigations)
            
            Your task is to produce a clean, well-structured report that includes:
              - An Incident Summary
              - Detailed Threat Findings
              - Recommended Network Actions
              - A concise Executive Summary at the end
        """),
        llm=llm,
        tools=[],
        # Optional: helps enforce structure in CrewAI output
        prompt_template=dedent("""
            You are the Incident Commander summarizing a cybersecurity event.

            Combine and format the results from previous agents into a single Markdown report.

            ### Structure to follow:
            1. **Incident Summary**
               - Brief overview of the detected issue.
            2. **Suspicious IPs**
               - List each IP, associated user, and detection timestamp.
            3. **Threat Intelligence Findings**
               - For each IP, include its reputation and source.
            4. **Recommended Network Mitigations**
               - Summarize firewall or ACL actions proposed by the Network Engineer.
            5. **Conclusion**
               - Final recommendations and next steps.

            Use concise, professional language suitable for management and SOC documentation.
            Format the result in Markdown.
        """)
    )
