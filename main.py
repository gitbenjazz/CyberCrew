from crewai import Crew, Task
from agents.log_analyst import log_analyst
from agents.threat_intel import threat_intel
from agents.network_engineer import network_engineer
from agents.incident_commander import incident_commander

crew = Crew([
    log_analyst,
    threat_intel,
    network_engineer,
    incident_commander
])

task = Task("Analyze system logs for suspicious IPs and produce a remediation plan.")
report = crew.run(task)

print("\n=== FINAL INCIDENT REPORT ===")
print(report)
