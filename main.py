from detection import detect_suspicious_processes
from heatmap import generate_heatmap
from reporting import generate_incident_report
import numpy as np

def dragonGrove_main():
    print("🚀 DragonGroveAI is now monitoring for threats...")

    # Step 1: Run Threat Detection
    risk_data = detect_suspicious_processes()  

    # Step 2: Generate Heatmap Based on Risks
    generate_heatmap(risk_data)

    # Step 3: Generate Incident Reports Dynamically
    for risk in risk_data:
        if risk == 3:  # High-Risk Alert
            report = generate_incident_report("Malicious Process Detected", "Critical Threat", "Terminate Immediately")
            print(report)

if __name__ == "__main__":
    dragonGrove_main()
