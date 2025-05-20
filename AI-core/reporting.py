from datetime import datetime

def generate_incident_report(process_name, classification, remediation):
    report = {
        "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Process": process_name,
        "Classification": classification,
        "Remediation": remediation,
    }
    return report
