import psutil

def detect_suspicious_processes():
    suspicious_list = ["python", "powershell", "cmd"]
    risk_data = [0] * 9  # Ensure proper array size (for 3x3 grid)

    for i, process in enumerate(psutil.process_iter(attrs=['pid', 'name'])):
        if any(suspect in process.info['name'].lower() for suspect in suspicious_list):
            risk_data[i % 9] = 3  # Assign high risk, ensure index stays within range

    return risk_data
