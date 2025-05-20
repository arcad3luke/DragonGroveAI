#/usr/bin/env python3

import subprocess
import sqlite3
import os
import time
import psutil
import pickle
import sys

# -----------------------------------------------------
# SentinelAI Orchestrator
# -----------------------------------------------------
def verify_malware_database(db_path="database/malware_samples.db"):
    """Check if the malware database exists and is accessible."""
    if not os.path.exists(db_path):
        print(f"❌ ERROR: Malware database '{db_path}' not found!")
        return False

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM malware_samples")
        total_entries = cursor.fetchone()[0]
        conn.close()

        print(f"✔ Malware database verified! Total stored samples: {total_entries}")
        return True
    except Exception as e:
        print(f"❌ ERROR: Database verification failed - {e}")
        return False

def verify_ml_model(model_path="ml_model.pkl"):
    """Check if the ML model exists and is properly loaded."""
    if not os.path.exists(model_path):
        print(f"❌ ERROR: ML Model '{model_path}' not found!")
        return False

    try:
        with open(model_path, "rb") as file:
            model = pickle.load(file)
        
        print(f"✔ ML Model verified! Model Type: {type(model).__name__}")
        return True
    except Exception as e:
        print(f"❌ ERROR: ML Model validation failed - {e}")
        return False

def system_diagnostics():
    """Perform key system health checks before launching SentinelAI."""
    print("🚀 Running DragonGroveAI Diagnostics...")

    # CPU and RAM Usage
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent
    print(f"✔ CPU Usage: {cpu_usage}% | RAM Usage: {ram_usage}%")

    # Active Processes
    active_processes = len(psutil.pids())
    print(f"✔ Active Processes: {active_processes}")

    # Malware Database Check
    if not verify_malware_database():
        print("⚠️ Warning: Malware database unavailable, proceeding with limited functionality.")

    # ML Model Check
    if not verify_ml_model():
        print("⚠️ Warning: ML model unavailable, predictions will be disabled.")

    print("✔ System diagnostics complete!")

# -----------------------------------------------------
# Start Dashboard
# -----------------------------------------------------
def start_dashboard():
    """Launch DragonGroveAI's real-time security dashboard."""
    try:
        subprocess.run(["python3", "dashboard/dashboard.py"], check=True)
    except subprocess.CalledProcessError:
        print("❌ ERROR: Failed to launch the dashboard.")
        sys.exit(1)

# -----------------------------------------------------
# Main Execution
# -----------------------------------------------------
if __name__ == "__main__":
    system_diagnostics()  # Run all verification checks before launching
    start_dashboard()  # Launch real-time dashboard
