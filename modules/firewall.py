import logging
import os
import re
import sqlite3
from rich.console import Console
from rich.table import Table
import json

# Define paths for saving parsed logs
FIREWALL_LOGS_REPORT = "../logs/firewall_logs_analysis.json"
SNORT_LOGS_REPORT = "../logs/snort_logs_analysis.json"
LOG_FILE_PATH = "../logs/firewall.log"

def init_db():
    try:
        # Initialize database
        conn = sqlite3.connect('../database/firewall_logs.db')
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_data TEXT
        )''')

        conn.commit()
        conn.close()
    except ConnectionError as c:
        print(f'Connection error: {c}')
    finally:
        if not ConnectionError:
            print("🔥 Firewall log database initialized!")
        else:
            print(f'ERROR: {ConnectionError}')
init_db()
# Parse & Store logs

def parse_log(line):
    match = re.match(r'(\S+ \S+) (\S+) (\S+) (\d+) (\S+) (\S+) (.+)', line)
    return match.groups() if match else None

def store_logs():
    conn = sqlite3.connect('firewall_logs.db')
    cursor = conn.cursor()

    with open(LOG_FILE_PATH, 'r') as f:
        for line in f:
            entry = parse_log(line)
            for l in entry['source_ip', 'destination_ip', 'port', 'protocol', 'action', 'rule_value', 'log_message']:
                try:
                    log_info = {
                        l['source_ip'] : 'source_ip',
                        l['destination_ip'] : 'destination_ip',
                        l['port'] : 'port',
                        l['protocol'] : 'protocol',
                        l['action'] : 'action',
                        l['rule_value'] : 'rule',
                        l['log_message'] : 'log_message'
                    }
                except IOError as e:
                    print(f'ERROR: {e}')
                finally:
                    if not IOError:
                        cursor.execute("""
                            INSERT INTO firewall_logs (source_ip, destination_ip, port, protocol, action, rule, log_message)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, log_info)
                        conn.commit()
                        conn.close()
                        print("🔥 Logs inserted successfully!")
                        return log_info
                    else:
                        print(f'{IOError}')
    f.close()

# Log everything from SQL to JSON
def log_sql_to_json():
    conn = sqlite3.connect('../database/firewall_logs.db')
    cursor = conn.cursor()

    cursor.execute("SELECT log_data FROM logs")
    logs = [json.loads(row[0]) for row in cursor.fetchall()]

    for f,s in logs:
        with open(FIREWALL_LOGS_REPORT, 'rw') as F:
            json.dumps(f, indent=4)
        with open(SNORT_LOGS_REPORT, 'rw') as S:
            json.dumps(s, indent=4)

    conn.close()

console = Console()



### Firewall Log Functions
def render_firewall_table(REPORT):
    """
    Render firewall log entries in a table format for the terminal.
    """
    table = Table(title="Firewall Logs Analysis")
    table.add_column("Event", justify="left", style="cyan")
    table.add_column("Details", justify="left", style="green")

    for entry in REPORT:
        table.add_row(entry["Event"], entry["Details"])
    console.print(table)

### Snort Log Functions
def locate_snort_logs():
    """
    Locate Snort logs directory dynamically.
    """
    default_snort_path = "/var/log/snort/"
    if os.path.exists(default_snort_path):
        logging.info(f"Snort logs directory found: {default_snort_path}")
        return default_snort_path
    logging.warning("Snort logs directory not found.")
    return None

def parse_snort_logs(snort_path):
    """
    Parse Snort log files for actionable alerts.
    """
    log_data = []
    try:
        alert_file = os.path.join(snort_path, "alert")
        if not os.path.exists(alert_file):
            logging.warning("Snort alert file not found.")
            return []

        logging.info(f"Parsing Snort alerts from: {alert_file}")
        with open(alert_file, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                # Match Snort alert lines for details
                match = re.match(
                    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2})\.\d+ \[.* ([A-Za-z0-9 ]+) "
                    r"\[Classification: (.+) \[Priority: (\d+): .* "
                    r"(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)", line
                )
                if match:
                    timestamp, signature, classification, priority, src_ip, src_port, dst_ip, dst_port = match.groups()
                    log_data.append({
                        "Timestamp": timestamp,
                        "Signature": signature,
                        "Classification": classification,
                        "Priority": int(priority),
                        "Source IP": src_ip,
                        "Source Port": src_port,
                        "Destination IP": dst_ip,
                        "Destination Port": dst_port
                    })
    except Exception as e:
        logging.error(f"Error parsing Snort logs: {e}", exc_info=True)
    return log_data

def save_snort_logs(log_data):
    """
    Save parsed Snort logs to a JSON report.
    """
    try:
        with open(SNORT_LOGS_REPORT, "w") as file:
            json.dump(log_data, file, indent=4)
        logging.info(f"Snort logs saved to {SNORT_LOGS_REPORT}")
    except Exception as e:
        logging.error(f"Error saving Snort logs: {e}", exc_info=True)

def render_snort_table(log_data):
    """
    Render Snort log entries in a table format for the terminal.
    """
    table = Table(title="Snort Alerts")
    table.add_column("Timestamp", style="cyan", justify="left")
    table.add_column("Signature", style="magenta", justify="left")
    table.add_column("Classification", style="yellow", justify="left")
    table.add_column("Priority", style="red", justify="center")
    table.add_column("Source", style="green", justify="left")
    table.add_column("Destination", style="blue", justify="left")

    for entry in log_data:
        table.add_row(
            entry["Timestamp"],
            entry["Signature"],
            entry["Classification"],
            str(entry["Priority"]),
            f"{entry['Source IP']}:{entry['Source Port']}",
            f"{entry['Destination IP']}:{entry['Destination Port']}"
        )
    console.print(table)

### Unified Monitoring Function
def monitor_logs():
    """
    Monitor and analyze both firewall and Snort logs.
    """
    logging.info("Starting unified log monitoring...")

    # Firewall logs monitoring
    logging.info("Monitoring firewall logs...")
    firewall_log_files = FIREWALL_LOGS_REPORT
    if firewall_log_files:
        render_firewall_table(firewall_log_files)
        store_logs()
    else:
        logging.info("No actionable entries found in firewall logs.")
        console.print("[yellow]No actionable events found in firewall logs.[/yellow]")

    # Snort logs monitoring
    logging.info("Monitoring Snort logs...")
    snort_path = locate_snort_logs()
    if snort_path:
        snort_logs = parse_snort_logs(snort_path)
        if snort_logs:
            render_snort_table(snort_logs)
            save_snort_logs(snort_logs)
        else:
            logging.info("No actionable alerts found in Snort logs.")
            console.print("[yellow]No actionable alerts found in Snort logs.[/yellow]")

    logging.info("Unified log monitoring complete.")
