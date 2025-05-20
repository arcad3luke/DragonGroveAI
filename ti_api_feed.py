# Import Required Libraries
from dotenv import load_dotenv
import os
import requests
import sqlite3
import time
import json

# Load Environment Variables
load_dotenv()

# Initialize API keys
alienvault_api_key = os.getenv("OTX_API_KEY")
virustotal_api_key = os.getenv("VT_API_KEY")
openphish_url = "https://openphish.com/feed.txt"

# Initialize SQLite Database
DB_NAME = "dragon_grove_ti.sqlite"
conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

# Create Unified Database Schema
cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT,
    entry_type TEXT,
    entry_value TEXT,
    time_stamp TEXT,
    additional_info TEXT,
    timestamp_added DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()
conn.close()
print("Database initialized and schema created.")

# Function for Logging Errors
def log_error(source, error_message):
    print(f"[ERROR] {source}: {error_message}")

# 🔥 Load Hashes from malware_db.sqlite 🔥
def get_hashes_from_db():
    """Retrieve hashes from the malware database."""
    try:
        conn = sqlite3.connect("../database/malware_db.sqlite")  # Connect to malware_db.sqlite
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT file_hash FROM malware_samples WHERE file_hash IS NOT NULL")
        hashes = [row[0] for row in cursor.fetchall()]  # Extract hashes
        conn.close()
        print(f"Fetched {len(hashes)} hashes from malware_db.sqlite.")
        return hashes
    except sqlite3.Error as e:
        log_error("malware_db.sqlite", str(e))
        return []

# 🔥 1️⃣ AlienVault OTX Integration 🔥
def fetch_otx_data(api_key):
    """Fetch data from AlienVault OTX."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("results", [])
            for pulse in data:
                for indicator in pulse.get("indicators", []):
                    cursor.execute("""
                    INSERT INTO threat_intelligence (source, entry_type, entry_value, time_stamp, additional_info)
                    VALUES (?, ?, ?, ?, ?)
                    """, (
                        "AlienVault OTX",
                        indicator["type"],
                        indicator["indicator"],
                        pulse["modified"],
                        pulse["name"]
                    ))
            conn.commit()
            print(f"Fetched and stored {len(data)} pulses from AlienVault OTX.")
        else:
            log_error("AlienVault OTX", f"Status Code {response.status_code}: {response.text}")
    except Exception as e:
        log_error("AlienVault OTX", str(e))

# 🔥 2️⃣ Abuse.ch Feeds Integration 🔥
def fetch_abuse_ch_data(endpoint):
    """Fetch data from Abuse.ch ThreatFox or URLhaus."""
    try:
        response = requests.get(endpoint)
        if response.status_code == 200:
            data = response.json().get("data", [])
            for entry in data:
                cursor.execute("""
                INSERT INTO threat_intelligence (source, entry_type, entry_value, time_stamp, additional_info)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    "Abuse.ch",
                    entry["ioc_type"],
                    entry["ioc_value"],
                    entry["first_seen"],
                    entry["malware"]
                ))
            conn.commit()
            print(f"Fetched and stored {len(data)} entries from Abuse.ch.")
        else:
            log_error("Abuse.ch", f"Status Code {response.status_code}: {response.text}")
    except Exception as e:
        log_error("Abuse.ch", str(e))

# 🔥 3️⃣ VirusTotal Integration 🔥
def fetch_virustotal_data(api_key):
    """Fetch file reports from VirusTotal for hashes in the database."""
    hashes = get_hashes_from_db()  # Fetch hashes from malware_db.sqlite
    for file_hash in hashes:
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                cursor.execute("""
                INSERT INTO threat_intelligence (source, entry_type, entry_value, time_stamp, additional_info)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    "VirusTotal",
                    "file_hash",
                    file_hash,
                    data.get("data", {}).get("attributes", {}).get("last_analysis_date"),
                    json.dumps(data.get("data", {}).get("attributes", {}))
                ))
                conn.commit()
                print(f"Stored data for hash: {file_hash}")
            else:
                log_error("VirusTotal", f"Status Code {response.status_code}: {response.text}")
        except Exception as e:
            log_error("VirusTotal", str(e))
        time.sleep(15)  # Rate limit handling

# 🔥 4️⃣ OpenPhish Integration 🔥
def fetch_openphish_data():
    """Fetch phishing URLs from OpenPhish."""
    try:
        response = requests.get(openphish_url)
        if response.status_code == 200:
            urls = response.text.splitlines()
            for url in urls:
                cursor.execute("""
                INSERT INTO threat_intelligence (source, entry_type, entry_value, time_stamp, additional_info)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    "OpenPhish",
                    "phishing_url",
                    url,
                    None,
                    None
                ))
            conn.commit()
            print(f"Fetched and stored {len(urls)} phishing URLs from OpenPhish.")
        else:
            log_error("OpenPhish", f"Status Code {response.status_code}: {response.text}")
    except Exception as e:
        log_error("OpenPhish", str(e))

# 🔥 5️⃣ Spamhaus DROP Integration 🔥
def fetch_spamhaus_drop():
    """Fetch malicious IPs from Spamhaus DROP list."""
    url = "https://www.spamhaus.org/drop/drop.txt"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            drop_list = response.text.splitlines()
            for ip in drop_list:
                cursor.execute("""
                INSERT INTO threat_intelligence (source, entry_type, entry_value, time_stamp, additional_info)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    "Spamhaus DROP",
                    "malicious_ip",
                    ip,
                    None,
                    None
                ))
            conn.commit()
            print(f"Fetched and stored {len(drop_list)} malicious IPs from Spamhaus DROP.")
        else:
            log_error("Spamhaus DROP", f"Status Code {response.status_code}: {response.text}")
    except Exception as e:
        log_error("Spamhaus DROP", str(e))

# 🔥 Master Workflow 🔥
def main():
    fetch_otx_data(alienvault_api_key)
    fetch_abuse_ch_data("https://threatfox.abuse.ch/api/v1/")
    fetch_abuse_ch_data("https://urlhaus.abuse.ch/api/")
    fetch_virustotal_data(virustotal_api_key)
    fetch_openphish_data()
    fetch_spamhaus_drop()

if __name__ == "__main__":
    main()