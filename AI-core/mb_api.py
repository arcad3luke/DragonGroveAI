import requests
import sqlite3

# API setup
api_url = "https://hunting.abuse.ch/api/"
auth_key = os.environ.get("ABUSE_CH_API_KEY")
headers = {"Auth-Key": auth_key}

payload = {"query": "get_hashes", "limit": 500}

response = requests.post(api_url, headers=headers, json=payload)
print("Status Code:", response.status_code)
print("Raw Response:", response.text)
if response.status_code == 200:
    data = response.json().get("hashes", [])
    
    # Save hashes into SQLite database
    conn = sqlite3.connect("malware_db.sqlite")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hash TEXT,
        type TEXT DEFAULT 'Malware',
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    for hash_entry in data:
        cursor.execute("INSERT INTO malware_samples (file_hash) VALUES (?)", (hash_entry,))
    conn.commit()
    conn.close()
    print(f"{len(data)} hashes added to the database!")
else:
    print(f"Error {response.status_code}: {response.text}")