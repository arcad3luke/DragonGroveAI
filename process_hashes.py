import json
import sqlite3

# Load hashes from JSON file
with open("hashes.json", "r") as file:
    data = json.load(file)

# Connect to the database
conn = sqlite3.connect("malware_db.sqlite")
cursor = conn.cursor()

# Create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hash TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

# Insert hashes into the database
for hash_entry in data.get("hashes", []):  # Adjust based on JSON structure
    cursor.execute("INSERT INTO hashes (hash) VALUES (?)", (hash_entry,))
conn.commit()
conn.close()

print("Hashes saved to database!")