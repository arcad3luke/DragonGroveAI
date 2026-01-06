## 🦠 Malware Storage & Analysis
DragonGroveAI **stores malware samples in**:
**`/mnt/disk2/malware_samples`**
This directory is **locked down with strict permissions (`chmod 700`)**, preventing accidental execution.

### 🔍 How SentinelAI Analyzes Malware:
- **YARA Rules** – Matches common malware signatures.
- **SHA256 Hashing** – Cross-checks files against known threats.
- **Entropy Analysis** – Flags obfuscated or packed executables.
- **VirusTotal Lookups** – Fetches threat intelligence on suspicious hashes.

### 🚫 Security Measures:
✅ **No execution occurs—DragonGroveAI only scans malware statically.**  
✅ **Read-only access is enforced (`chattr +i`) to prevent modifications.**  
✅ **Network isolation prevents malware samples from calling home.**  
## 🚀 Installation & Setup
To install DragonGroveAI:
```bash
git clone https://github.com/DragonGroveAI/DragonGroveAI.git
cd DragonGroveAI
pip install -r requirements.txt
```

### To run the tool
```bash
cd DragonGroveAI
python3 DragonGrove.py
