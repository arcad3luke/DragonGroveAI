import os
import time
import hashlib
import json
import datetime
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import RandomForestClassifier  # Example ML integration
import pickle  # For loading pre-trained models

# -----------------------------------------------------
# Logging Utility
# -----------------------------------------------------
def log_action(action_type, details, log_file="system_logs.log"):
    """
    Logs an action with a timestamp to the specified log file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {action_type}: {details}\n")

# -----------------------------------------------------
# File Hashing and Hash Log Management
# -----------------------------------------------------
def generate_file_hash(file_path):
    """
    Generates a SHA-256 hash for the given file using chunked reading.
    Handles inaccessible or ephemeral files gracefully.
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        log_action("Error", f"Skipping file {file_path}: {str(e)}")
        return None

def initialize_hash_log(log_file="hashes.json"):
    """
    Ensure the hash log exists and contains valid JSON.
    """
    if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
        with open(log_file, "w") as f:
            f.write("{}")  # Initialize as an empty dictionary
        log_action("Info", f"Initialized hash log: {log_file}")

def load_hash_log(log_file="hashes.json"):
    """
    Loads the file hash log into a dictionary.
    """
    initialize_hash_log(log_file)  # Ensure the log exists and is valid
    try:
        with open(log_file, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log_action("Error", f"Failed to decode JSON from {log_file}: {str(e)}")
        return {}

def save_hash_log(hash_data, log_file="hashes.json"):
    """
    Saves the file hash log dictionary to the log file.
    """
    try:
        with open(log_file, "w") as f:
            json.dump(hash_data, f, indent=4)
    except Exception as e:
        log_action("Error", f"Failed to save hash log: {str(e)}")

# -----------------------------------------------------
# Timestamp Utility
# -----------------------------------------------------
def save_last_run_timestamp(filename="last_run.txt"):
    """
    Save the current timestamp to track when the script was last run.
    """
    with open(filename, "w") as file:
        file.write(str(time.time()))

def load_last_run_timestamp(filename="last_run.txt"):
    """
    Load the timestamp from the last run of the script.
    """
    try:
        with open(filename, "r") as file:
            return float(file.read().strip())
    except FileNotFoundError:
        return 0  # Default to 0 if no timestamp file exists

# -----------------------------------------------------
# Sonar Integration Function
# -----------------------------------------------------
def sonar_scan(file_path):
    """
    Integrates Sonar scanning logic for flagged files.
    Performs analysis, classification, or additional processing.
    """
    log_action("Sonar", f"Scanning file: {file_path}")

    try:
        # Generate file hash for identification
        file_hash = generate_file_hash(file_path)
        if file_hash:
            print(f"Sonar Scan: {file_path} [Hash: {file_hash}]")

        # ML classification (if model is loaded)
        ml_model = load_ml_model()
        if ml_model:
            classification = classify_file(file_path, ml_model)
            print(f"Sonar Classification: {file_path} classified as {classification}")

        # Example: Add file entropy analysis (optional)
        entropy = calculate_entropy(file_path)
        print(f"Entropy of {file_path}: {entropy}")

    except Exception as e:
        log_action("Error", f"Sonar scan failed for {file_path}: {e}")

# -----------------------------------------------------
# System-Wide Deep Sweep
# -----------------------------------------------------

def deep_sweep(
    root="/",
    hash_log_file="hashes.json",
    last_run_file="last_run.txt",
    sonar_scan_function=sonar_scan,  # Sonar integration
    ml_model=None
):

    if ml_model is None:
        log_action("Warning", "ML model is not loaded. Proceeding without classification.")

    """
    Performs a deep sweep of the filesystem:
    - Detects changes or additions based on hash comparisons and timestamps.
    - Skips known token files and inaccessible directories.
    - Classifies suspicious files using an ML model.
    """
    excluded_dirs = ["/proc", "/sys", "/dev", "/run", "/tmp", "/home/arcadeluke/.cache", "/home/arcadeluke/.steam"]
    excluded_files = [
        ".token", "steam.token", "auth.token", "registry.vdf",  # Steam registry file
        "access.token", "refresh.token", "id.token"
    ]
    suspicious_files = []

    # Load previous hashes and timestamps
    existing_hashes = load_hash_log(hash_log_file)
    last_run_timestamp = load_last_run_timestamp(last_run_file)
    updated_hashes = {}

    print(f"Starting filesystem analysis from: {root}")
    for dirpath, dirs, files in os.walk(root, topdown=True, followlinks=False):
        # Exclude directories
        dirs[:] = [d for d in dirs if os.path.join(dirpath, d) not in excluded_dirs]

        for file in files:
            file_path = os.path.join(dirpath, file)

            # Exclude token files
            if any(file.endswith(pattern) for pattern in excluded_files):
                log_action("Info", f"Skipping token file: {file_path}")
                continue

            # Generate file hash and detect changes
            current_hash = generate_file_hash(file_path)
            if current_hash is None:
                continue  # Skip inaccessible files

            updated_hashes[file_path] = current_hash

            file_mtime = os.path.getmtime(file_path)
            if (
                file_mtime > last_run_timestamp or  # New or modified based on timestamp
                current_hash != existing_hashes.get(file_path)  # Modified based on hash
            ):
                print(f"File changed or new: {file_path}")
                log_action("Update", f"File updated or new: {file_path}")

                # Invoke Sonar scan
                sonar_scan_function(file_path)

                # Run ML classification if available
                if ml_model:
                    classification = classify_file(file_path, ml_model)
                    if classification == "Malicious":
                        suspicious_files.append(file_path)
                        log_action("Alert", f"Malicious file detected: {file_path}")
            else:
                log_action("Info", f"File unchanged: {file_path}")

    # Save updated hashes and last run timestamp
    save_hash_log(updated_hashes, hash_log_file)
    save_last_run_timestamp(last_run_file)
    print("Filesystem analysis complete. Hash log updated.")

    # Return results for further processing
    return {"suspicious_files": suspicious_files}
    if sonar_scan_function and not callable(sonar_scan_function):
          raise TypeError(f"Expected a callable for sonar_scan_function, got {type(sonar_scan_function)}")

# -----------------------------------------------------
# Machine Learning Integration
# -----------------------------------------------------
def load_ml_model(model_path="ml_model.pkl"):
    """
    Loads a pre-trained machine learning model for malware detection.
    """
    try:
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        log_action("Info", "ML model loaded successfully.")
        return model
    except FileNotFoundError:
        log_action("Error", "ML model file not found.")
        return None

def classify_file(file_path, model):
    """
    Classifies a file as malicious or benign using the ML model.
    """
    try:
        features = extract_features(file_path)  # Extract features for classification
        prediction = model.predict([features])  # Predict using the loaded model
        classification = "Malicious" if prediction[0] == 1 else "Benign"
        log_action("ML", f"File {file_path} classified as {classification}")
        return classification
    except Exception as e:
        log_action("Error", f"Classification failed for {file_path}: {str(e)}")
        return "Error"

def extract_features(file_path):
    """
    Extracts features from a file for ML classification, such as size and entropy.
    """
    try:
        file_size = os.path.getsize(file_path)
        entropy = calculate_entropy(file_path)
        return [file_size, entropy]  # Example features
    except Exception as e:
        log_action("Error", f"Feature extraction failed for {file_path}: {str(e)}")
        return [0, 0]  # Fallback values

def calculate_entropy(file_path):
    """
    Calculates the entropy of a file (a measure of randomness in its contents).
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        from collections import Counter
        counter = Counter(data)
        length = len(data)
        entropy = -sum((count / length) * (count / length).bit_length() for count in counter.values())
        return entropy
    except Exception as e:
        log_action("Error", f"Entropy calculation failed for {file_path}: {str(e)}")
        return 0

# -----------------------------------------------------
# Main Orchestration
# -----------------------------------------------------
def main():
    print("Starting system-wide analysis...")
    ml_model = load_ml_model()
    results = deep_sweep(
        root="/",
        hash_log_file="hashes.json",
        last_run_file="last_run.txt",
        sonar_scan_function=sonar_scan,
        ml_model=ml_model
    )
    print(f"Suspicious files detected: {results['suspicious_files']}")

if __name__ == "__main__":
    main()
