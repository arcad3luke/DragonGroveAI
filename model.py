import os

import requests
import sqlite3
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
from collections import Counter

# Load and preprocess data
data = pd.read_csv("malware_dataset.csv")
encoder = LabelEncoder()
data["file_hash_encoded"] = encoder.fit_transform(data["file_hash"])
data["malware_type_encoded"] = encoder.fit_transform(data["malware_type"].fillna("Unknown"))
data["malware_type"] = data["malware_type"].fillna("Unknown")

# Add artificial benign samples for balancing
synthetic_data = pd.DataFrame({
    "file_size": [1500, 2000],
    "file_hash_encoded": [999, 1000],
    "malware_type_encoded": [0, 0],
    "classification": ["Benign", "Benign"]
})
data = pd.concat([data, synthetic_data], ignore_index=True)

# Define features and labels
X = data[["file_size", "file_hash_encoded", "malware_type_encoded"]]
y = data["classification"]

# Display class distribution
print(Counter(y))

# Apply SMOTE for further balancing
smote = SMOTE(k_neighbors=1, random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Define parameter grid for hyperparameter tuning
param_grid = {
    "n_estimators": [100, 300, 500],
    "max_depth": [10, 20, None],
    "min_samples_split": [2, 5, 10]
}

# Perform Grid Search for hyperparameter tuning
grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42),
    param_grid,
    cv=2,  # Reduced to 2 folds for small datasets
    scoring="accuracy"
)
grid_search.fit(X_resampled, y_resampled)
print("Best Parameters:", grid_search.best_params_)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.3, random_state=42, stratify=y_resampled
)

# Train Random Forest with best hyperparameters
rf_model = RandomForestClassifier(**grid_search.best_params_, random_state=42)
rf_model.fit(X_train, y_train)

# Predict and evaluate
y_pred = rf_model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Fetch API Data: Example for false positives or IOCs
def fetch_false_positives():
    headers = {
        "Auth-Key": os.getenv("ABUSE_CH_API_KEY"),
        "User-Agent": "DragonGroveAI/1.0"
    }
    payload = {
        "query": "get_fplist",
        "format": "json"
    }
    response = requests.post("https://hunting-api.abuse.ch/api/v1/", headers=headers, json=payload)
    if response.status_code == 200:
        try:
            hunting_data = response.json()
            false_positives = hunting_data.values()  # Extract dictionary values
            print(f"Fetched {len(false_positives)} false positives!")

            # Process and store in the database
            conn = sqlite3.connect("malware_db.sqlite")
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time_stamp TEXT,
                platform TEXT,
                entry_type TEXT,
                entry_value TEXT,
                removed_by TEXT,
                removal_notes TEXT,
                timestamp_added DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """)
            for fp in false_positives:
                cursor.execute(
                    "INSERT INTO false_positives (time_stamp, platform, entry_type, entry_value, removed_by, removal_notes) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        fp["time_stamp"],
                        fp["platform"],
                        fp["entry_type"],
                        fp["entry_value"],
                        fp["removed_by"],
                        fp.get("removal_notes", "N/A")
                    )
                )
            conn.commit()
            conn.close()
            print("False positives stored in database.")
        except requests.exceptions.JSONDecodeError:
            print("Invalid JSON response from API.")
            print("Raw Response:", response.text)
    else:
        print(f"Error {response.status_code}: {response.text}")
# Example call for API fetching function
fetch_false_positives()