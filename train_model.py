import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification

# Generate sample training data
X, y = make_classification(n_samples=1000, n_features=10, random_state=42)

# Train the model
model = RandomForestClassifier()
model.fit(X, y)

# Save it as `ml_model.pkl`
with open("ml_model.pkl", "wb") as file:
    pickle.dump(model, file)

print("✔ ML Model successfully trained and saved!")
