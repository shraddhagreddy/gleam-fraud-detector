import pandas as pd
import pickle
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# Load dataset
df = pd.read_csv("data/fraud_training_data.csv")

# Features (X) and Label (y)
X = df[["actions_per_minute", "domain_type", "ip_asn", "duplicate_email"]]
y = df["fraud"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n", classification_report(y_test, y_pred))

# Save trained model
with open("models/fraud_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("🎉 Model trained and saved at models/fraud_model.pkl")
