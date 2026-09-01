import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import json
import os

# Load dataset
dataset_path = 'balanced_urls.csv'  
# OR
dataset_path = 'dataset_phishing.csv'
dataset_path = 'Dataset.csv'
dataset_path = 'legitimate_urls.csv'
dataset_path = 'phishing_clean.csv'
dataset_path = 'phishing_urls.csv'
dataset_path = 'urlhaus_cleaned1.csv'

if not os.path.exists(dataset_path):
    print(f"Error: {dataset_path} not found!")
    print("Download from: https://www.kaggle.com/datasets/sriharshithabattula/phishing-url-dataset/data")
    print("OR: https://zenodo.org/records/19371661 (balanced_urls.csv)")
    exit(1)

print(f"Loading dataset: {dataset_path}...")
df = pd.read_csv(dataset_path)

print(f"Dataset shape: {df.shape}")
print(f"Columns: {list(df.columns)}")

# Find the target column (usually named 'Result', 'label', 'class', 'phishing')
target_col = None
possible_targets = ['Result', 'label', 'class', 'phishing', 'target', 'Label']

for col in possible_targets:
    if col in df.columns:
        target_col = col
        break

if target_col is None:
    # Try to find any binary column
    for col in df.columns:
        if df[col].nunique() == 2:
            target_col = col
            print(f"Auto-detected target column: {target_col}")
            break

if target_col is None:
    print("Error: Could not find target column!")
    print("Please rename your target column to 'Result' or 'label'")
    exit(1)

print(f"Using target column: {target_col}")

# Separate features and target
X = df.drop(target_col, axis=1)
y = df[target_col]

# Convert labels to binary if needed (e.g., -1/1 to 0/1)
if y.unique().tolist() == [-1, 1]:
    y = y.map({-1: 0, 1: 1})
    print("Converted labels from -1/1 to 0/1")

print(f"Class distribution:\n{y.value_counts()}")

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")

# Train Random Forest
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("\n" + "="*60)
print("Classification Report:")
print("="*60)
print(classification_report(y_test, y_pred))
print(f"ROC-AUC Score: {roc_auc_score(y_test, y_proba):.4f}")
print("="*60)

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("\n✅ Model saved: phishing_model.pkl")

# Save feature names
feature_config = {
    'feature_names': list(X.columns),
    'model_type': 'RandomForest',
    'target_column': target_col,
    'dataset': dataset_path
}
with open('feature_config.json', 'w') as f:
    json.dump(feature_config, f, indent=2)

print("✅ Config saved: feature_config.json")
print("\n🎉 Training complete!")
print(f"Model accuracy: {sum(y_pred == y_test) / len(y_test) * 100:.2f}%")