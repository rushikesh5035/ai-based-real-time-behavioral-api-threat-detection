import joblib
import pandas as pd
import requests
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

MODEL_PATH = "./model/api_security_pipeline.pkl"
API_URL = "http://127.0.0.1:8000/predict"

# Load pipeline and test data
model = joblib.load(MODEL_PATH)
X_test = pd.read_csv("./data/processed/X_test.csv")
y_test = pd.read_csv("./data/processed/y_test.csv").values.ravel()

# Offline evaluation (model vs ground truth)
y_pred = model.predict(X_test)
print("=== Offline evaluation (model vs y_test) ===")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

# Helper: convert a DataFrame row -> API payload (matches main.py RequestFeatures)
def row_to_payload(row):
    return {
        "inter_api_access_duration_sec": float(row["inter_api_access_duration(sec)"]),
        "api_access_uniqueness": float(row["api_access_uniqueness"]),
        "sequence_length_count": int(row["sequence_length(count)"]),
        "vsession_duration_min": float(row["vsession_duration(min)"]),
        "ip_type": str(row["ip_type"]),
        "num_sessions": int(row["num_sessions"]),
        "num_users": int(row["num_users"]),
        "num_unique_apis": int(row["num_unique_apis"]),
        "source": str(row["source"]),
    }

# API consistency check: sample first N rows and compare API -> model
N = 50
mismatches = []
api_preds = []
model_preds = y_pred[:N].astype(int)
for i, (_, row) in enumerate(X_test.head(N).iterrows()):
    payload = row_to_payload(row)
    try:
        resp = requests.post(API_URL, json=payload, timeout=5)
        resp.raise_for_status()
        api_label = 1 if resp.json().get("prediction") == "outlier" else 0
    except Exception as e:
        print("API call failed for row", i, ":", e)
        api_label = None
    api_preds.append(api_label)
    if api_label is not None and api_label != int(model_preds[i]):
        mismatches.append((i, int(model_preds[i]), api_label))

print(f"\nSampled {N} rows -> API vs offline model mismatches: {len(mismatches)}")
if mismatches:
    print("First 10 mismatches (index, model, api):", mismatches[:10])
else:
    print("API predictions match the offline pipeline for sampled rows.")
