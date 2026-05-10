from pathlib import Path

import joblib
import pandas as pd
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "api_security_pipeline.pkl"

categorical_cols = ["ip_type", "source"]
numerical_cols = [
    "inter_api_access_duration(sec)",
    "api_access_uniqueness",
    "sequence_length(count)",
    "vsession_duration(min)",
    "num_sessions",
    "num_users",
    "num_unique_apis",
]

X_train_raw = pd.read_csv(DATA_DIR / "processed" / "X_train.csv")
y_train_raw = pd.read_csv(DATA_DIR / "processed" / "y_train.csv").values.ravel()

preprocessor = ColumnTransformer(
    [
        (
            "num",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="median")),
                    ("scaler", StandardScaler()),
                ]
            ),
            numerical_cols,
        ),
        (
            "cat",
            Pipeline(
                [
                    ("imputer", SimpleImputer(strategy="most_frequent")),
                    ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
                ]
            ),
            categorical_cols,
        ),
    ]
)

deployment_pipeline = ImbPipeline(
    [
        ("preprocessor", preprocessor),
        ("model", RandomForestClassifier(n_estimators=100, random_state=42)),
    ]
)

print(f"Training data shape: {X_train_raw.shape}")
print(f"Training labels shape: {y_train_raw.shape}")
print("Training deployment pipeline...")
deployment_pipeline.fit(X_train_raw, y_train_raw)

MODEL_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump(deployment_pipeline, MODEL_PATH)
print(f"Saved pipeline to {MODEL_PATH}")

# Validate the saved artifact immediately.
reloaded_pipeline = joblib.load(MODEL_PATH)
print("Reloaded pipeline successfully")
print(reloaded_pipeline.predict(X_train_raw.head(1)))
