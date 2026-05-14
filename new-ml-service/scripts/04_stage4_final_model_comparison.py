from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, StandardScaler
from sklearn.svm import SVC

try:
    from xgboost import XGBClassifier
except Exception:
    XGBClassifier = None

FEATURES = [
    "inter_api_access_duration(sec)",
    "api_access_uniqueness",
    "sequence_length(count)",
    "vsession_duration(min)",
    "ip_type",
    "num_sessions",
    "num_users",
    "num_unique_apis",
    "source",
    "failed_auth_count",
    "token_reuse_ratio",
    "status_4xx_ratio",
    "status_5xx_ratio",
]
TARGET = "attack_class"
CAT_COLS = ["ip_type", "source"]
NUM_COLS = [c for c in FEATURES if c not in CAT_COLS]


def metric_row(model_name: str, resampling: str, scaling: str, y_true, y_pred) -> dict:
    return {
        "model": model_name,
        "resampling": resampling,
        "scaling": scaling,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "macro_precision": round(precision_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "macro_recall": round(recall_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "macro_f1": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
    }


def make_preprocessor(scaling: str) -> ColumnTransformer:
    if scaling == "minmax":
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", MinMaxScaler())])
    elif scaling == "standard":
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())])
    else:
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median"))])

    cat_pipe = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]
    )

    return ColumnTransformer([("num", num_pipe, NUM_COLS), ("cat", cat_pipe, CAT_COLS)])


def main() -> None:
    base = Path(__file__).resolve().parents[1]
    proc_dir = base / "data" / "processed"
    imb_dir = base / "data" / "imbalanced"
    report_dir = base / "reports" / "stage_4"
    model_dir = base / "model"

    best_combo_path = base / "reports" / "stage_3" / "stage3_best_combo.csv"

    report_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    combo = pd.read_csv(best_combo_path).iloc[0]
    best_resampling = combo["best_resampling"]
    best_scaling = combo["best_scaling"]

    X_train = pd.read_csv(imb_dir / f"X_{best_resampling}.csv")
    y_train = pd.read_csv(imb_dir / f"y_{best_resampling}.csv").iloc[:, 0]
    X_test = pd.read_csv(proc_dir / "X_test.csv")
    y_test = pd.read_csv(proc_dir / "y_test.csv").iloc[:, 0]

    models = {
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced"),
        "SVM": SVC(probability=True, class_weight="balanced", random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=1500, class_weight="balanced"),
        "NaiveBayes": GaussianNB(),
    }
    if XGBClassifier is not None:
        models["XGBoost"] = XGBClassifier(
            eval_metric="mlogloss",
            random_state=42,
            n_estimators=250,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
        )

    rows = []
    trained = {}
    for name, estimator in models.items():
        pipe = Pipeline(
            [
                ("preprocessor", make_preprocessor(best_scaling)),
                ("model", estimator),
            ]
        )
        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)
        rows.append(metric_row(name, best_resampling, best_scaling, y_test, y_pred))
        trained[name] = (pipe, y_pred)

    results = pd.DataFrame(rows).sort_values(["macro_f1", "macro_recall"], ascending=False)
    results.to_csv(report_dir / "stage4_model_comparison.csv", index=False)

    best_model_name = results.iloc[0]["model"]
    best_pipeline, best_pred = trained[best_model_name]

    report_text = classification_report(y_test, best_pred, digits=4)
    cm = confusion_matrix(y_test, best_pred)

    (report_dir / "classification_report.txt").write_text(report_text, encoding="utf-8")
    (report_dir / "confusion_matrix.txt").write_text(str(cm), encoding="utf-8")

    pd.DataFrame(
        [
            {
                "best_model": best_model_name,
                "best_resampling": best_resampling,
                "best_scaling": best_scaling,
            }
        ]
    ).to_csv(report_dir / "final_selection_summary.csv", index=False)

    joblib.dump(best_pipeline, model_dir / "api_security_pipeline_v2.pkl")

    print("Stage 4 complete")
    print(results)
    print("Best:", best_model_name)


if __name__ == "__main__":
    main()
