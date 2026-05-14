from __future__ import annotations

from pathlib import Path

import pandas as pd
from imblearn.combine import SMOTEENN
from imblearn.over_sampling import RandomOverSampler, SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

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


def metric_row(resampling: str, y_true, y_pred) -> dict:
    return {
        "resampling": resampling,
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "macro_precision": round(precision_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "macro_recall": round(recall_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "macro_f1": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
    }


def apply_resampling(name: str, X, y):
    if name == "none":
        return X.copy(), y.copy()
    sampler_map = {
        "oversampling": RandomOverSampler(random_state=42),
        "undersampling": RandomUnderSampler(random_state=42),
        "smote": SMOTE(random_state=42),
        "smoteenn": SMOTEENN(random_state=42),
    }
    return sampler_map[name].fit_resample(X, y)


def main() -> None:
    base = Path(__file__).resolve().parents[1]
    proc_dir = base / "data" / "processed"
    imb_dir = base / "data" / "imbalanced"
    report_dir = base / "reports" / "stage_2"

    imb_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    X_train = pd.read_csv(proc_dir / "X_train.csv")
    X_test = pd.read_csv(proc_dir / "X_test.csv")
    y_train = pd.read_csv(proc_dir / "y_train.csv").iloc[:, 0]
    y_test = pd.read_csv(proc_dir / "y_test.csv").iloc[:, 0]

    preprocessor = ColumnTransformer(
        [
            ("num", Pipeline([("imputer", SimpleImputer(strategy="median"))]), NUM_COLS),
            (
                "cat",
                Pipeline(
                    [
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                CAT_COLS,
            ),
        ]
    )

    methods = ["none", "oversampling", "undersampling", "smote", "smoteenn"]
    resampling_metrics_rows = []

    for method in methods:
        X_res, y_res = apply_resampling(method, X_train, y_train)

        pd.DataFrame(X_res, columns=FEATURES).to_csv(imb_dir / f"X_{method}.csv", index=False)
        pd.DataFrame({TARGET: y_res}).to_csv(imb_dir / f"y_{method}.csv", index=False)

        model = Pipeline(
            [
                ("preprocessor", preprocessor),
                ("model", RandomForestClassifier(n_estimators=220, random_state=42, class_weight="balanced")),
            ]
        )
        model.fit(X_res, y_res)
        y_pred = model.predict(X_test)
        resampling_metrics_rows.append(metric_row(method, y_test, y_pred))

    resampling_results_df = pd.DataFrame(resampling_metrics_rows).sort_values(["macro_f1", "macro_recall"], ascending=False)
    resampling_results_df.to_csv(report_dir / "stage2_resampling_results.csv", index=False)

    best_two_resampling_methods = resampling_results_df.head(2)["resampling"].tolist()
    pd.DataFrame([{"best_method_rank_1": best_two_resampling_methods[0], "best_method_rank_2": best_two_resampling_methods[1]}]).to_csv(
        report_dir / "stage2_top2_resampling.csv", index=False
    )

    print("Stage 2 (Resampling Filter) complete")
    print("Best two resampling methods:", best_two_resampling_methods)
    print("Resampling leaderboard:")
    print(resampling_results_df)


if __name__ == "__main__":
    main()
