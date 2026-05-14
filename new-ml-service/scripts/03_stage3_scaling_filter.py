from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, StandardScaler

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


def align_feature_schema(df: pd.DataFrame, resampling: str) -> pd.DataFrame:
    if set(FEATURES).issubset(df.columns):
        return df
    if df.shape[1] >= len(FEATURES):
        fixed = df.iloc[:, : len(FEATURES)].copy()
        fixed.columns = FEATURES
        return fixed
    missing = sorted(set(FEATURES) - set(df.columns))
    raise ValueError(f"Resampled file for {resampling} is missing required columns: {missing}")


def metric_row(resampling: str, scaling: str, y_true, y_pred) -> dict:
    return {
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
    norm_dir = base / "data" / "normalized"
    report_dir = base / "reports" / "stage_3"
    top2_path = base / "reports" / "stage_2" / "stage2_top2_resampling.csv"

    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    X_test = pd.read_csv(proc_dir / "X_test.csv")
    y_test = pd.read_csv(proc_dir / "y_test.csv").iloc[:, 0]

    top2_df = pd.read_csv(top2_path)
    if "best_two_resampling_methods" in top2_df.columns:
        top2_raw = str(top2_df.loc[0, "best_two_resampling_methods"])
        top2 = [x.strip() for x in top2_raw.split(",") if x.strip()]
    elif "top2_resampling" in top2_df.columns:
        top2_raw = str(top2_df.loc[0, "top2_resampling"])
        top2 = [x.strip() for x in top2_raw.split(",") if x.strip()]
    elif {"best_method_rank_1", "best_method_rank_2"}.issubset(set(top2_df.columns)):
        top2 = [str(top2_df.loc[0, "best_method_rank_1"]), str(top2_df.loc[0, "best_method_rank_2"])]
    else:
        top2 = [top2_df.loc[0, "top1"], top2_df.loc[0, "top2"]]

    rows = []
    scalers = ["none", "minmax", "standard"]

    for resampling in top2:
        X_train_res = pd.read_csv(imb_dir / f"X_{resampling}.csv")
        X_train_res = align_feature_schema(X_train_res, resampling)
        y_train_res = pd.read_csv(imb_dir / f"y_{resampling}.csv").iloc[:, 0]

        for scaling in scalers:
            pre = make_preprocessor(scaling)

            X_train_t = pre.fit_transform(X_train_res)
            X_test_t = pre.transform(X_test)

            train_cols = pre.get_feature_names_out()
            combo_dir = norm_dir / f"{resampling}_{scaling}"
            combo_dir.mkdir(parents=True, exist_ok=True)
            pd.DataFrame(X_train_t, columns=train_cols).to_csv(combo_dir / "X_train.csv", index=False)
            pd.DataFrame(X_test_t, columns=train_cols).to_csv(combo_dir / "X_test.csv", index=False)

            clf = RandomForestClassifier(n_estimators=220, random_state=42, class_weight="balanced")
            clf.fit(X_train_t, y_train_res)
            y_pred = clf.predict(X_test_t)

            rows.append(metric_row(resampling, scaling, y_test, y_pred))

    results = pd.DataFrame(rows).sort_values(["macro_f1", "macro_recall"], ascending=False)
    results.to_csv(report_dir / "stage3_scaling_results.csv", index=False)

    best = results.iloc[0]
    pd.DataFrame(
        [
            {
                "best_resampling": best["resampling"],
                "best_scaling": best["scaling"],
            }
        ]
    ).to_csv(report_dir / "stage3_best_combo.csv", index=False)

    print("Stage 3 complete")
    print(results)


if __name__ == "__main__":
    main()
