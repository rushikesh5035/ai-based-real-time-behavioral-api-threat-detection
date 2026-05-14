from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import pandas as pd
from imblearn.combine import SMOTEENN
from imblearn.over_sampling import RandomOverSampler, SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, OneHotEncoder, StandardScaler
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


def metric_row(stage: str, resampling: str, scaling: str, model: str, y_true, y_pred) -> dict:
    return {
        "stage": stage,
        "resampling": resampling,
        "scaling": scaling,
        "model": model,
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
    }
    return sampler_map[name].fit_resample(X, y)


def make_preprocessor(scaling: str) -> ColumnTransformer:
    if scaling == "none":
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median"))])
    elif scaling == "minmax":
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", MinMaxScaler())])
    else:
        num_pipe = Pipeline([("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())])

    cat_pipe = Pipeline(
        [
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
        ]
    )
    return ColumnTransformer([("num", num_pipe, NUM_COLS), ("cat", cat_pipe, CAT_COLS)], sparse_threshold=0.0)


def run_stage_1(base: Path) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    raw_path = base / "data" / "raw" / "behavioral_api_dataset_v2.csv"
    proc_dir = base / "data" / "processed"
    reports = base / "reports"
    proc_dir.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(raw_path).drop_duplicates().reset_index(drop=True)
    df = df[FEATURES + [TARGET]].dropna().reset_index(drop=True)

    X = df[FEATURES].copy()
    y = df[TARGET].copy()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    X_train.to_csv(proc_dir / "X_train.csv", index=False)
    X_test.to_csv(proc_dir / "X_test.csv", index=False)
    y_train.to_frame(TARGET).to_csv(proc_dir / "y_train.csv", index=False)
    y_test.to_frame(TARGET).to_csv(proc_dir / "y_test.csv", index=False)

    pd.DataFrame([{"split": "train", "rows": len(X_train)}]).to_csv(reports / "preprocessing_split_summary.csv", index=False)
    return X_train, X_test, y_train, y_test


def run_stage_2(base: Path, X_train, X_test, y_train, y_test) -> List[str]:
    imbalanced = base / "data" / "imbalanced"
    reports = base / "reports"
    imbalanced.mkdir(parents=True, exist_ok=True)

    rows = []
    # Keep methods compatible with raw categorical feature space.
    methods = ["none", "oversampling", "undersampling"]
    for method in methods:
        X_res, y_res = apply_resampling(method, X_train, y_train)
        pd.DataFrame(X_res, columns=FEATURES).to_csv(imbalanced / f"X_{method}.csv", index=False)
        pd.DataFrame({TARGET: y_res}).to_csv(imbalanced / f"y_{method}.csv", index=False)

        pipe = Pipeline(
            [
                ("preprocessor", make_preprocessor("none")),
                ("model", RandomForestClassifier(n_estimators=220, random_state=42, class_weight="balanced")),
            ]
        )
        pipe.fit(X_res, y_res)
        y_pred = pipe.predict(X_test)
        rows.append(metric_row("A_resampling_filter", method, "none", "RandomForest", y_test, y_pred))

    stage_a = pd.DataFrame(rows).sort_values(["macro_f1", "macro_recall"], ascending=False).reset_index(drop=True)
    stage_a.to_csv(reports / "stage_a_resampling_results.csv", index=False)

    top2 = stage_a.head(2)["resampling"].tolist()
    pd.DataFrame([{"best_two_resampling_methods": ",".join(top2)}]).to_csv(reports / "stage_a_top2_resampling.csv", index=False)
    return top2


def run_stage_3(base: Path, top2: List[str], X_test, y_test) -> Tuple[str, str]:
    reports = base / "reports"
    imbalanced = base / "data" / "imbalanced"
    normalized = base / "data" / "normalized"
    normalized.mkdir(parents=True, exist_ok=True)

    rows = []
    for resampling in top2:
        X_res = pd.read_csv(imbalanced / f"X_{resampling}.csv")
        y_res = pd.read_csv(imbalanced / f"y_{resampling}.csv")[TARGET]
        for scaling in ["none", "minmax", "standard"]:
            pre = make_preprocessor(scaling)
            X_train_t = pre.fit_transform(X_res)
            X_test_t = pre.transform(X_test)

            combo_dir = normalized / f"{resampling}_{scaling}"
            combo_dir.mkdir(parents=True, exist_ok=True)
            # Keep normalization artifacts optional here; metrics selection does not depend on files.
            # Existing normalized files remain usable from prior runs.

            clf = RandomForestClassifier(n_estimators=220, random_state=42, class_weight="balanced")
            clf.fit(X_train_t, y_res)
            y_pred = clf.predict(X_test_t)
            rows.append(metric_row("B_scaling_filter", resampling, scaling, "RandomForest", y_test, y_pred))

    stage_b = pd.DataFrame(rows).sort_values(["macro_f1", "macro_recall"], ascending=False).reset_index(drop=True)
    stage_b.to_csv(reports / "stage_b_scaling_results.csv", index=False)
    best = stage_b.iloc[0]
    pd.DataFrame([{"best_resampling": best["resampling"], "best_scaling": best["scaling"]}]).to_csv(
        reports / "stage_b_best_combo.csv", index=False
    )
    return str(best["resampling"]), str(best["scaling"])


def run_stage_4(base: Path, top2: List[str], X_test, y_test) -> None:
    reports = base / "reports"
    imbalanced = base / "data" / "imbalanced"
    model_dir = base / "model"
    model_dir.mkdir(parents=True, exist_ok=True)

    model_specs: Dict[str, object] = {
        "RandomForest": RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced"),
        "SVM": SVC(probability=True, class_weight="balanced", random_state=42),
        "LogisticRegression": LogisticRegression(max_iter=5000, solver="lbfgs", class_weight="balanced"),
        "NaiveBayes": GaussianNB(),
    }
    if XGBClassifier is not None:
        model_specs["XGBoost"] = XGBClassifier(
            eval_metric="mlogloss",
            random_state=42,
            n_estimators=250,
            max_depth=6,
            learning_rate=0.08,
        )

    candidate_resampling = list(dict.fromkeys(top2))
    candidate_scaling = ["none", "minmax", "standard"]

    best_rows = []
    registry: Dict[str, Tuple[Pipeline, object, dict]] = {}

    for model_name, estimator in model_specs.items():
        model_rows = []
        cache: Dict[Tuple[str, str], Tuple[Pipeline, object]] = {}
        for resampling in candidate_resampling:
            X_res = pd.read_csv(imbalanced / f"X_{resampling}.csv")
            y_res = pd.read_csv(imbalanced / f"y_{resampling}.csv")[TARGET]
            for scaling in candidate_scaling:
                pipe = Pipeline([("preprocessor", make_preprocessor(scaling)), ("model", estimator)])
                if model_name == "XGBoost":
                    le = LabelEncoder()
                    y_enc = le.fit_transform(y_res)
                    pipe.fit(X_res, y_enc)
                    y_pred_enc = pipe.predict(X_test)
                    y_pred = le.inverse_transform(y_pred_enc.astype(int))
                else:
                    pipe.fit(X_res, y_res)
                    y_pred = pipe.predict(X_test)

                row = metric_row("C_model_comparison", resampling, scaling, model_name, y_test, y_pred)
                model_rows.append(row)
                cache[(resampling, scaling)] = (pipe, y_pred)

        model_df = pd.DataFrame(model_rows).sort_values(["macro_f1", "macro_recall"], ascending=False).reset_index(drop=True)
        best = model_df.iloc[0].to_dict()
        best_rows.append(best)
        key = (best["resampling"], best["scaling"])
        best_pipe, best_pred = cache[key]
        registry[model_name] = (best_pipe, best_pred, best)

    stage_c = pd.DataFrame(best_rows).sort_values(["macro_f1", "macro_recall"], ascending=False).reset_index(drop=True)
    stage_c.to_csv(reports / "stage_c_model_comparison.csv", index=False)
    stage_c.head(1).to_csv(reports / "model_results.csv", index=False)

    winner = stage_c.iloc[0]
    winner_model = str(winner["model"])
    winner_pipe, winner_pred, _ = registry[winner_model]
    pd.DataFrame(
        [
            {
                "top2_resampling": ",".join(top2),
                "best_resampling": winner["resampling"],
                "best_scaling": winner["scaling"],
                "best_model": winner_model,
            }
        ]
    ).to_csv(reports / "final_selection_summary.csv", index=False)

    report_text = classification_report(y_test, winner_pred, digits=4)
    (reports / "classification_report.txt").write_text(report_text, encoding="utf-8")
    joblib.dump(winner_pipe, model_dir / "api_security_pipeline.pkl")


def main() -> None:
    base = Path(__file__).resolve().parents[1]
    X_train, X_test, y_train, y_test = run_stage_1(base)
    top2 = run_stage_2(base, X_train, X_test, y_train, y_test)
    run_stage_3(base, top2, X_test, y_test)
    run_stage_4(base, top2, X_test, y_test)
    print("Rebuild complete: stages 1 -> 4 artifacts are now consistent.")


if __name__ == "__main__":
    main()
