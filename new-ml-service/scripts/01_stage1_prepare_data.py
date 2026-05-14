from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

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


def main() -> None:
    base = Path(__file__).resolve().parents[1]
    raw_path = base / "data" / "raw" / "behavioral_api_dataset_v2.csv"
    proc_dir = base / "data" / "processed"
    report_dir = base / "reports" / "stage_1"

    proc_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(raw_path)

    # Basic cleaning
    df = df.drop_duplicates().reset_index(drop=True)
    needed = FEATURES + [TARGET]
    df = df[needed].dropna().reset_index(drop=True)

    X = df[FEATURES].copy()
    y = df[TARGET].copy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    X_train.to_csv(proc_dir / "X_train.csv", index=False)
    X_test.to_csv(proc_dir / "X_test.csv", index=False)
    y_train.to_frame(name=TARGET).to_csv(proc_dir / "y_train.csv", index=False)
    y_test.to_frame(name=TARGET).to_csv(proc_dir / "y_test.csv", index=False)

    summary = pd.DataFrame(
        [
            {
                "rows_after_cleaning": len(df),
                "train_rows": len(X_train),
                "test_rows": len(X_test),
                "num_features": len(FEATURES),
            }
        ]
    )
    summary.to_csv(report_dir / "split_summary.csv", index=False)
    y_train.value_counts().rename_axis("class").reset_index(name="count").to_csv(
        report_dir / "train_class_distribution.csv", index=False
    )

    print("Stage 1 complete")
    print(summary.to_dict(orient="records")[0])


if __name__ == "__main__":
    main()
