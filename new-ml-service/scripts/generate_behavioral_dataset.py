from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


FEATURE_COLUMNS = [
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

CLASSES = ["normal", "bruteforce", "flood", "token_abuse"]


def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def sample_row(label: str, rng: np.random.Generator) -> dict:
    # Overlapping ranges by design to avoid trivial leakage.
    base = {
        "inter_api_access_duration(sec)": _clip(rng.normal(1.7, 0.8), 0.03, 8.0),
        "api_access_uniqueness": _clip(rng.normal(0.45, 0.2), 0.02, 1.0),
        "sequence_length(count)": int(_clip(rng.normal(55, 25), 3, 280)),
        "vsession_duration(min)": _clip(rng.normal(18, 10), 1, 120),
        "ip_type": "default" if rng.random() < 0.72 else "datacenter",
        "num_sessions": int(_clip(rng.normal(4.5, 2.8), 1, 40)),
        "num_users": int(_clip(rng.normal(6.0, 3.0), 1, 35)),
        "num_unique_apis": int(_clip(rng.normal(12, 7), 1, 70)),
        "source": "E" if rng.random() < 0.74 else "F",
        "failed_auth_count": int(_clip(rng.normal(1.2, 1.6), 0, 30)),
        "token_reuse_ratio": _clip(rng.normal(0.30, 0.20), 0.0, 1.0),
        "status_4xx_ratio": _clip(rng.normal(0.12, 0.10), 0.0, 1.0),
        "status_5xx_ratio": _clip(rng.normal(0.03, 0.04), 0.0, 1.0),
    }

    if label == "normal":
        base["inter_api_access_duration(sec)"] = _clip(rng.normal(2.4, 0.9), 0.1, 9.0)
        base["sequence_length(count)"] = int(_clip(rng.normal(38, 16), 3, 180))
        base["failed_auth_count"] = int(_clip(rng.normal(0.4, 0.9), 0, 6))
        base["token_reuse_ratio"] = _clip(rng.normal(0.22, 0.14), 0.0, 0.8)
        base["status_4xx_ratio"] = _clip(rng.normal(0.07, 0.06), 0.0, 0.45)
    elif label == "bruteforce":
        base["inter_api_access_duration(sec)"] = _clip(rng.normal(0.35, 0.22), 0.01, 2.0)
        base["sequence_length(count)"] = int(_clip(rng.normal(90, 35), 10, 340))
        base["failed_auth_count"] = int(_clip(rng.normal(11, 5), 2, 40))
        base["status_4xx_ratio"] = _clip(rng.normal(0.42, 0.14), 0.08, 1.0)
        base["token_reuse_ratio"] = _clip(rng.normal(0.52, 0.20), 0.05, 1.0)
    elif label == "flood":
        base["inter_api_access_duration(sec)"] = _clip(rng.normal(0.08, 0.06), 0.005, 0.8)
        base["sequence_length(count)"] = int(_clip(rng.normal(175, 55), 35, 520))
        base["api_access_uniqueness"] = _clip(rng.normal(0.18, 0.12), 0.01, 0.7)
        base["status_5xx_ratio"] = _clip(rng.normal(0.12, 0.11), 0.0, 1.0)
    elif label == "token_abuse":
        base["inter_api_access_duration(sec)"] = _clip(rng.normal(0.95, 0.55), 0.02, 5.0)
        base["token_reuse_ratio"] = _clip(rng.normal(0.84, 0.10), 0.25, 1.0)
        base["num_sessions"] = int(_clip(rng.normal(10, 5), 1, 50))
        base["num_users"] = int(_clip(rng.normal(3.2, 2.1), 1, 20))
        base["status_4xx_ratio"] = _clip(rng.normal(0.27, 0.12), 0.03, 0.95)

    base["attack_class"] = label
    base["is_malicious"] = 0 if label == "normal" else 1
    return base


def generate_dataset(rows: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    probs = np.array([0.52, 0.18, 0.16, 0.14])
    labels = rng.choice(CLASSES, size=rows, p=probs)
    data = [sample_row(lbl, rng) for lbl in labels]
    df = pd.DataFrame(data)
    return df


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=6000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    base = Path(__file__).resolve().parents[1]
    raw_dir = base / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    df = generate_dataset(rows=args.rows, seed=args.seed)
    out_path = raw_dir / "behavioral_api_dataset_v2.csv"
    df.to_csv(out_path, index=False)

    print(f"saved: {out_path}")
    print("shape:", df.shape)
    print("class counts:\n", df["attack_class"].value_counts())


if __name__ == "__main__":
    main()