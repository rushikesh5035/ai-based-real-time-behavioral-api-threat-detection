from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix


def main() -> None:
    base = Path(__file__).resolve().parents[1]
    model_path = base / "model" / "api_security_pipeline_v2.pkl"
    x_test_path = base / "data" / "processed" / "X_test.csv"
    y_test_path = base / "data" / "processed" / "y_test.csv"
    report_dir = base / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    model = joblib.load(model_path)
    X_test = pd.read_csv(x_test_path)
    y_test = pd.read_csv(y_test_path).iloc[:, 0]

    y_pred = model.predict(X_test)

    report = classification_report(y_test, y_pred, digits=4)
    cm = confusion_matrix(y_test, y_pred)

    out = ["Classification Report", report, "Confusion Matrix", str(cm)]
    (report_dir / "classification_report_v2.txt").write_text("\n\n".join(out), encoding="utf-8")

    print(report)
    print(cm)


if __name__ == "__main__":
    main()