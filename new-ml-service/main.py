from __future__ import annotations

from pathlib import Path
import logging

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


MODEL_PATH = Path(__file__).parent / "model" / "api_security_pipeline_v2.pkl"
if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)
MODEL_VERSION = "v2"
MODEL_FEATURES = [
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ml_service")

app = FastAPI(title="API Behavioral Threat Detection Service v2")


class RequestFeatures(BaseModel):
    inter_api_access_duration_sec: float
    api_access_uniqueness: float
    sequence_length_count: int
    vsession_duration_min: float
    ip_type: str
    num_sessions: int
    num_users: int
    num_unique_apis: int
    source: str
    failed_auth_count: int
    token_reuse_ratio: float
    status_4xx_ratio: float
    status_5xx_ratio: float


def map_action(label: str) -> str:
    if label == "normal":
        return "ALLOW"
    if label == "token_abuse":
        return "ALERT"
    return "BLOCK"


def decide_action(label: str, confidence: float | None) -> tuple[str, int | None, str]:
    # Confidence-aware policy for 4 actions:
    # ALLOW, ALERT, RATE_LIMIT, BLOCK
    if confidence is None:
        return map_action(label), None, "fallback_no_confidence"

    if label == "normal":
        if confidence >= 0.80:
            return "ALLOW", None, "normal_high_confidence"
        return "RATE_LIMIT", 60, "normal_low_confidence"

    if label == "token_abuse":
        if confidence >= 0.85:
            return "ALERT", None, "token_abuse_high_confidence"
        return "RATE_LIMIT", 120, "token_abuse_borderline"

    if label == "flood":
        if confidence >= 0.90:
            return "BLOCK", None, "flood_high_confidence"
        return "RATE_LIMIT", 180, "flood_borderline"

    if label == "bruteforce":
        if confidence >= 0.90:
            return "BLOCK", None, "bruteforce_high_confidence"
        return "RATE_LIMIT", 300, "bruteforce_borderline"

    return "BLOCK", None, "unknown_label_failsafe"


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "model": MODEL_VERSION,
        "model_file": MODEL_PATH.name,
        "feature_count": len(MODEL_FEATURES),
    }


@app.post("/predict")
async def predict(data: RequestFeatures) -> dict:
    try:
        df = pd.DataFrame(
            [
                {
                    "inter_api_access_duration(sec)": data.inter_api_access_duration_sec,
                    "api_access_uniqueness": data.api_access_uniqueness,
                    "sequence_length(count)": data.sequence_length_count,
                    "vsession_duration(min)": data.vsession_duration_min,
                    "ip_type": data.ip_type,
                    "num_sessions": data.num_sessions,
                    "num_users": data.num_users,
                    "num_unique_apis": data.num_unique_apis,
                    "source": data.source,
                    "failed_auth_count": data.failed_auth_count,
                    "token_reuse_ratio": data.token_reuse_ratio,
                    "status_4xx_ratio": data.status_4xx_ratio,
                    "status_5xx_ratio": data.status_5xx_ratio,
                }
            ]
        )

        label = str(model.predict(df)[0])
        confidence = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(df)[0]
            confidence = float(proba.max())

        action, rate_limit_seconds, policy_reason = decide_action(label, confidence)
        logger.info(
            "predict_result prediction=%s decision=%s confidence=%s policy_reason=%s",
            label,
            action,
            f"{confidence:.4f}" if confidence is not None else "None",
            policy_reason,
        )

        return {
            "prediction": label,
            "decision": action,
            "confidence": confidence,
            "rate_limit_seconds": rate_limit_seconds,
            "policy_reason": policy_reason,
        }
    except Exception as exc:
        logger.exception("prediction_failed error=%s", exc)
        raise HTTPException(status_code=500, detail="prediction_failed")
