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

app = FastAPI(title="API Behavioral Threat Detection — ML Inference Service v2")


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
    """
    Pure ML inference endpoint.
    Accepts behavioral features, returns ONLY the model prediction and confidence.
    Decision logic (ALLOW/BLOCK/RATE_LIMIT/ALERT) is handled by the backend layer.
    """
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

        logger.info(
            "prediction  class=%s  confidence=%s",
            label,
            f"{confidence:.4f}" if confidence is not None else "None",
        )

        # Return ONLY prediction + confidence. No decision, no policy.
        return {
            "prediction": label,
            "confidence": confidence,
        }
    except Exception as exc:
        logger.exception("prediction_failed error=%s", exc)
        raise HTTPException(status_code=500, detail="prediction_failed")
