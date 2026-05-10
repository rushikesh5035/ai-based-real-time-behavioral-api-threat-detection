from pathlib import Path

import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException

from pydantic import BaseModel


# Load Pipeline
MODEL_PATH = (
    Path(__file__).parent
    / "model"
    / "api_security_pipeline.pkl"
)

if not MODEL_PATH.exists():

    raise FileNotFoundError(
        f"Model not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

app = FastAPI(
    title="AI Security Prediction Service"
)


# Request Schema

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


# -----------------------------
# Risk Refinement Logic
# -----------------------------

def calculate_risk(data: RequestFeatures):

    risk_score = 0


    # Fast repeated requests
    if data.inter_api_access_duration_sec <= 0.5:
        risk_score += 2


    # Long attack sequence
    if data.sequence_length_count >= 100:
        risk_score += 2


    # Many sessions/users
    if (
        data.num_sessions >= 10
        or data.num_users >= 10
    ):
        risk_score += 2


    # Datacenter IP
    if data.ip_type == "datacenter":
        risk_score += 1


    # Very low API uniqueness
    if data.num_unique_apis <= 2:
        risk_score += 1


    return risk_score


# -----------------------------
# Decision Logic
# -----------------------------

def decide_policy(
    prediction: str,
    risk_score: int
):

    # ML says attack
    if prediction == "outlier":

        if risk_score >= 5:
            return "BLOCK"

        return "ALERT"


    # ML says normal
    else:

        if risk_score >= 5:
            return "ALERT"

        return "ALLOW"


# -----------------------------
# Health Check
# -----------------------------

@app.get("/health")

def health():

    return {

        "status": "healthy"
    }


# -----------------------------
# Prediction Endpoint
# -----------------------------

@app.post("/predict")

async def predict(data: RequestFeatures):

    try:

        # Convert request -> dataframe
        df = pd.DataFrame([{

            "inter_api_access_duration(sec)":
                data.inter_api_access_duration_sec,

            "api_access_uniqueness":
                data.api_access_uniqueness,

            "sequence_length(count)":
                data.sequence_length_count,

            "vsession_duration(min)":
                data.vsession_duration_min,

            "ip_type":
                data.ip_type,

            "num_sessions":
                data.num_sessions,

            "num_users":
                data.num_users,

            "num_unique_apis":
                data.num_unique_apis,

            "source":
                data.source
        }])


        # -----------------------------
        # ML Prediction
        # -----------------------------

        prediction = model.predict(df)[0]

        label = (
            "outlier"
            if int(prediction) == 1
            else "normal"
        )


        # -----------------------------
        # Probability
        # -----------------------------

        probability = None

        try:

            probability = max(
                model.predict_proba(df)[0]
            )

        except Exception:

            probability = None


        # -----------------------------
        # Risk Refinement
        # -----------------------------

        risk_score = calculate_risk(data)


        # -----------------------------
        # Final Decision
        # -----------------------------

        decision = decide_policy(
            label,
            risk_score
        )


        return {

            "prediction":
                label,

            "decision":
                decision,

            "risk_score":
                risk_score,

            "confidence":
                probability
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc)
        )