"""Anomaly detection endpoints.

The route layer owns no detection logic of its own. It converts the request into
a DataFrame, hands it to the shared inference engine, and converts the result
back. When no trained model is loaded the endpoint returns 503 rather than a
placeholder number, because a security API that invents findings is worse than
one that is honestly unavailable.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from src.ml.inference.engine import InferenceEngine

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_EVENTS_PER_REQUEST = 10_000


@lru_cache(maxsize=1)
def get_engine() -> InferenceEngine:
    """One inference engine per process. Loading a model costs ~100 ms, so it is
    cached rather than rebuilt per request."""
    return InferenceEngine()


class AnomalyDetectionRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ..., description="Network events, each with the fields the model was trained on"
    )
    threshold: Optional[float] = Field(
        None,
        description="Override the model's anomaly-score cutoff. Lower is stricter.",
    )


class AnomalyResult(BaseModel):
    index: int
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    severity: Optional[str] = None


class AnomalyDetectionResponse(BaseModel):
    anomalies_detected: int
    total_events: int
    anomaly_rate: float
    model_version: str
    results: List[AnomalyResult]


class ModelStatus(BaseModel):
    anomaly_detector_loaded: bool
    lstm_predictor_loaded: bool
    model_version: Optional[str] = None
    trained_at: Optional[str] = None
    features: List[str] = []


@router.post("/anomaly/detect", response_model=AnomalyDetectionResponse)
async def detect_anomalies(request: AnomalyDetectionRequest) -> AnomalyDetectionResponse:
    """Score a batch of network events with the trained Isolation Forest."""
    if not request.events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No events supplied",
        )

    if len(request.events) > MAX_EVENTS_PER_REQUEST:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch limit is {MAX_EVENTS_PER_REQUEST} events per request",
        )

    engine = get_engine()
    detector = engine.anomaly_detector
    if detector is None or not getattr(detector, "is_trained", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No trained anomaly model is loaded. Train one with "
                "scripts/data_generation/generate_synthetic_data.py and "
                "src.ml.training.trainer, then restart the API."
            ),
        )

    frame = pd.DataFrame(request.events)

    try:
        scored = detector.detect_anomalies(frame, threshold=request.threshold)
    except (KeyError, ValueError) as exc:
        # A missing feature column is the caller's problem, not a server fault.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Events do not match the model's expected features: {exc}",
        ) from exc

    results = [
        AnomalyResult(
            index=int(position),
            is_anomaly=bool(row["is_anomaly"]),
            anomaly_score=float(row["anomaly_score"]),
            confidence=float(row["confidence"]),
            severity=None if pd.isna(row.get("severity")) else str(row.get("severity")),
        )
        for position, (_, row) in enumerate(scored.iterrows())
    ]

    detected = sum(1 for r in results if r.is_anomaly)

    return AnomalyDetectionResponse(
        anomalies_detected=detected,
        total_events=len(results),
        anomaly_rate=detected / len(results),
        model_version=getattr(detector, "version", "unknown"),
        results=results,
    )


@router.get("/anomaly/model", response_model=ModelStatus)
async def model_status() -> ModelStatus:
    """Report what is actually loaded, so a deployment can be verified."""
    engine = get_engine()
    detector = engine.anomaly_detector
    trained_at = getattr(detector, "training_date", None) if detector else None

    return ModelStatus(
        anomaly_detector_loaded=bool(detector and getattr(detector, "is_trained", False)),
        lstm_predictor_loaded=engine.lstm_predictor is not None,
        model_version=getattr(detector, "version", None) if detector else None,
        trained_at=trained_at.isoformat() if hasattr(trained_at, "isoformat") else trained_at,
        features=list(getattr(detector, "feature_names", []) or []) if detector else [],
    )


@router.get("/anomaly/recent")
async def get_recent_anomalies(hours: int = 24, limit: int = 100) -> Dict[str, Any]:
    """Recent detections.

    Returns an empty set until the event repository is wired to a live database;
    the shape is stable so callers can integrate against it now.
    """
    if hours < 1 or hours > 720:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="hours must be between 1 and 720",
        )

    return {
        "anomalies": [],
        "count": 0,
        "time_range_hours": hours,
        "limit": limit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "not_connected",
    }
