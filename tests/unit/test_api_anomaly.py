"""API contract for the anomaly endpoints.

The point of these tests is that the endpoint reports what the model actually
found. The previous implementation returned a hardcoded count regardless of
input, which is exactly the kind of thing that survives code review and then
misleads an operator at 3am.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from src.api.routes import anomaly as anomaly_routes
from src.ml.models.anomaly_detector import NetworkAnomalyDetector


@pytest.fixture
def client():
    return TestClient(app)


def training_frame(rows: int = 300) -> pd.DataFrame:
    rng = np.random.default_rng(42)
    return pd.DataFrame(
        {
            "bytes_sent": rng.integers(1_000, 5_000, rows),
            "bytes_received": rng.integers(1_000, 5_000, rows),
            "packets_sent": rng.integers(10, 60, rows),
            "packets_received": rng.integers(10, 60, rows),
            "timestamp": pd.date_range("2026-01-01", periods=rows, freq="min"),
        }
    )


def event(**overrides) -> dict:
    base = {
        "bytes_sent": 2_500,
        "bytes_received": 2_500,
        "packets_sent": 30,
        "packets_received": 30,
        "timestamp": "2026-01-01T00:00:00",
    }
    base.update(overrides)
    return base


class LoadedEngine:
    """An inference engine with a genuinely trained detector."""

    def __init__(self):
        self.anomaly_detector = NetworkAnomalyDetector(contamination=0.1)
        self.anomaly_detector.train(training_frame())
        self.lstm_predictor = None


class EmptyEngine:
    anomaly_detector = None
    lstm_predictor = None


@pytest.fixture
def with_model(monkeypatch):
    engine = LoadedEngine()
    monkeypatch.setattr(anomaly_routes, "get_engine", lambda: engine)
    return engine


@pytest.fixture
def without_model(monkeypatch):
    monkeypatch.setattr(anomaly_routes, "get_engine", lambda: EmptyEngine())


class TestDetectEndpoint:
    def test_counts_match_the_returned_results(self, client, with_model):
        """anomalies_detected must be derived from results, never asserted."""
        payload = {"events": [event() for _ in range(20)]}
        body = client.post("/api/v1/anomaly/detect", json=payload).json()

        assert body["total_events"] == 20
        assert body["anomalies_detected"] == sum(r["is_anomaly"] for r in body["results"])
        assert body["anomaly_rate"] == pytest.approx(
            body["anomalies_detected"] / body["total_events"]
        )

    def test_result_count_tracks_the_input_size(self, client, with_model):
        for size in (1, 5, 37):
            body = client.post(
                "/api/v1/anomaly/detect", json={"events": [event() for _ in range(size)]}
            ).json()
            assert body["total_events"] == size
            assert len(body["results"]) == size

    def test_an_extreme_event_scores_worse_than_a_typical_one(self, client, with_model):
        """The model has to actually run for this to hold."""
        payload = {
            "events": [
                event(),
                event(bytes_sent=90_000_000, packets_sent=500_000),
            ]
        }
        results = client.post("/api/v1/anomaly/detect", json=payload).json()["results"]
        assert results[1]["anomaly_score"] < results[0]["anomaly_score"]

    def test_every_result_carries_a_score_and_a_confidence(self, client, with_model):
        results = client.post(
            "/api/v1/anomaly/detect", json={"events": [event() for _ in range(5)]}
        ).json()["results"]
        for r in results:
            assert isinstance(r["anomaly_score"], float)
            assert 0.0 <= r["confidence"] <= 100.0

    def test_the_response_names_the_model_version(self, client, with_model):
        body = client.post("/api/v1/anomaly/detect", json={"events": [event()]}).json()
        assert body["model_version"] == with_model.anomaly_detector.version


class TestFailureModes:
    def test_no_model_returns_503_not_a_made_up_number(self, client, without_model):
        response = client.post("/api/v1/anomaly/detect", json={"events": [event()]})
        assert response.status_code == 503
        assert "No trained anomaly model" in response.json()["detail"]

    def test_an_empty_batch_is_rejected(self, client, with_model):
        assert client.post("/api/v1/anomaly/detect", json={"events": []}).status_code == 422

    def test_an_oversized_batch_is_rejected_before_inference(self, client, with_model):
        payload = {"events": [event()] * (anomaly_routes.MAX_EVENTS_PER_REQUEST + 1)}
        assert client.post("/api/v1/anomaly/detect", json=payload).status_code == 413

    def test_events_missing_model_features_return_422_not_500(self, client, with_model):
        response = client.post(
            "/api/v1/anomaly/detect", json={"events": [{"nothing": "useful"}]}
        )
        assert response.status_code == 422

    def test_a_malformed_body_is_rejected_by_validation(self, client, with_model):
        assert client.post("/api/v1/anomaly/detect", json={"nope": 1}).status_code == 422


class TestModelStatus:
    def test_reports_a_loaded_model(self, client, with_model):
        body = client.get("/api/v1/anomaly/model").json()
        assert body["anomaly_detector_loaded"] is True
        assert body["features"]
        assert body["trained_at"]

    def test_reports_an_unloaded_model(self, client, without_model):
        body = client.get("/api/v1/anomaly/model").json()
        assert body["anomaly_detector_loaded"] is False
        assert body["features"] == []


class TestRecentAnomalies:
    def test_declares_that_no_datastore_is_connected(self, client):
        """Better an explicit 'not_connected' than an empty list that reads as 'all clear'."""
        body = client.get("/api/v1/anomaly/recent").json()
        assert body["source"] == "not_connected"
        assert body["count"] == 0

    def test_echoes_the_requested_window(self, client):
        assert client.get("/api/v1/anomaly/recent?hours=6").json()["time_range_hours"] == 6

    @pytest.mark.parametrize("hours", [0, -1, 10_000])
    def test_rejects_an_impossible_window(self, client, hours):
        assert client.get(f"/api/v1/anomaly/recent?hours={hours}").status_code == 422


class TestServiceEndpoints:
    def test_health_is_reachable(self, client):
        assert client.get("/api/v1/health").status_code == 200

    def test_metrics_are_exposed_in_prometheus_format(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

    def test_openapi_schema_documents_both_anomaly_routes(self, client):
        paths = client.get("/openapi.json").json()["paths"]
        assert "/api/v1/anomaly/detect" in paths
        assert "/api/v1/anomaly/model" in paths
