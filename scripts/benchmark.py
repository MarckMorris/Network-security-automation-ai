#!/usr/bin/env python3
"""Reproducible benchmark for the anomaly detector.

Every performance number quoted in the README is produced by this script. Run it
yourself and you should get the same figures, because both datasets are seeded.

    python scripts/benchmark.py

IMPORTANT: this measures the model against SYNTHETIC data produced by
scripts/data_generation/generate_synthetic_data.py. That generator creates
anomalies by scaling traffic volume well outside the normal band, which is a far
easier problem than real network telemetry. Treat these numbers as a regression
check on the pipeline, not as a prediction of production accuracy. Real traffic
has seasonality, legitimate bursts, and label noise that this generator does not
reproduce.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.metrics import precision_score, recall_score, f1_score  # noqa: E402

from scripts.data_generation.generate_synthetic_data import (  # noqa: E402
    SyntheticDataGenerator,
)
from src.ml.models.anomaly_detector import NetworkAnomalyDetector  # noqa: E402

TRAIN_SEED = 42
TEST_SEED = 7
LABEL = "is_anomaly"


def run(events: int, anomaly_rate: float, contamination: float) -> dict:
    train = SyntheticDataGenerator(seed=TRAIN_SEED).generate_network_events(
        events, anomaly_rate=anomaly_rate
    )
    # A separate seed, so the model is scored on data it has never seen.
    test = SyntheticDataGenerator(seed=TEST_SEED).generate_network_events(
        events, anomaly_rate=anomaly_rate
    )

    detector = NetworkAnomalyDetector(contamination=contamination, random_state=42)

    started = time.perf_counter()
    detector.train(train.drop(columns=[LABEL]))
    train_seconds = time.perf_counter() - started

    started = time.perf_counter()
    scored = detector.detect_anomalies(test.drop(columns=[LABEL]))
    inference_seconds = time.perf_counter() - started

    y_true = test[LABEL].astype(int)
    y_pred = scored["is_anomaly"].astype(int)

    return {
        "events_per_split": events,
        "true_anomaly_rate": anomaly_rate,
        "contamination": contamination,
        "train_seconds": round(train_seconds, 3),
        "inference_seconds": round(inference_seconds, 3),
        "events_per_second": round(events / inference_seconds),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "true_anomalies": int(y_true.sum()),
        "flagged": int(y_pred.sum()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=20_000)
    parser.add_argument("--anomaly-rate", type=float, default=0.05)
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="What the model is told to expect. Matching the true rate is the best case.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    result = run(args.events, args.anomaly_rate, args.contamination)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print()
    print("  Isolation Forest on synthetic network telemetry")
    print(f"  train / test   {result['events_per_split']:,} events each, disjoint seeds")
    print(f"  true anomalies {result['true_anomalies']:,}   flagged {result['flagged']:,}")
    print()
    print(f"  precision      {result['precision']:.3f}")
    print(f"  recall         {result['recall']:.3f}")
    print(f"  f1             {result['f1']:.3f}")
    print()
    print(f"  train          {result['train_seconds']:.2f} s")
    print(f"  inference      {result['inference_seconds'] * 1000:.0f} ms "
          f"({result['events_per_second']:,} events/sec)")
    print()
    print("  Synthetic data. See the module docstring before quoting these numbers.")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
