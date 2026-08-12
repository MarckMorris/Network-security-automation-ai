# Network Security Automation

**Anomaly detection over network telemetry, wired to Cisco ISE and Symantec DLP, with a remediation engine that knows when not to act on its own.**

[![CI](https://github.com/MarckMorris/Network-security-automation-ai/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/MarckMorris/Network-security-automation-ai/actions/workflows/ci-cd.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A network access control platform that scores traffic for anomalies, decides what
to do about a confirmed incident, and executes that decision against real NAC and
DLP appliances — or against the bundled simulators, so the whole stack runs on a
laptop without a vendor licence.

## Honesty about what this is

This is a personal project, not a deployed production system. It has never run
against a live enterprise network. Everything below is either measured by a
script in this repository or labelled as unverified.

- **The ML pipeline is real and measured.** Numbers come from `scripts/benchmark.py`, on synthetic data, with the limitations stated below.
- **The ISE and DLP clients are real REST clients** written against the published APIs, tested against a mocked HTTP layer. They have not been run against licensed appliances.
- **The simulators are real Flask services** that implement the subset of each vendor API this platform calls, so `docker compose up` gives you a working end-to-end system.
- **The database layer is defined but not connected.** `/api/v1/anomaly/recent` returns `"source": "not_connected"` rather than an empty list that could be mistaken for "all clear".

## Measured performance

Reproduce with `python scripts/benchmark.py`. Both datasets are seeded, so you should get the same figures.

| Metric | Value |
| --- | --- |
| Precision | 0.986 |
| Recall | 0.947 |
| F1 | 0.966 |
| Training | 0.38 s on 20,000 events |
| Inference | 275 ms for 20,000 events (~72,000 events/sec) |

**What these numbers do not mean.** They are measured against synthetic telemetry
from `scripts/data_generation/generate_synthetic_data.py`, which creates anomalies by
pushing traffic volume well outside the normal band. That is a much easier problem
than real network traffic, which has seasonality, legitimate bursts, and label
noise. Treat this as a regression check on the pipeline, not a forecast of
production accuracy. Training and scoring are on disjoint seeds, so the model is
never evaluated on data it has seen.

## Architecture

```
                    ┌──────────────────┐
   telemetry ──────▶│  Isolation Forest │──── anomaly score + confidence
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ RemediationEngine │──── decides actions + autonomy
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Cisco ISE      Symantec DLP    alert a human
      (quarantine)   (quarantine file)   (always allowed)
```

| Path | What is there |
| --- | --- |
| `src/ml/` | Isolation Forest detector, optional LSTM capacity predictor, training and inference |
| `src/automation/remediation/` | Decision logic and execution, with an audit trail |
| `src/integrations/` | Cisco ISE and Symantec DLP REST clients |
| `src/simulators/` | Flask stand-ins for both appliances |
| `src/api/` | FastAPI service, Prometheus metrics |
| `src/database/` | SQLAlchemy models and repositories (defined, not wired) |
| `terraform/` | Azure AKS, database and networking |
| `kubernetes/` | Deployment, service, configmap |
| `ansible/` | Local and production playbooks |
| `dashboards/` | Prometheus alert rules and a Grafana dashboard |
| `frontend-dashboard/` | React + Vite operator dashboard |

## The part worth reading

The remediation engine is where the interesting decisions live, and where a bug
costs the most. It separates **what to do** from **whether it may do it alone**:

- Acting autonomously requires **high confidence AND high severity**. Either one on its own is not enough — 99% confidence on a low-severity event still waits for a human.
- **Blocking an IP is held to a higher bar than quarantining an endpoint** (0.85 vs 0.80), because an IP can be a shared NAT gateway and the blast radius is larger.
- **Terminating a session is ordered before blocking the IP**, because an established session survives an IP block.
- **Alerting a human is always allowed**, at any confidence.
- **An endpoint ISE cannot find is never reported as quarantined.** That is the most dangerous false positive in the system, and it has a test named after it.

All of this is pinned in `tests/unit/test_remediation_engine.py`.

## Quick start

```bash
git clone https://github.com/MarckMorris/Network-security-automation-ai.git
cd Network-security-automation-ai

python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest                        # 71 tests
python scripts/benchmark.py   # reproduce the numbers above
```

The whole stack, including both appliance simulators:

```bash
cp .env.example .env
docker compose up
```

| Service | URL |
| --- | --- |
| API docs | http://localhost:8000/docs |
| Prometheus metrics | http://localhost:8000/metrics |
| ISE simulator | http://localhost:9060/health |
| DLP simulator | http://localhost:8443/health |

## API

```bash
# What model is actually loaded?
curl http://localhost:8000/api/v1/anomaly/model

# Score a batch of events
curl -X POST http://localhost:8000/api/v1/anomaly/detect \
  -H "Content-Type: application/json" \
  -d '{"events": [{"bytes_sent": 2500, "bytes_received": 2500,
                   "packets_sent": 30, "packets_received": 30,
                   "timestamp": "2026-01-01T00:00:00"}]}'
```

`/anomaly/detect` returns **503 when no trained model is loaded**, rather than a
placeholder count. A security API that invents findings is worse than one that is
honestly unavailable. `/anomaly/model` exists so a deployment can be verified
before anyone trusts its output.

## Testing

```bash
pytest                                    # everything
pytest -m unit                            # unit only
pytest --cov=src --cov-report=term-missing
```

71 tests. Coverage is concentrated where correctness matters rather than spread
evenly: anomaly route 98%, remediation engine 89%, detector 78%, ISE client 66%,
DLP client 54%. The vendor clients are tested at the HTTP boundary with
`responses`, which catches the failures that actually occur in the field — wrong
URL, missing auth header, and an unreachable appliance being reported as success.

CI runs the suite on Python 3.10, 3.11 and 3.12, builds the Docker image and the
React dashboard, and scans the filesystem with Trivy. The test job has no
`continue-on-error`: a pipeline that stays green while its tests fail converts a
real signal into a decoration.

## Known limitations

- No production deployment, no real-network validation.
- The database layer is modelled but not connected, so detections are not persisted.
- The LSTM capacity predictor needs TensorFlow, which is an optional dependency; without it the module loads but forecasting is unavailable.
- CORS is wide open for local development. Narrow it before exposing the API.
- `QUARANTINE_GROUP_ID` in the ISE client is a placeholder that must be set per environment.
- Most of the codebase predates the formatter, so `black` and `isort` run as advisory in CI rather than as gates.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Marcos Morris** — Cloud Infrastructure Engineer, Bentonville, AR

[LinkedIn](https://www.linkedin.com/in/marck-morris/) · [Portfolio](https://marckmorris.github.io/) · marck.morris.pro@gmail.com
