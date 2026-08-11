# Network Security Automation AI

Anomaly detection and autonomous policy remediation for enterprise NAC and DLP platforms, built around Cisco ISE and Symantec DLP integrations.

[![Python](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **How to read the numbers in this README.** All integrations run against simulators, and every figure below is measured on synthetic traffic produced by `scripts/data_generation/`. They describe how the system behaves on that dataset, not results from a production deployment. The generator is in the repository, so the runs are reproducible.

## What it does

Network access control and data loss prevention platforms generate far more alerts than a security team can triage. Most are noise, and the ones that matter arrive late.

This project pairs unsupervised anomaly detection with a policy engine that acts on high-confidence findings without waiting for a human, while escalating anything ambiguous.

On the synthetic dataset the detection model reaches 92.3% precision and 89.7% recall, F1 91.0%, with a 5.3% false-positive rate and 87ms p95 inference latency.

## Architecture

A React dashboard sits on a FastAPI service. Behind it, three components share PostgreSQL and Redis: an Isolation Forest detection engine, an autonomous remediation engine, and API clients for Cisco ISE and Symantec DLP. Prometheus scrapes the service and Grafana renders the dashboards. Terraform provisions the Azure environment and Ansible handles configuration.

## Detection approach

The model is an Isolation Forest, chosen because labelled attack data is rarely available in this domain. It learns normal behaviour and isolates deviations across nine engineered features: byte and packet ratios in both directions, hour of day, day of week, port entropy, connection duration, protocol distribution, geographic deviation, and delta from historical baseline.

Confidence drives the response:

| Confidence | Severity | Action | Automated |
| --- | --- | --- | --- |
| 95% and above | Critical | Quarantine device, page SOC | Yes |
| 85% and above | High | VLAN isolation, notify team | Yes |
| 70% and above | Medium | Raise alert, recommend action | No |
| Below 70% | Low | Log and monitor | No |

## Automation scripts

Six scripts in `automation-showcase/` exercise the platform end to end:

| Script | Purpose |
| --- | --- |
| `01_deploy_ise_policy.py` | Concurrent policy deployment across sites using asyncio, with post-deployment validation |
| `02_detect_config_drift.py` | Compares live configuration against a Git baseline, auto-remediates medium severity, escalates high |
| `03_automated_health_check.py` | Health checks for ISE and DLP, certificate expiry, session thresholds, agent connectivity |
| `04_incident_auto_response.py` | Event-driven response following the confidence table above |
| `05_policy_lifecycle.py` | Policy CRUD with semantic versioning and an audit trail |
| `06_bulk_endpoint_management.py` | Batched concurrent operations across large endpoint counts |

## Quick start

```bash
git clone https://github.com/MarckMorris/Network-security-automation-ai.git
cd Network-security-automation-ai

docker compose up -d
docker compose ps
```

This starts the API on port 8000, Grafana on 3000, Prometheus on 9090, PostgreSQL on 5432, Redis on 6379, and the ISE and DLP simulators.

For the dashboard:

```bash
cd frontend-dashboard
npm install
npm run dev
```

Interactive API documentation is at `http://localhost:8000/docs`.

## Tech stack

**Detection** scikit-learn, NumPy, Pandas. **Backend** Python 3.13, FastAPI, asyncio, Pydantic, SQLAlchemy, PostgreSQL, Redis. **Integrations** Cisco ISE REST API, Symantec DLP API, 802.1X and MAB. **Infrastructure** Docker, Kubernetes manifests, Terraform for Azure, Ansible. **Observability** Prometheus, Grafana, structured logging. **Frontend** React 18, Vite, Tailwind.

## Testing

```bash
pytest
pytest --cov=src --cov-report=html
```

## License

MIT, see [LICENSE](LICENSE).

## Author

**Marcos Morris**, Cloud Infrastructure Engineer, Bentonville, AR

[LinkedIn](https://www.linkedin.com/in/marck-morris/) · [Portfolio](https://marckmorris.github.io/) · marck.morris.pro@gmail.com
