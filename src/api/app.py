"""FastAPI application wiring.

Routers are mounted under /api/v1; Prometheus metrics are exposed at /metrics so
the existing Grafana dashboards in dashboards/grafana can scrape this service
without extra configuration.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .metrics import get_metrics
from .routes import anomaly, health

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startup and shutdown. Replaces the on_event hooks deprecated in FastAPI 0.109."""
    logger.info("API starting up")
    yield
    logger.info("API shutting down")


app = FastAPI(
    title="Network Security Automation API",
    description=(
        "AI-driven network security platform: anomaly detection over network "
        "telemetry, with Cisco ISE and Symantec DLP integrations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS is wide open because the bundled dashboard is served from a different
# origin in development. Narrow this to your dashboard's origin before exposing
# the API outside a trusted network.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(anomaly.router, prefix="/api/v1", tags=["anomaly"])


@app.get("/metrics", include_in_schema=False)
async def metrics():
    """Prometheus scrape endpoint."""
    return get_metrics()
