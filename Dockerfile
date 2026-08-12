# Python 3.12 rather than 3.13: this project pins numpy <2.0 for pandas and
# scikit-learn compatibility, and numpy 1.26 ships no cp313 wheels, so 3.13
# forces a source build that fails in a slim image. 3.12 is also the top of the
# version matrix the test suite runs against.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Build toolchain is needed for any dependency without a manylinux wheel.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies first, so a source change does not invalidate the layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY scripts/ ./scripts/

# Models and training data are mounted at runtime, not baked into the image.
# The directory is created here so the volume mount has somewhere to land.
RUN mkdir -p /app/data/models /app/logs

# Run unprivileged. A container that quarantines network endpoints has no
# business running as root.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://localhost:8000/api/v1/health || exit 1

CMD ["python", "-m", "src.main"]
