# Dockerfile
#
# Multi-stage build: dependencies are installed from uv.lock with uv (no pip,
# no Node.js), then only the virtualenv and the app code go into the runtime image.

# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.11-slim AS builder

# Pinned uv binary from the official image (keep in step with the uv used to
# generate uv.lock).
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Install only the locked runtime dependencies. The project itself is not a
# package (tool.uv.package = false), so pyproject.toml and uv.lock are enough
# and this layer is cached until the lock changes.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.11-slim

# Non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Virtualenv from the builder (same base image, so the interpreter path matches)
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv

# Application code and runtime config (prompts and the agent card are read
# relative to /app)
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser config ./config

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production

USER appuser

EXPOSE 8000

# urlopen raises on any non-2xx response, so a 503 from /health marks the
# container unhealthy (the old check ignored the status code and imported
# `requests`, which is not a dependency).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
