# Multi-stage secure non-root Dockerfile for Cloud Copilot

FROM python:3.11-slim AS builder

WORKDIR /build

# Install security updates and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final minimal runtime image
FROM python:3.11-slim AS runner

WORKDIR /app

# Create unprivileged application user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy installed wheels from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application source code
COPY app/ ./app/
COPY ui/ ./ui/
COPY tests/architectures/ ./tests/architectures/
COPY CONTRACT.md ./

# Set environment paths and ownership
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN chown -R appuser:appuser /app /home/appuser

USER appuser

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# Default CMD runs the API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
