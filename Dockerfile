# ──────────────────────────────────────────────────────────────────────────
# AI AppSec Service — Production Dockerfile
# Suitable for Azure App Service, Docker Compose, or any container platform
# ──────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (git for repo cloning, ruby for Noir)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl ruby && \
    rm -rf /var/lib/apt/lists/*

# Install OWASP Noir (Crystal binary via snap or prebuilt)
# Noir is also available as a Ruby gem alternative
RUN gem install noir --no-document || true

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install AI security scanning engines
RUN pip install --no-cache-dir garak agentic-radar || true

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m -r appuser && chown -R appuser:appuser /app
USER appuser

# Expose port (Azure App Service expects 8000 by default, configurable via WEBSITES_PORT)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ || exit 1

# Start with Gunicorn + Uvicorn workers for production
# Azure App Service sets PORT env var; default to 8000
CMD ["gunicorn", "main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "2", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
