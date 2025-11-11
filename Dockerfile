# Use Python 3.13 slim image for smaller size
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install uv (fast Python package manager)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency metadata first for better caching
# uv.lock is copied if it exists (for reproducible builds)
COPY pyproject.toml uv.lock* ./

# Install Python dependencies using uv (runtime only)
RUN uv pip install --system --no-cache .

# Copy application code
COPY . .

# Create directory for data files
RUN mkdir -p /app/data

# Expose port
EXPOSE 8080

# Set environment variables
ENV PORT=8080
ENV UVICORN_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/app-info')" || exit 1

# Run the application
CMD ["python", "main.py"]

