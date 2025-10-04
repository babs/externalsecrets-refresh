# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy requirements and install dependencies using uv
COPY requirements.txt .
RUN uv venv && \
    uv pip install --no-cache -r requirements.txt

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Copy only the virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy the main script
COPY refresh_externalsecrets.py .

# Run the script using the venv
ENTRYPOINT ["/app/.venv/bin/python", "/app/refresh_externalsecrets.py"]
