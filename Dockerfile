# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY requirements.txt .
RUN uv venv && \
    uv pip install --no-cache -r requirements.txt

COPY refresh_externalsecrets.py .

FROM python:3.13-slim

ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG COMMIT_HASH="00000000-dirty"
ARG PROJECT_URL="https://github.com/babs/externalsecrets-refresh"
ARG VERSION="v0.0.0"

ENV BUILD_TIMESTAMP=${BUILD_TIMESTAMP}
ENV COMMIT_HASH=${COMMIT_HASH}
ENV PROJECT_URL=${PROJECT_URL}
ENV VERSION=${VERSION}

LABEL org.opencontainers.image.source=${PROJECT_URL}
LABEL org.opencontainers.image.created=${BUILD_TIMESTAMP}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT_HASH}

WORKDIR /app

COPY --from=builder /app/ /app/

CMD ["/app/.venv/bin/python", "/app/refresh_externalsecrets.py"]
