# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.12.18 AS uv

FROM python:3.12-alpine3.23 AS builder

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project --no-editable

FROM python:3.12-alpine3.23 AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    ENTROPY_PATH=/ \
    TZ=Europe/Warsaw \
    GUNICORN_CMD_ARGS="--workers=2 --threads=4 --worker-class=gthread --timeout=30 --graceful-timeout=30 --access-logfile=- --error-logfile=- --capture-output"

RUN addgroup -S -g 10001 oracle \
    && adduser -S -D -H -u 10001 -G oracle oracle

WORKDIR /app

COPY --from=builder --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 server /app/server

USER 10001:10001

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '5000') + os.getenv('ENTROPY_PATH', '/'), timeout=2)"]

CMD ["sh", "-c", "exec gunicorn --bind 0.0.0.0:${PORT:-5000} server.server:app"]
