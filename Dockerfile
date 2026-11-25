FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.11.6 /uv /uvx /bin/

WORKDIR /app

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}"

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-install-project

COPY manage.py ./
COPY src ./src
COPY scripts/install_scanners.py ./scripts/install_scanners.py
COPY config/ciclosec.yaml.example ./config/ciclosec.yaml.example

RUN apt-get update \
    && apt-get install --yes --no-install-recommends docker-cli \
    && rm -rf /var/lib/apt/lists/* \
    && uv sync --locked \
    && uv run --no-sync python scripts/install_scanners.py \
    && groupadd --system ciclosec \
    && useradd --system --gid ciclosec --create-home --home-dir /home/ciclosec ciclosec \
    && usermod -aG 0 ciclosec

ENV HOME=/home/ciclosec
USER ciclosec
