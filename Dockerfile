FROM python:3.12-slim

# Security patch: pull the fixed Debian release of zlib1g (trivy HIGH findings
# CVE-2026-76844 / CVE-2026-85091 ship in the base tag's zlib1g). The base tag
# itself is not yet rebuilt with the security update, so upgrade it here
# instead of weakening the CI gate.
# NOTE: revisit once python:3.12-slim ships > 1.3.dfsg+really1.3.1-1+deb13u1.
RUN apt-get update \
    && apt-get install -y --no-install-recommends zlib1g \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir uv \
    && useradd --system --create-home --uid 10001 --shell /usr/sbin/nologin itsm \
    && mkdir -p /app && chown itsm:itsm /app

WORKDIR /app
USER root

# Project metadata first, so dependency resolution is cached separately from
# source changes. README.md is required because pyproject.toml declares it as
# the project readme (hatchling reads it during the build).
COPY pyproject.toml uv.lock README.md ./

# Install only third-party dependencies (no project build yet).
RUN uv sync --frozen --no-dev --no-install-project

# Application source + migrations (needed to build/install the project itself).
COPY src ./src
COPY migrations ./migrations

# Install the project (editable-free) into the system site-packages.
RUN uv sync --frozen --no-dev

ENV PYTHONPATH=/app/src \
    PATH="/app/.venv/bin:$PATH"

USER itsm

CMD ["python", "-m", "itsm_agent.workers.consumer"]
