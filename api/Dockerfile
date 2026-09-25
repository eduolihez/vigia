FROM golang:1.25-alpine AS tools

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy

RUN pip install --no-cache-dir uv==0.12.18
COPY --from=tools /go/bin/subfinder /usr/local/bin/subfinder

WORKDIR /app

COPY pyproject.toml uv.lock* ./
RUN uv sync --no-install-project

COPY . .
RUN uv sync

# dnstwist ships as a pip package with a `dnstwist` CLI entry point, so it lands in
# the project venv via pyproject.toml rather than a separate binary install here.

# PDF export (report/exporters/pdf.py) renders via headless Chromium.
RUN uv run playwright install --with-deps chromium

EXPOSE 8000

CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn vigia.api.main:app --host 0.0.0.0 --port 8000"]
