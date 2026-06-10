FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:${PATH}"

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml ./
COPY uv.lock* ./
RUN uv sync --no-dev --no-install-project

COPY immuta_queries.py mcp_server.py ./

RUN useradd -u 10001 -m app && chown -R app:app /app
USER app

EXPOSE 8080

ENTRYPOINT ["python", "-m", "mcp_server"]
CMD ["--transport", "http", "--host", "0.0.0.0", "--port", "8080"]
