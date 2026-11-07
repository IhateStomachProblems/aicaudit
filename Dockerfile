FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY aicaudit/ ./aicaudit/

RUN pip install --no-cache-dir ".[mcp]"

CMD ["aicaudit", "mcp"]
