FROM python:3.11-slim

RUN pip install --no-cache-dir "aiohttp>=3.10,<4"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY plugin.py /app/plugin.py

ENTRYPOINT ["python", "/app/plugin.py"]
