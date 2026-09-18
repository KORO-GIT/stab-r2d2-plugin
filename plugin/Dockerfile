FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends kmod procps v4l-utils \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "aiohttp>=3.10,<4"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY plugin.py /app/plugin.py

ENTRYPOINT ["python", "/app/plugin.py"]
