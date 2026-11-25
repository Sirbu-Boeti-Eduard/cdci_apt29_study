FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELEASE_DIR=/data/releases
WORKDIR /app

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY build/build_release.py /app/build/
COPY src/ /app/src/
COPY payload/orion_support.py /app/payload/
EXPOSE 8080
CMD ["python", "/app/backend/server.py"]
