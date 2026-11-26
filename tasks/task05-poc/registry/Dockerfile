FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY payload/ /app/payload/

EXPOSE 8080
CMD ["python", "/app/backend/server.py"]
