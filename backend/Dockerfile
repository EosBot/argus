FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    nmap \
    whois \
    yara \
    libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/backend/
COPY config/ /app/config/
COPY argus_engine/ /app/argus_engine/
RUN useradd --system --uid 10001 --create-home argus \
    && chown -R argus:argus /app

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

USER argus
EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
