# Copyright (C) 2026 zakery1369
# SPDX-License-Identifier: AGPL-3.0-or-later

# Uses the official Trivy image as the binary source.
FROM aquasec/trivy:latest AS trivy

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/var/lib/trivy \
    REPORT_DIR=/app/reports

WORKDIR /app

# ca-certificates is needed for registry/API HTTPS calls.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/trivy /app/reports

# Copy Trivy binary from official Aqua image.
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8569

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8569"]
