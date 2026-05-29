# SafeMAS backend (FastAPI). Ships the Docker CLI so it can build the runner
# image and spawn sandbox containers against the host daemon via the mounted
# /var/run/docker.sock (docker-out-of-docker).
FROM python:3.12-slim

# Docker CLI only (no daemon) — talks to the host socket mounted by compose.
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
