# Sandbox image that executes a SafeMAS architecture.
# Build once; the backend runs a fresh container per execution. The architecture
# and resolved providers are passed in via $SAFEMAS_ARCH / $SAFEMAS_PROVIDERS so
# the image needs no host bind-mounts (works when spawned via the Docker socket).
FROM python:3.12-slim

WORKDIR /mas

# YAML parsing + LLM clients (OpenAI-compatible and Anthropic).
RUN pip install --no-cache-dir pyyaml==6.0.2 openai==1.55.0 anthropic==0.39.0

COPY run_mas.py /mas/run_mas.py

ENTRYPOINT ["python", "/mas/run_mas.py"]
