# Sandbox image that executes a SafeMAS architecture (architecture.yml).
# Build once; the backend runs a fresh container per execution.
FROM python:3.12-slim

WORKDIR /mas

# Minimal deps: YAML parsing + (optional) OpenAI client for real LLM agents.
RUN pip install --no-cache-dir pyyaml==6.0.2 openai==1.55.0

COPY run_mas.py /mas/run_mas.py

# The architecture is mounted at runtime to /mas/architecture.yml
ENTRYPOINT ["python", "/mas/run_mas.py", "/mas/architecture.yml"]
