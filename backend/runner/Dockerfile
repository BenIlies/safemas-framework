# Sandbox image that executes a SafeMAS architecture by running its DSL code.
# Build context is the backend/ directory so the image can bundle the `safemas`
# library beside the runner. Build once; the backend runs a fresh container per
# execution. The generated code and resolved providers are passed in via
# $SAFEMAS_CODE / $SAFEMAS_PROVIDERS, so the image needs no host bind-mounts
# (works when spawned via the Docker socket).
#
#   docker build -t safemas-runner -f runner/Dockerfile .      (from backend/)
FROM python:3.12-slim

WORKDIR /app

# LLM clients only (OpenAI-compatible + Anthropic). The DSL/engine is pure stdlib.
RUN pip install --no-cache-dir openai==1.55.0 anthropic==0.39.0

COPY safemas /app/safemas
COPY runner/run_mas.py /app/run_mas.py

ENTRYPOINT ["python", "/app/run_mas.py"]
