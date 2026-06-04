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

# LangGraph runtime + LangChain chat clients (OpenAI-compatible + Anthropic).
# We let these pull mutually-consistent openai/anthropic/httpx versions (modern
# openai fixed the httpx-0.28 `proxies` incompatibility, so no pin is needed).
RUN pip install --no-cache-dir \
        langgraph>=0.2.50 \
        langchain-core>=0.3.0 \
        langchain-openai>=0.2.0 \
        langchain-anthropic>=0.2.0

COPY safemas /app/safemas
COPY runner/run_mas.py /app/run_mas.py

ENTRYPOINT ["python", "/app/run_mas.py"]
