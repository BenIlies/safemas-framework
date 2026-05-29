"""SafeMAS backend.

REST API for the visual editor: persist architectures as YAML, manage LLM
providers, export, and run architectures (in a Docker sandbox when available,
otherwise as a local subprocess).

Endpoints
    GET    /api/health
    GET    /api/configs                 list saved architectures
    GET    /api/configs/{name}          load one (as JSON graph)
    PUT    /api/configs/{name}          save / overwrite
    DELETE /api/configs/{name}          delete
    GET    /api/providers               list providers (keys masked)
    POST   /api/providers               create provider
    PUT    /api/providers/{id}          update (blank key keeps existing)
    DELETE /api/providers/{id}          delete
    POST   /api/export                  body: Architecture -> raw YAML text
    POST   /api/run                     body: Architecture -> {run_id}
    GET    /api/run/{run_id}            run status + log tail
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

import providers as provider_store
from schema import Architecture, ProviderInput, ProviderPublic

BASE = Path(__file__).resolve().parent
CONFIG_DIR = BASE / "configs"
RUNS_DIR = BASE / "runs"
RUNNER_DIR = BASE / "runner"


def _runner_tag() -> str:
    """Content-addressed image tag so a changed runner auto-rebuilds (and an
    unchanged one is reused from cache)."""
    h = hashlib.sha256()
    for f in ("run_mas.py", "Dockerfile"):
        p = RUNNER_DIR / f
        if p.exists():
            h.update(p.read_bytes())
    return f"safemas-runner:{h.hexdigest()[:12]}"


IMAGE_TAG = _runner_tag()

# SAFEMAS_SANDBOX: "auto" (docker if present, else local), "docker", or "local".
SANDBOX_MODE = os.environ.get("SAFEMAS_SANDBOX", "auto").lower()

CONFIG_DIR.mkdir(exist_ok=True)
RUNS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="SafeMAS", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# in-memory run registry: run_id -> {status, log_path, result}
RUNS: dict[str, dict] = {}

SAFE_NAME = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(name: str) -> str:
    cleaned = SAFE_NAME.sub("-", name.strip()) or "untitled"
    return cleaned[:80]


def docker_available() -> bool:
    return shutil.which("docker") is not None and SANDBOX_MODE != "local"


# --------------------------------------------------------------------------- #
# Health + Config CRUD
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health() -> dict:
    has_docker = shutil.which("docker") is not None
    if has_docker and SANDBOX_MODE != "local":
        mode = "docker"
    else:
        mode = "local"
    return {"ok": True, "docker": has_docker, "sandbox": mode}


@app.get("/api/configs")
def list_configs() -> list[dict]:
    out = []
    for p in sorted(CONFIG_DIR.glob("*.yml")):
        out.append({"name": p.stem, "modified": p.stat().st_mtime})
    return out


@app.get("/api/configs/{name}")
def load_config(name: str) -> Architecture:
    p = CONFIG_DIR / f"{safe_name(name)}.yml"
    if not p.exists():
        raise HTTPException(404, "not found")
    data = yaml.safe_load(p.read_text()) or {}
    return Architecture(**data)


@app.put("/api/configs/{name}")
def save_config(name: str, arch: Architecture) -> dict:
    p = CONFIG_DIR / f"{safe_name(name)}.yml"
    p.write_text(yaml.safe_dump(arch.to_yaml_dict(), sort_keys=False))
    return {"saved": p.stem}


@app.delete("/api/configs/{name}")
def delete_config(name: str) -> dict:
    p = CONFIG_DIR / f"{safe_name(name)}.yml"
    if p.exists():
        p.unlink()
    return {"deleted": safe_name(name)}


@app.post("/api/export", response_class=PlainTextResponse)
def export_yaml(arch: Architecture) -> str:
    return yaml.safe_dump(arch.to_yaml_dict(), sort_keys=False)


# --------------------------------------------------------------------------- #
# Provider registry (keys never leave the server)
# --------------------------------------------------------------------------- #
@app.get("/api/providers")
def list_providers() -> list[ProviderPublic]:
    return [ProviderPublic.of(p) for p in provider_store.all_providers()]


@app.post("/api/providers")
def create_provider(data: ProviderInput) -> ProviderPublic:
    return ProviderPublic.of(provider_store.create(data))


@app.put("/api/providers/{provider_id}")
def update_provider(provider_id: str, data: ProviderInput) -> ProviderPublic:
    updated = provider_store.update(provider_id, data)
    if not updated:
        raise HTTPException(404, "provider not found")
    return ProviderPublic.of(updated)


@app.delete("/api/providers/{provider_id}")
def delete_provider(provider_id: str) -> dict:
    return {"deleted": provider_store.delete(provider_id)}


# --------------------------------------------------------------------------- #
# Run (Docker sandbox, or local subprocess fallback)
# --------------------------------------------------------------------------- #
def ensure_image() -> bool:
    """Build the runner image on first use. Returns True if image is available."""
    have = subprocess.run(
        ["docker", "image", "inspect", IMAGE_TAG], capture_output=True
    )
    if have.returncode == 0:
        return True
    build = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, str(RUNNER_DIR)],
        capture_output=True, text=True,
    )
    return build.returncode == 0


def _arch_uses_live_llm(arch: Architecture, prov_map: dict) -> bool:
    for n in arch.nodes:
        if n.type == "agent" and n.provider:
            if prov_map.get(n.provider, {}).get("api_key"):
                return True
    return False


def _run_docker(arch_yaml: str, prov_json: str, needs_net: bool, logf) -> int:
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "bridge" if needs_net else "none",
        "--memory", "512m", "--cpus", "1",
        "-e", "SAFEMAS_ARCH",
        "-e", "SAFEMAS_PROVIDERS",
        IMAGE_TAG,
    ]
    env = {**os.environ, "SAFEMAS_ARCH": arch_yaml, "SAFEMAS_PROVIDERS": prov_json}
    proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env)
    return proc.returncode


def _run_local(arch_yaml: str, prov_json: str, logf) -> int:
    logf.write("[local] Docker sandbox unavailable — running runner as a local "
               "subprocess (NOT network-isolated).\n")
    logf.flush()
    env = {**os.environ, "SAFEMAS_ARCH": arch_yaml, "SAFEMAS_PROVIDERS": prov_json}
    proc = subprocess.run(
        [sys.executable, str(RUNNER_DIR / "run_mas.py")],
        stdout=logf, stderr=subprocess.STDOUT, env=env,
    )
    return proc.returncode


def _execute(run_id: str, arch: Architecture) -> None:
    run = RUNS[run_id]
    log_path = Path(run["log_path"])
    prov_map = provider_store.resolved_map()
    arch_yaml = yaml.safe_dump(arch.to_yaml_dict(), sort_keys=False)
    prov_json = json.dumps(prov_map)
    needs_net = _arch_uses_live_llm(arch, prov_map)

    run["status"] = "running"
    rc = 1
    with open(log_path, "w") as logf:
        try:
            if docker_available() and ensure_image():
                rc = _run_docker(arch_yaml, prov_json, needs_net, logf)
            else:
                rc = _run_local(arch_yaml, prov_json, logf)
        except Exception as exc:  # pragma: no cover
            logf.write(f"[error] execution failed: {exc}\n")
            rc = 1

    # extract the machine-readable result line
    result = None
    for line in log_path.read_text().splitlines():
        if line.startswith("__RESULT__ "):
            try:
                result = json.loads(line[len("__RESULT__ "):])
            except json.JSONDecodeError:
                pass
    run["result"] = result
    run["status"] = "done" if rc == 0 else "error"


@app.post("/api/run")
def run(arch: Architecture) -> dict:
    run_id = uuid.uuid4().hex[:12]
    log_path = RUNS_DIR / f"{run_id}.log"
    log_path.write_text("[queued] preparing execution...\n")
    RUNS[run_id] = {"status": "queued", "log_path": str(log_path), "result": None}
    threading.Thread(target=_execute, args=(run_id, arch), daemon=True).start()
    return {"run_id": run_id}


@app.get("/api/run/{run_id}")
def run_status(run_id: str) -> dict:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    log = ""
    p = Path(run["log_path"])
    if p.exists():
        log = "\n".join(
            l for l in p.read_text().splitlines() if not l.startswith("__RESULT__")
        )
    return {
        "run_id": run_id,
        "status": run["status"],
        "log": log,
        "result": run["result"],
    }
