"""SafeMAS backend.

REST API for the visual editor: persist architectures as YAML, export them, and
run them inside a Docker container via the runner image.

Endpoints
    GET    /api/health
    GET    /api/configs                 list saved architectures
    GET    /api/configs/{name}          load one (as JSON graph)
    PUT    /api/configs/{name}          save / overwrite
    DELETE /api/configs/{name}          delete
    POST   /api/export                  body: Architecture -> raw YAML text
    POST   /api/run                      body: Architecture -> {run_id}
    GET    /api/run/{run_id}            run status + log tail
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from schema import Architecture

BASE = Path(__file__).resolve().parent
CONFIG_DIR = BASE / "configs"
RUNS_DIR = BASE / "runs"
RUNNER_DIR = BASE / "runner"
IMAGE_TAG = "safemas-runner:latest"

CONFIG_DIR.mkdir(exist_ok=True)
RUNS_DIR.mkdir(exist_ok=True)

app = FastAPI(title="SafeMAS", version="1.0.0")
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


# --------------------------------------------------------------------------- #
# Config CRUD
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "docker": shutil.which("docker") is not None}


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
# Run inside Docker
# --------------------------------------------------------------------------- #
def ensure_image() -> bool:
    """Build the runner image on first use. Returns True if image is available."""
    if shutil.which("docker") is None:
        return False
    have = subprocess.run(
        ["docker", "image", "inspect", IMAGE_TAG],
        capture_output=True,
    )
    if have.returncode == 0:
        return True
    build = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, str(RUNNER_DIR)],
        capture_output=True,
        text=True,
    )
    return build.returncode == 0


def _execute(run_id: str, arch: Architecture) -> None:
    run = RUNS[run_id]
    log_path = Path(run["log_path"])
    workdir = Path(tempfile.mkdtemp(prefix="safemas-"))
    arch_file = workdir / "architecture.yml"
    arch_file.write_text(yaml.safe_dump(arch.to_yaml_dict(), sort_keys=False))

    if not ensure_image():
        log_path.write_text(
            "[error] Docker is unavailable or the runner image failed to build.\n"
            "Install Docker and ensure the daemon is running.\n"
        )
        run["status"] = "error"
        return

    run["status"] = "running"
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",           # sandbox: no network egress
        "--memory", "512m", "--cpus", "1",
        "-v", f"{arch_file}:/mas/architecture.yml:ro",
    ]
    if os.environ.get("OPENAI_API_KEY"):
        cmd += ["-e", "OPENAI_API_KEY"]
    cmd.append(IMAGE_TAG)

    with open(log_path, "w") as logf:
        proc = subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, text=True)

    # extract the machine-readable result line
    text = log_path.read_text()
    result = None
    for line in text.splitlines():
        if line.startswith("__RESULT__ "):
            import json

            try:
                result = json.loads(line[len("__RESULT__ "):])
            except json.JSONDecodeError:
                pass
    run["result"] = result
    run["status"] = "done" if proc.returncode == 0 else "error"
    shutil.rmtree(workdir, ignore_errors=True)


@app.post("/api/run")
def run(arch: Architecture) -> dict:
    run_id = uuid.uuid4().hex[:12]
    log_path = RUNS_DIR / f"{run_id}.log"
    log_path.write_text("[queued] preparing container...\n")
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
