"""SafeMAS backend.

REST API for the visual editor. An architecture is a JSON graph ({name, task,
nodes[], edges[]}) — the single source of truth. Runs execute it on the LangGraph
runtime (:mod:`safemas.graph_runtime`) in a Docker sandbox when available,
otherwise a local subprocess. There is no DSL / codegen step.

Endpoints
    GET    /api/health
    GET    /api/configs                 list saved architectures (JSON)
    GET    /api/configs/{name}          load one
    PUT    /api/configs/{name}          save / overwrite
    DELETE /api/configs/{name}          delete
    GET    /api/templates               list built-in templates
    GET    /api/templates/{id}          load a template (JSON graph)
    POST   /api/templates/{id}/run      run a template with task/provider/compromise/resource overrides
    GET    /api/providers               list providers (keys masked)
    POST   /api/providers               create provider
    PUT    /api/providers/{id}          update (blank key keeps existing)
    DELETE /api/providers/{id}          delete
    POST   /api/run                     body: Architecture -> {run_id}
    GET    /api/run/{run_id}            run status + log tail
    GET    /api/run/{run_id}/scn        structured scenario log
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
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

import campaigns as campaign_store
import providers as provider_store
import spec as spec_module
from schema import Architecture, ProviderInput, ProviderPublic

BASE = Path(__file__).resolve().parent
CONFIG_DIR = BASE / "configs"
RUNS_DIR = BASE / "runs"
RUNNER_DIR = BASE / "runner"
TEMPLATE_DIR = BASE.parent / "templates"


def _runner_tag() -> str:
    """Content-addressed image tag so a changed runner (or library) auto-rebuilds
    and an unchanged one is reused from cache."""
    h = hashlib.sha256()
    for f in (RUNNER_DIR / "run_mas.py", RUNNER_DIR / "Dockerfile"):
        if f.exists():
            h.update(f.read_bytes())
    for f in sorted((BASE / "safemas").glob("*.py")):
        h.update(f.read_bytes())
    return f"safemas-runner:{h.hexdigest()[:12]}"


IMAGE_TAG = _runner_tag()

# SAFEMAS_SANDBOX: "auto" (docker if present, else local), "docker", or "local".
SANDBOX_MODE = os.environ.get("SAFEMAS_SANDBOX", "auto").lower()

CONFIG_DIR.mkdir(exist_ok=True)
RUNS_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="SafeMAS",
    version="4.0.0",
    description=(
        "Author multi-agent systems as JSON, run them on a LangGraph runtime with "
        "real tool-calling agents, and benchmark their robustness to prompt-injection "
        "/ poisoning / AiTM attacks. Call `GET /api/spec` for the machine-readable "
        "format + architecture catalogue, then drive runs with `/api/templates/{id}/run` "
        "or campaigns with `/api/campaigns`."
    ),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class CampaignInput(BaseModel):
    """Start a benchmark campaign over one architecture. Provide either a built-in
    ``template_id`` or an inline ``arch`` graph."""

    name: str = ""
    template_id: str = ""
    arch: Architecture | None = None
    task: str = ""
    attacks: list[str] = Field(default_factory=list)  # restrict to these attack types; [] = all
    limit: int | None = None                          # cap the number of tests
    concurrency: int | None = None                    # parallel workers (default ~2×CPU, max 32)

# in-memory run registry: run_id -> {status, log_path, result}
RUNS: dict[str, dict] = {}

SAFE_NAME = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(name: str) -> str:
    cleaned = SAFE_NAME.sub("-", name.strip()) or "untitled"
    return cleaned[:80]


def docker_available() -> bool:
    return shutil.which("docker") is not None and SANDBOX_MODE != "local"


# --------------------------------------------------------------------------- #
# Health + Config CRUD  (architectures persisted as SafeMAS DSL .py files)
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health() -> dict:
    has_docker = shutil.which("docker") is not None
    mode = "docker" if has_docker and SANDBOX_MODE != "local" else "local"
    return {"ok": True, "docker": has_docker, "sandbox": mode}


@app.get("/api/configs")
def list_configs() -> list[dict]:
    return [
        {"name": p.stem, "modified": p.stat().st_mtime}
        for p in sorted(CONFIG_DIR.glob("*.json"))
    ]


@app.get("/api/configs/{name}")
def load_config(name: str) -> Architecture:
    p = CONFIG_DIR / f"{safe_name(name)}.json"
    if not p.exists():
        raise HTTPException(404, "not found")
    try:
        return Architecture(**json.loads(p.read_text()))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))


@app.put("/api/configs/{name}")
def save_config(name: str, arch: Architecture) -> dict:
    p = CONFIG_DIR / f"{safe_name(name)}.json"
    p.write_text(json.dumps(arch.model_dump(), indent=2))
    return {"saved": p.stem}


@app.delete("/api/configs/{name}")
def delete_config(name: str) -> dict:
    p = CONFIG_DIR / f"{safe_name(name)}.json"
    if p.exists():
        p.unlink()
    return {"deleted": safe_name(name)}


# --------------------------------------------------------------------------- #
# Built-in templates (architecture JSON files in templates/)
# --------------------------------------------------------------------------- #
def _load_template(p: Path) -> Architecture:
    return Architecture(**json.loads(p.read_text()))


@app.get("/api/templates")
def list_templates() -> list[dict]:
    """List templates with their menu grouping/label."""
    out = []
    for p in sorted(TEMPLATE_DIR.glob("*.json")):
        try:
            a = _load_template(p)
        except (json.JSONDecodeError, ValueError):
            continue
        out.append({
            "id": p.stem,
            "group": a.group or "Templates",
            "label": a.title or a.name,
        })
    return out


@app.get("/api/templates/{template_id}")
def load_template(template_id: str) -> Architecture:
    p = TEMPLATE_DIR / f"{safe_name(template_id)}.json"
    if not p.exists():
        raise HTTPException(404, "template not found")
    try:
        return _load_template(p)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))


# --------------------------------------------------------------------------- #
# Spec — machine-readable docs for external campaign drivers
# --------------------------------------------------------------------------- #
@app.get("/api/spec")
def spec() -> dict:
    return spec_module.build_spec(list_templates())


# --------------------------------------------------------------------------- #
# Campaigns — benchmark an architecture against many attacks, in parallel
# --------------------------------------------------------------------------- #
def _resolve_arch(inp: CampaignInput) -> Architecture:
    if inp.arch is not None:
        return inp.arch
    if inp.template_id:
        return load_template(inp.template_id)
    raise HTTPException(422, "provide either `arch` or `template_id`")


@app.post("/api/campaigns")
def start_campaign(inp: CampaignInput) -> dict:
    arch = _resolve_arch(inp)
    cid = campaign_store.create_campaign(
        name=inp.name, arch=arch.model_dump(), task=inp.task or None,
        attacks=inp.attacks or None, limit=inp.limit, concurrency=inp.concurrency,
    )
    return {"campaign_id": cid, **campaign_store.summary(campaign_store.CAMPAIGNS[cid])}


@app.get("/api/campaigns")
def list_campaigns() -> list[dict]:
    return [campaign_store.summary(c) for c in campaign_store.CAMPAIGNS.values()]


def _get_campaign(cid: str) -> dict:
    c = campaign_store.CAMPAIGNS.get(cid)
    if not c:
        raise HTTPException(404, "unknown campaign")
    return c


@app.get("/api/campaigns/{cid}")
def campaign_status(cid: str) -> dict:
    return campaign_store.summary(_get_campaign(cid))


@app.get("/api/campaigns/{cid}/tests")
def campaign_tests(cid: str) -> list[dict]:
    return campaign_store.test_rows(_get_campaign(cid))


@app.get("/api/campaigns/{cid}/log", response_class=PlainTextResponse)
def campaign_log(cid: str) -> str:
    return "\n".join(_get_campaign(cid)["log"])


@app.get("/api/campaigns/{cid}/tests/{idx}/scn")
def campaign_test_scn(cid: str, idx: int) -> dict:
    """One campaign test's scenario log (PCAP scn_*.json format)."""
    _get_campaign(cid)
    scn = campaign_store.test_scn(cid, idx)
    if scn is None:
        raise HTTPException(404, "no scenario log for this test")
    return scn


@app.delete("/api/campaigns/{cid}")
def delete_campaign(cid: str) -> dict:
    return {"deleted": campaign_store.delete(cid)}


# --------------------------------------------------------------------------- #
# Provider registry (keys never leave the server)
# --------------------------------------------------------------------------- #
@app.get("/api/providers")
def list_providers() -> list[ProviderPublic]:
    default = provider_store.get_default()
    out = []
    for p in provider_store.all_providers():
        pub = ProviderPublic.of(p)
        pub.default = (p.id == default)
        out.append(pub)
    return out


@app.post("/api/providers")
def create_provider(data: ProviderInput) -> ProviderPublic:
    p = provider_store.create(data)
    pub = ProviderPublic.of(p)
    pub.default = (p.id == provider_store.get_default())
    return pub


@app.put("/api/providers/{provider_id}")
def update_provider(provider_id: str, data: ProviderInput) -> ProviderPublic:
    updated = provider_store.update(provider_id, data)
    if not updated:
        raise HTTPException(404, "provider not found")
    pub = ProviderPublic.of(updated)
    pub.default = (updated.id == provider_store.get_default())
    return pub


@app.put("/api/providers/{provider_id}/default")
def set_default_provider(provider_id: str) -> dict:
    if not provider_store.set_default(provider_id):
        raise HTTPException(404, "provider not found")
    return {"default": provider_id}


@app.delete("/api/providers/{provider_id}")
def delete_provider(provider_id: str) -> dict:
    return {"deleted": provider_store.delete(provider_id)}


# --------------------------------------------------------------------------- #
# Run — generate the DSL code and execute it (sandbox, or local fallback)
# --------------------------------------------------------------------------- #
def ensure_image() -> bool:
    """Build the runner image on first use. Returns True if the image is available.
    The build context is ``backend/`` so the image can bundle the safemas library
    alongside the runner."""
    have = subprocess.run(["docker", "image", "inspect", IMAGE_TAG], capture_output=True)
    if have.returncode == 0:
        return True
    build = subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "-f", str(RUNNER_DIR / "Dockerfile"), str(BASE)],
        capture_output=True, text=True,
    )
    return build.returncode == 0


def _arch_uses_live_llm(arch: Architecture, prov_map: dict) -> bool:
    return any(
        n.type == "agent" and n.provider and prov_map.get(n.provider, {}).get("api_key")
        for n in arch.nodes
    )


def _run_docker(arch_json: str, prov_json: str, needs_net: bool, logf) -> int:
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "bridge" if needs_net else "none",
        "--memory", "512m", "--cpus", "1",
        # Unbuffered stdout so streamed tokens reach the log file as they arrive.
        "-e", "PYTHONUNBUFFERED=1",
        "-e", "SAFEMAS_ARCH", "-e", "SAFEMAS_PROVIDERS",
        IMAGE_TAG,
    ]
    env = {**os.environ, "SAFEMAS_ARCH": arch_json, "SAFEMAS_PROVIDERS": prov_json}
    return subprocess.run(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env).returncode


def _run_local(arch_json: str, prov_json: str, logf) -> int:
    logf.write("[local] Docker sandbox unavailable — running the architecture "
               "as a local subprocess (NOT network-isolated).\n")
    logf.flush()
    env = {**os.environ, "SAFEMAS_ARCH": arch_json, "SAFEMAS_PROVIDERS": prov_json,
           "PYTHONUNBUFFERED": "1"}
    return subprocess.run(
        [sys.executable, str(RUNNER_DIR / "run_mas.py")],
        stdout=logf, stderr=subprocess.STDOUT, env=env,
    ).returncode


def _execute(run_id: str, arch: Architecture) -> None:
    run = RUNS[run_id]
    log_path = Path(run["log_path"])
    prov_map = provider_store.resolved_map()
    arch_json = json.dumps(arch.model_dump())
    prov_json = json.dumps(prov_map)
    needs_net = _arch_uses_live_llm(arch, prov_map)

    run["status"] = "running"
    rc = 1
    with open(log_path, "w") as logf:
        try:
            if docker_available() and ensure_image():
                rc = _run_docker(arch_json, prov_json, needs_net, logf)
            else:
                rc = _run_local(arch_json, prov_json, logf)
        except Exception as exc:  # pragma: no cover
            logf.write(f"[error] execution failed: {exc}\n")
            rc = 1

    result = None
    for line in log_path.read_text().splitlines():
        if line.startswith("__RESULT__ "):
            try:
                result = json.loads(line[len("__RESULT__ "):])
            except json.JSONDecodeError:
                pass
        elif line.startswith("__SCN__ "):
            try:
                scn = json.loads(line[len("__SCN__ "):])
                Path(run["scn_path"]).write_text(json.dumps(scn, indent=2))
                run["has_scn"] = True
            except (json.JSONDecodeError, OSError):
                pass
    run["result"] = result
    run["status"] = "done" if rc == 0 else "error"


def _start_run(arch: Architecture) -> str:
    """Register a run for ``arch`` and kick off execution in a thread. Returns id."""
    run_id = uuid.uuid4().hex[:12]
    log_path = RUNS_DIR / f"{run_id}.log"
    log_path.write_text("[queued] preparing execution...\n")
    RUNS[run_id] = {
        "status": "queued", "log_path": str(log_path),
        "scn_path": str(RUNS_DIR / f"{run_id}.scn.json"),
        "has_scn": False, "result": None,
    }
    threading.Thread(target=_execute, args=(run_id, arch), daemon=True).start()
    return run_id


@app.post("/api/run")
def run(arch: Architecture) -> dict:
    return {"run_id": _start_run(arch)}


class CompromiseInput(BaseModel):
    node: str                                   # id of the node to compromise
    attack: Optional[str] = None                # defaults to the node type's attack
    payload: str = ""


class TemplateRunInput(BaseModel):
    """Run a stored template without rebuilding its graph: override the task,
    assign a provider/model to its agents, optionally compromise one node, and
    set what tools/memories return (``resources``: node-id → content)."""
    task: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    compromise: Optional[CompromiseInput] = None
    resources: dict[str, str] = Field(default_factory=dict)


@app.post("/api/templates/{template_id}/run")
def run_template(template_id: str, body: TemplateRunInput) -> dict:
    """Convenience runner: load a template, apply task / provider / compromise /
    resource overrides on the *instance* (never the template file), and run it."""
    arch = load_template(template_id)  # reuses the 404/422 handling
    data = arch.model_dump()

    if body.task is not None:
        data["task"] = body.task
    for n in data["nodes"]:
        if n["type"] == "agent":
            if body.provider is not None:
                n["provider"] = body.provider
            if body.model is not None:
                n["model"] = body.model
        if n["id"] in body.resources and n["type"] in ("tool", "memory"):
            n["content"] = body.resources[n["id"]]

    if body.compromise:
        target = next((n for n in data["nodes"] if n["id"] == body.compromise.node), None)
        if target is None:
            raise HTTPException(422, f"compromise node '{body.compromise.node}' not in template")
        target["malicious"] = {"enabled": True, "attack": body.compromise.attack,
                               "payload": body.compromise.payload}

    return {"run_id": _start_run(Architecture(**data))}


@app.get("/api/run/{run_id}")
def run_status(run_id: str) -> dict:
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    log = ""
    p = Path(run["log_path"])
    if p.exists():
        log = "\n".join(
            l for l in p.read_text().splitlines()
            if not l.startswith("__RESULT__") and not l.startswith("__SCN__")
        )
    return {"run_id": run_id, "status": run["status"], "log": log,
            "result": run["result"], "has_scn": run.get("has_scn", False)}


@app.get("/api/run/{run_id}/scn")
def run_scn(run_id: str) -> dict:
    """The structured scenario log for a run (the PCAP analyzer's scn_*.json
    format). 404 until the run finishes and emits one."""
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    p = Path(run.get("scn_path", ""))
    if not p.exists():
        raise HTTPException(404, "no scenario log for this run yet")
    return json.loads(p.read_text())
