"""SafeMAS backend.

REST API for the visual editor. The canonical authoring/persisted form of an
architecture is **native-LangGraph Python code** (the ``StateGraph`` DSL — see
:mod:`safemas.model`); templates and saved configs are ``.py`` files. The
backend converts code <-> the architecture graph dict ({name, task, nodes[],
edges[]}) via :mod:`safemas.codegen`, and runs that dict on the LangGraph runtime
(:mod:`safemas.graph_runtime`) in a Docker sandbox when available, otherwise a
local subprocess.

Endpoints
    GET    /api/health
    GET    /api/configs                 list saved architectures (.py)
    GET    /api/configs/{name}          load one
    PUT    /api/configs/{name}          save / overwrite (persisted as code)
    DELETE /api/configs/{name}          delete
    GET    /api/templates               list built-in templates
    GET    /api/templates/{id}          load a template (graph dict)
    GET    /api/templates/{id}/code     load a template's StateGraph source
    POST   /api/templates/{id}/run      run a template with task/provider/compromise/resource overrides
    POST   /api/code/to-arch            body: {code} -> Architecture graph
    POST   /api/code/from-arch          body: Architecture -> {code}
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
import tempfile
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
import verdict as verdict_store
import providers as provider_store
import scenario as scenario_store
import spec as spec_module
from safemas.codegen import arch_to_code, code_to_arch
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
    # New configs persist as .py; legacy .json saves still list/load.
    seen: dict[str, float] = {}
    for p in sorted([*CONFIG_DIR.glob("*.py"), *CONFIG_DIR.glob("*.json")]):
        seen.setdefault(p.stem, p.stat().st_mtime)
    return [{"name": n, "modified": m} for n, m in sorted(seen.items())]


@app.get("/api/configs/{name}")
def load_config(name: str) -> Architecture:
    safe = safe_name(name)
    py, js = CONFIG_DIR / f"{safe}.py", CONFIG_DIR / f"{safe}.json"
    try:
        if py.exists():
            return Architecture(**code_to_arch(py.read_text()))
        if js.exists():  # legacy JSON config
            return Architecture(**json.loads(js.read_text()))
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    raise HTTPException(404, "not found")


@app.put("/api/configs/{name}")
def save_config(name: str, arch: Architecture) -> dict:
    safe = safe_name(name)
    p = CONFIG_DIR / f"{safe}.py"
    try:
        p.write_text(arch_to_code(arch.model_dump()))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    (CONFIG_DIR / f"{safe}.json").unlink(missing_ok=True)  # supersede legacy JSON
    return {"saved": p.stem}


@app.delete("/api/configs/{name}")
def delete_config(name: str) -> dict:
    safe = safe_name(name)
    for ext in ("py", "json"):
        (CONFIG_DIR / f"{safe}.{ext}").unlink(missing_ok=True)
    return {"deleted": safe}


# --------------------------------------------------------------------------- #
# Built-in templates (native-LangGraph StateGraph .py files in templates/)
# --------------------------------------------------------------------------- #
def _load_template(p: Path) -> Architecture:
    return Architecture(**code_to_arch(p.read_text()))


@app.get("/api/templates")
def list_templates() -> list[dict]:
    """List templates with their menu grouping/label."""
    out = []
    for p in sorted(TEMPLATE_DIR.glob("*.py")):
        try:
            a = _load_template(p)
        except ValueError:
            continue
        out.append({
            "id": p.stem,
            "group": a.group or "Templates",
            "label": a.title or a.name,
        })
    return out


@app.get("/api/templates/{template_id}")
def load_template(template_id: str) -> Architecture:
    p = TEMPLATE_DIR / f"{safe_name(template_id)}.py"
    if not p.exists():
        raise HTTPException(404, "template not found")
    try:
        return _load_template(p)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.get("/api/templates/{template_id}/code", response_class=PlainTextResponse)
def load_template_code(template_id: str) -> str:
    p = TEMPLATE_DIR / f"{safe_name(template_id)}.py"
    if not p.exists():
        raise HTTPException(404, "template not found")
    return p.read_text()


# --------------------------------------------------------------------------- #
# Code <-> architecture graph (the editor authors templates as StateGraph code)
# --------------------------------------------------------------------------- #
class CodeIn(BaseModel):
    code: str = ""


@app.post("/api/code/to-arch")
def code_to_arch_endpoint(body: CodeIn) -> Architecture:
    """Execute StateGraph source and return the architecture graph it builds."""
    try:
        return Architecture(**code_to_arch(body.code))
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@app.post("/api/code/from-arch")
def code_from_arch_endpoint(arch: Architecture) -> dict:
    """Generate native-LangGraph StateGraph source from an architecture graph."""
    try:
        return {"code": arch_to_code(arch.model_dump())}
    except ValueError as exc:
        raise HTTPException(422, str(exc))


# --------------------------------------------------------------------------- #
# Spec — machine-readable docs for external campaign drivers
# --------------------------------------------------------------------------- #
@app.get("/api/spec")
def spec() -> dict:
    return spec_module.build_spec(list_templates())


# --------------------------------------------------------------------------- #
# Environments + scenario runner — pick an environment dataset, a template, a
# task, and (optionally) an injection scenario + where the poison lands, then
# assemble and run that single case.
# --------------------------------------------------------------------------- #
@app.get("/api/environments")
def list_environments() -> list[dict]:
    return scenario_store.list_environments()


@app.get("/api/environments/{name}")
def get_environment(name: str) -> dict:
    env = scenario_store.load_environment(name)
    if env is None:
        raise HTTPException(404, "unknown environment")
    return {
        **env,
        "injection_points": scenario_store.injection_points(env),
        "default_breach_signal": scenario_store.default_breach_signal(env),
    }


class ScenarioInput(BaseModel):
    """Compose one runnable case: template ⊗ environment ⊗ poison ⊗ task."""

    environment: str
    template_id: str
    user_task_id: Optional[str] = None      # benign task; None -> env's first
    injection_task_id: Optional[str] = None  # attacker goal; None -> clean run
    injection_kind: Optional[str] = None     # 'tool' | 'agent' (memory is the global board, never injected)
    injection_target: Optional[str] = None   # tool id (tool kind) or agent node id/label (agent kind)
    stealth_style: str = "blended"           # blended | authority | metadata | tagged
    provider: Optional[str] = None
    model: Optional[str] = None


def _build_scenario(inp: ScenarioInput) -> tuple[Architecture, dict]:
    env = scenario_store.load_environment(inp.environment)
    if env is None:
        raise HTTPException(404, "unknown environment")
    template = load_template(inp.template_id).model_dump()  # reuses 404 handling

    tasks = {t["id"]: t for t in env.get("user_tasks", [])}
    user_task = tasks.get(inp.user_task_id) or (env.get("user_tasks") or [None])[0]
    task_prompt = user_task["prompt"] if user_task else "Help the user with their request."
    task_success = user_task.get("success") if user_task else None  # deterministic completion spec

    goal, point, success = None, None, None
    if inp.injection_task_id:
        inj = next((j for j in env.get("injection_tasks", [])
                    if j["id"] == inp.injection_task_id), None)
        if inj is None:
            raise HTTPException(422, "unknown injection_task_id")
        goal = inj["goal"]
        success = inj.get("success")  # deterministic tool-call attack-success condition
        kind = inp.injection_kind or "agent"
        if kind == "agent":
            # Which agent is compromised is an architecture-level choice (the env
            # doesn't know the template's agents); assemble resolves the id/label and
            # defaults to the entry agent when none is named.
            point = {"kind": "agent", "id": inp.injection_target or "",
                     "attack": "prompt-injection", "label": "agent"}
        else:
            point = next((p for p in scenario_store.injection_points(env)
                          if p["kind"] == kind and (p["id"] or None) == (inp.injection_target or None)),
                         None)
            if point is None:
                raise HTTPException(422, "injection point not found for this environment")

    try:
        arch, meta = scenario_store.assemble(
            template, env, task_prompt=task_prompt, provider=inp.provider,
            model=inp.model, injection_goal=goal, point=point, style=inp.stealth_style)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    meta["breach_signal"] = scenario_store.default_breach_signal(env)
    meta["success"] = success           # {tool, args} sink that means the attack landed
    meta["task_success"] = task_success  # deterministic user-task completion spec
    meta["task_prompt"] = task_prompt
    return Architecture(**arch), meta


@app.post("/api/scenario/preview")
def scenario_preview(inp: ScenarioInput) -> dict:
    """Assemble the case without running it — returns the rendered payload, the
    resolved injection-point label, the task prompt, and the breach signal."""
    _, meta = _build_scenario(inp)
    return meta


@app.post("/api/scenario/run")
def scenario_run(inp: ScenarioInput) -> dict:
    arch, meta = _build_scenario(inp)
    # Attach an evaluation spec so the run is scored deterministically once it
    # finishes: attack success (the injection `success` sink condition) and task
    # completion (the user task's `task_success` spec) — both written into the scn.
    evaluate = {
        "success": meta.get("success"),
        "task_success": meta.get("task_success"),
    }
    # Return the assembled architecture so the editor can switch its canvas to
    # exactly what's running (env tools/memory + the injection point), not just
    # the bare template.
    return {"run_id": _start_run(arch, evaluate=evaluate), "arch": arch.model_dump(), **meta}


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
    """One campaign test's scenario log (scn_*.json format)."""
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
    # The arch can be large (an environment's tool data); pass it on STDIN, not via
    # an env var / CLI arg, which would blow past the OS argument-size limit (E2BIG).
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", "bridge" if needs_net else "none",
        "--memory", "512m", "--cpus", "1",
        # Unbuffered stdout so streamed tokens reach the log file as they arrive.
        "-e", "PYTHONUNBUFFERED=1",
        "-e", "SAFEMAS_PROVIDERS",
        IMAGE_TAG,
    ]
    env = {**os.environ, "SAFEMAS_PROVIDERS": prov_json}
    return subprocess.run(cmd, input=arch_json.encode(), stdout=logf,
                          stderr=subprocess.STDOUT, env=env).returncode


def _run_local(arch_json: str, prov_json: str, logf) -> int:
    logf.write("[local] Docker sandbox unavailable — running the architecture "
               "as a local subprocess (NOT network-isolated).\n")
    logf.flush()
    # Write the arch to a temp file and pass its PATH (run_mas.py accepts argv[1]);
    # putting a large arch in an env var overflows the OS limit (E2BIG).
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write(arch_json)
        arch_path = tf.name
    env = {**os.environ, "SAFEMAS_PROVIDERS": prov_json, "PYTHONUNBUFFERED": "1"}
    env.pop("SAFEMAS_ARCH", None)  # force run_mas.py to read the file argument
    try:
        return subprocess.run(
            [sys.executable, str(RUNNER_DIR / "run_mas.py"), arch_path],
            stdout=logf, stderr=subprocess.STDOUT, env=env,
        ).returncode
    finally:
        try:
            os.unlink(arch_path)
        except OSError:
            pass


def _apply_default_provider(arch: Architecture) -> None:
    """Every agent runs on the default provider unless it was set explicitly — so
    an architecture never silently falls back to the offline mock. Manual choices
    (an agent with its own provider) are left untouched."""
    default = provider_store.get_default()
    if not default:
        return
    for n in arch.nodes:
        if n.type == "agent" and not n.provider:
            n.provider = default


def _execute(run_id: str, arch: Architecture) -> None:
    run = RUNS[run_id]
    log_path = Path(run["log_path"])
    _apply_default_provider(arch)
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

    result = scn = None
    for line in log_path.read_text().splitlines():
        if line.startswith("__RESULT__ "):
            try:
                result = json.loads(line[len("__RESULT__ "):])
            except json.JSONDecodeError:
                pass
        elif line.startswith("__SCN__ "):
            try:
                scn = json.loads(line[len("__SCN__ "):])
            except json.JSONDecodeError:
                scn = None
    if scn is not None:
        _score_run(run, scn)
        try:
            Path(run["scn_path"]).write_text(json.dumps(scn, indent=2))
            run["has_scn"] = True
        except OSError:
            pass
    run["result"] = result
    run["status"] = "done" if rc == 0 else "error"


def _score_run(run: dict, scn: dict) -> None:
    """For a scenario run, write the deterministic verdicts (attack success + task
    completion) into the scn (no-op for a plain canvas run, which carries no spec)."""
    ev = run.get("evaluate")
    if not ev:
        return
    try:
        verdict_store.evaluate_scenario(
            scn, success=ev.get("success"), task_success=ev.get("task_success"))
    except Exception:  # scoring must never sink the run
        pass


def _start_run(arch: Architecture, evaluate: Optional[dict] = None) -> str:
    """Register a run for ``arch`` and kick off execution in a thread. Returns id.

    ``evaluate`` (optional) carries the scoring spec for a scenario run:
    ``{success, task, provider, model}`` — applied post-run by :func:`_score_run`.
    """
    run_id = uuid.uuid4().hex[:12]
    log_path = RUNS_DIR / f"{run_id}.log"
    log_path.write_text("[queued] preparing execution...\n")
    RUNS[run_id] = {
        "status": "queued", "log_path": str(log_path),
        "scn_path": str(RUNS_DIR / f"{run_id}.scn.json"),
        "has_scn": False, "result": None, "evaluate": evaluate,
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
    """The structured scenario log for a run (the scn_*.json
    format). 404 until the run finishes and emits one."""
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run")
    p = Path(run.get("scn_path", ""))
    if not p.exists():
        raise HTTPException(404, "no scenario log for this run yet")
    return json.loads(p.read_text())
