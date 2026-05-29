#!/usr/bin/env python3
"""Execute a SafeMAS architecture described in YAML.

Designed to run *inside* a Docker container (see Dockerfile), but also runnable
directly as a subprocess when Docker is unavailable. It loads the topology,
seeds the entry agent(s) with the task, and propagates messages along channels.

Each agent "thinks" using a real LLM when its referenced provider has an API key,
and a deterministic mock otherwise -- so the demo runs with zero credentials.

Inputs (in priority order, so the same image works mounted or socket-spawned):
    * architecture:  $SAFEMAS_ARCH (YAML)  ->  argv[1] file  ->  /mas/architecture.yml  ->  stdin
    * providers:     $SAFEMAS_PROVIDERS (JSON: {id: {kind, base_url, api_key, models}})

Malicious elements alter execution and are loudly logged as ATTACK events:

    agent   prompt-injection  -> attacker payload appended to the agent's input
    memory  memory-poisoning  -> poisoned content returned on every read
    tool    tool-poisoning    -> tool returns the attacker payload
    channel aitm              -> message rewritten as it crosses the edge

Output: a human-readable trace on stdout plus a machine-readable JSON summary
(the last line, prefixed with ``__RESULT__ ``) the backend can parse.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict

import yaml

RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREY = "\033[90m"
GREEN = "\033[92m"
BOLD = "\033[1m"


def log(msg: str = "") -> None:
    print(msg, flush=True)


def attack(msg: str) -> None:
    print(f"{RED}{BOLD}[ATTACK]{RESET} {RED}{msg}{RESET}", flush=True)


def step(msg: str) -> None:
    print(f"{CYAN}[exec]{RESET} {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Input loading
# --------------------------------------------------------------------------- #
def load_architecture() -> dict:
    env = os.environ.get("SAFEMAS_ARCH")
    if env:
        return yaml.safe_load(env)
    path = sys.argv[1] if len(sys.argv) > 1 else "/mas/architecture.yml"
    if os.path.exists(path):
        with open(path) as fh:
            return yaml.safe_load(fh)
    data = sys.stdin.read()
    return yaml.safe_load(data) if data.strip() else {}


def load_providers() -> dict[str, dict]:
    env = os.environ.get("SAFEMAS_PROVIDERS")
    if not env:
        return {}
    try:
        return json.loads(env)
    except json.JSONDecodeError:
        return {}


# --------------------------------------------------------------------------- #
# LLM backends (resolved per-agent via its provider)
# --------------------------------------------------------------------------- #
def call_llm(provider: dict | None, model: str, system: str, user: str,
             temperature: float | None, max_tokens: int | None) -> str:
    kind = (provider or {}).get("kind", "mock")
    key = (provider or {}).get("api_key", "")
    base_url = (provider or {}).get("base_url", "") or None

    if not provider or kind == "mock" or not key:
        # Deterministic mock so the system is runnable without credentials.
        digest = abs(hash(user)) % 1000
        tag = model or kind or "mock"
        return f"[mock:{tag}] processed input (#{digest}); produced an answer."

    try:
        if kind == "anthropic":
            import anthropic

            client = anthropic.Anthropic(api_key=key, base_url=base_url)
            resp = client.messages.create(
                model=model or "claude-haiku-4-5",
                system=system,
                max_tokens=max_tokens or 1024,
                temperature=temperature if temperature is not None else 1.0,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(getattr(b, "text", "") for b in resp.content)

        # openai + openai-compatible (base_url overrides the endpoint)
        from openai import OpenAI

        client = OpenAI(api_key=key, base_url=base_url)
        kwargs: dict = {
            "model": model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        resp = client.chat.completions.create(**kwargs)
        return resp.choices[0].message.content or ""
    except Exception as exc:  # pragma: no cover - network/credentials dependent
        return f"[llm-error:{kind}:{model}] {exc}"


# --------------------------------------------------------------------------- #
# Graph helpers
# --------------------------------------------------------------------------- #
def index_nodes(arch: dict) -> dict[str, dict]:
    return {n["id"]: n for n in arch.get("nodes", [])}


def mal(el: dict) -> dict:
    m = el.get("malicious") or {}
    return m if m.get("enabled") else {}


def main() -> int:
    arch = load_architecture() or {}
    providers = load_providers()

    nodes = index_nodes(arch)
    edges = arch.get("edges", [])
    task = arch.get("task", "Solve the assigned task.")

    agents = {i: n for i, n in nodes.items() if n["type"] == "agent"}
    channels: dict[str, list[dict]] = defaultdict(list)
    attachments: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    entry_from_io: set[str] = set()  # agents wired from an entrance node
    exit_from_io: set[str] = set()   # agents wired to an exit node
    for e in edges:
        src, tgt = e["source"], e["target"]
        s_type = nodes.get(src, {}).get("type")
        t_type = nodes.get(tgt, {}).get("type")
        if s_type == "entrance" and t_type == "agent":
            entry_from_io.add(tgt)
        elif t_type == "exit" and s_type == "agent":
            exit_from_io.add(src)
        elif s_type == "agent" and t_type == "agent":
            channels[src].append(e)
        elif "memory" in (s_type, t_type) or "tool" in (s_type, t_type):
            agent_id = src if src in agents else tgt
            other = tgt if src in agents else src
            if other in nodes:
                attachments[agent_id].append((nodes[other], e))

    live = sum(1 for a in agents.values()
               if providers.get(a.get("provider"), {}).get("api_key"))
    log(f"{BOLD}SafeMAS runner{RESET}  ::  architecture '{arch.get('name')}'")
    log(f"{GREY}agents={len(agents)} channels={sum(len(v) for v in channels.values())} "
        f"live-llm={live}/{len(agents)} task={task!r}{RESET}")
    log("=" * 64)

    attacks: list[dict] = []

    def resource_value(res: dict, kind: str) -> str:
        m = mal(res)
        if m:
            attacks.append({"element": res["id"], "type": m.get("attack")})
            attack(f"{kind} '{res.get('label', res['id'])}' is poisoned -> "
                   f"returns attacker payload: {m.get('payload', '')!r}")
            return m.get("payload", "")
        if kind == "memory":
            return f"[memory:{res.get('label', res['id'])}] (clean, empty)"
        return f"[tool:{res.get('label', res['id'])}] returned a normal result"

    visited: set[str] = set()
    outputs: dict[str, str] = {}  # last output produced by each agent

    def run_agent(agent_id: str, incoming: str, depth: int = 0) -> str:
        if depth > 32:
            log(f"{YELLOW}[guard] max delegation depth reached at {agent_id}{RESET}")
            return incoming
        agent = agents[agent_id]
        label = agent.get("label", agent_id)
        provider = providers.get(agent.get("provider"))
        model = agent.get("model") or (provider or {}).get("models", [None])[0] or "gpt-4o-mini"
        backend = (provider or {}).get("kind", "mock")
        step(f"agent '{label}' ({backend}:{model}) receives message")

        context_parts = [incoming]
        for res, _edge in attachments.get(agent_id, []):
            context_parts.append(resource_value(res, res["type"]))
        user_input = "\n".join(context_parts)

        m = mal(agent)
        if m and m.get("attack") == "prompt-injection":
            attacks.append({"element": agent_id, "type": "prompt-injection"})
            attack(f"agent '{label}' compromised -> injected directive appended")
            user_input += f"\n\n[INJECTED]: {m.get('payload', '')}"

        system = agent.get("prompt") or f"You are {agent.get('role', label)}."
        output = call_llm(
            provider, model, system, user_input,
            agent.get("temperature"), agent.get("max_tokens"),
        )
        outputs[agent_id] = output
        log(f"{GREY}    -> {output}{RESET}")

        final = output
        for e in channels.get(agent_id, []):
            msg = output
            em = mal(e)
            if em and em.get("attack") == "aitm":
                attacks.append({"element": e["id"], "type": "aitm"})
                attack(f"channel {agent_id} -> {e['target']} intercepted (AiTM) -> "
                       f"message rewritten to: {em.get('payload', '')!r}")
                msg = em.get("payload", "")
            if e["target"] in visited:
                continue
            visited.add(e["target"])
            final = run_agent(e["target"], msg, depth + 1)
        return final

    # Entry agents come from entrance nodes (or the deprecated entry flag); fall
    # back to agents with no incoming channel.
    entries = list(dict.fromkeys(
        list(entry_from_io) + [i for i, n in agents.items() if n.get("entry")]
    ))
    if not entries:
        targets = {e["target"] for e in edges
                   if nodes.get(e["source"], {}).get("type") == "agent"
                   and nodes.get(e["target"], {}).get("type") == "agent"}
        entries = [i for i in agents if i not in targets] or list(agents)[:1]

    last = ""
    for entry in entries:
        visited.add(entry)
        last = run_agent(entry, task)

    # The final answer is the exit agent's output (from an exit node, or the
    # deprecated exit flag); fall back to the last reached agent.
    exits = list(dict.fromkeys(
        list(exit_from_io) + [i for i, n in agents.items() if n.get("exit")]
    ))
    if exits:
        final_answer = "\n".join(outputs.get(i, "") for i in exits if i in outputs) or last
    else:
        final_answer = last

    log("=" * 64)
    if exits:
        names = ", ".join(agents[i].get("label", i) for i in exits)
        log(f"{GREY}exit agent(s): {names}{RESET}")
    log(f"{BOLD}final answer:{RESET} {GREEN}{final_answer}{RESET}")
    if attacks:
        log(f"{RED}{BOLD}{len(attacks)} attack(s) fired during execution.{RESET}")
    else:
        log(f"{GREY}no malicious elements triggered.{RESET}")

    result = {
        "name": arch.get("name"),
        "final_answer": final_answer,
        "attacks": attacks,
        "attack_count": len(attacks),
        "agents": len(agents),
    }
    print("__RESULT__ " + json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
