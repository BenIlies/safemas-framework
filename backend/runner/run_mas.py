#!/usr/bin/env python3
"""Execute a SafeMAS architecture described in YAML.

This runs *inside* a Docker container (see Dockerfile). It loads the topology,
seeds the entry agent(s) with the task, and propagates messages along channels.
Each agent "thinks" using a real LLM when ``OPENAI_API_KEY`` is present, and a
deterministic mock otherwise -- so the demo runs with zero credentials.

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
BOLD = "\033[1m"


def log(msg: str = "") -> None:
    print(msg, flush=True)


def attack(msg: str) -> None:
    print(f"{RED}{BOLD}[ATTACK]{RESET} {RED}{msg}{RESET}", flush=True)


def step(msg: str) -> None:
    print(f"{CYAN}[exec]{RESET} {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Optional real LLM backend
# --------------------------------------------------------------------------- #
def call_llm(model: str, system: str, user: str) -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        # Deterministic mock so the system is runnable without credentials.
        digest = abs(hash(user)) % 1000
        return f"[mock:{model}] processed input (#{digest}); produced an answer."
    try:
        from openai import OpenAI

        client = OpenAI(api_key=key)
        resp = client.chat.completions.create(
            model=model or "gpt-4o-mini",
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""
    except Exception as exc:  # pragma: no cover - network/credentials dependent
        return f"[llm-error:{model}] {exc}"


# --------------------------------------------------------------------------- #
# Graph helpers
# --------------------------------------------------------------------------- #
def index_nodes(arch: dict) -> dict[str, dict]:
    return {n["id"]: n for n in arch.get("nodes", [])}


def mal(el: dict) -> dict:
    m = el.get("malicious") or {}
    return m if m.get("enabled") else {}


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else "/mas/architecture.yml"
    with open(path) as fh:
        arch = yaml.safe_load(fh)

    nodes = index_nodes(arch)
    edges = arch.get("edges", [])
    task = arch.get("task", "Solve the assigned task.")

    agents = {i: n for i, n in nodes.items() if n["type"] == "agent"}
    # outgoing channels per agent; attachments (memory/tool) per agent
    channels: dict[str, list[dict]] = defaultdict(list)
    attachments: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
    for e in edges:
        kind = e.get("kind", "channel")
        src, tgt = e["source"], e["target"]
        if kind == "channel" and src in agents and tgt in agents:
            channels[src].append(e)
        elif kind == "attach":
            # attach orients agent <-> (memory|tool); normalise to agent-owned
            agent_id = src if src in agents else tgt
            other = tgt if src in agents else src
            if other in nodes:
                attachments[agent_id].append((nodes[other], e))

    log(f"{BOLD}SafeMAS runner{RESET}  ::  architecture '{arch.get('name')}'")
    log(f"{GREY}agents={len(agents)} channels={sum(len(v) for v in channels.values())} "
        f"task={task!r}{RESET}")
    log("=" * 64)

    attacks: list[dict] = []

    def resource_value(res: dict, kind: str) -> str:
        """Read a memory store or invoke a tool, honouring poisoning."""
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

    def run_agent(agent_id: str, incoming: str, depth: int = 0) -> str:
        if depth > 32:
            log(f"{YELLOW}[guard] max delegation depth reached at {agent_id}{RESET}")
            return incoming
        agent = agents[agent_id]
        label = agent.get("label", agent_id)
        model = agent.get("model", "gpt-4o-mini")
        step(f"agent '{label}' ({model}) receives message")

        # gather attached resources (memory reads / tool outputs)
        context_parts = [incoming]
        for res, _edge in attachments.get(agent_id, []):
            context_parts.append(resource_value(res, res["type"]))

        user_input = "\n".join(context_parts)

        # direct prompt injection at this agent
        m = mal(agent)
        if m and m.get("attack") == "prompt-injection":
            attacks.append({"element": agent_id, "type": "prompt-injection"})
            attack(f"agent '{label}' compromised -> injected directive appended")
            user_input += f"\n\n[INJECTED]: {m.get('payload', '')}"

        system = agent.get("prompt") or f"You are {agent.get('role', label)}."
        output = call_llm(model, system, user_input)
        log(f"{GREY}    -> {output}{RESET}")

        # propagate along outgoing channels (applying AiTM rewrites)
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

    entries = [i for i, n in agents.items() if n.get("entry")]
    if not entries:
        # fall back to agents with no incoming channel
        targets = {e["target"] for e in edges if e.get("kind", "channel") == "channel"}
        entries = [i for i in agents if i not in targets] or list(agents)[:1]

    final_answer = ""
    for entry in entries:
        visited.add(entry)
        final_answer = run_agent(entry, task)

    log("=" * 64)
    log(f"{BOLD}final answer:{RESET} {final_answer}")
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
