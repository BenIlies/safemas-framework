"""Execution engine for a :class:`safemas.MAS`.

Seeds the entry agent(s) with the task and propagates messages along channels;
each agent "thinks" with a real LLM when its provider has a key, and a
deterministic mock otherwise (so a MAS runs with zero credentials). Adversarial
elements alter execution and are loudly logged as ``[ATTACK]`` events.

Resolved providers are read from ``$SAFEMAS_PROVIDERS`` (JSON: ``{id: {api, kind,
base_url, api_key, models}}``) so credentials never live in the code. The task may
be overridden with ``$SAFEMAS_TASK``.

A human-readable trace is printed to stdout; the final line, prefixed
``__RESULT__ ``, is a machine-readable JSON summary the backend parses.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict, deque

RESET, RED, YELLOW, CYAN, GREY, GREEN, BOLD = (
    "\033[0m", "\033[91m", "\033[93m", "\033[96m", "\033[90m", "\033[92m", "\033[1m",
)


def log(msg: str = "") -> None:
    print(msg, flush=True)


def attack(msg: str) -> None:
    print(f"{RED}{BOLD}[ATTACK]{RESET} {RED}{msg}{RESET}", flush=True)


def step(msg: str) -> None:
    print(f"{CYAN}[exec]{RESET} {msg}", flush=True)


def load_providers() -> dict[str, dict]:
    env = os.environ.get("SAFEMAS_PROVIDERS")
    if not env:
        return {}
    try:
        return json.loads(env)
    except json.JSONDecodeError:
        return {}


def provider_engine(provider: dict | None) -> str:
    """Client engine for a provider: 'anthropic', 'mock', or 'openai' (the latter
    also covers every OpenAI-compatible endpoint via base_url)."""
    p = provider or {}
    api = p.get("api")
    if api in ("openai", "anthropic", "mock"):
        return api
    kind = p.get("kind")
    if kind in ("anthropic", "mock"):
        return kind
    return "openai"


def call_llm(provider: dict | None, model: str, system: str, user: str,
             temperature: float | None, max_tokens: int | None) -> str:
    engine = provider_engine(provider)
    key = (provider or {}).get("api_key", "")
    base_url = (provider or {}).get("base_url", "") or None

    if engine == "mock" or not key:
        digest = abs(hash(user)) % 1000
        tag = model or (provider or {}).get("kind") or "mock"
        return f"[mock:{tag}] processed input (#{digest}); produced an answer."

    try:
        if engine == "anthropic":
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
        return f"[llm-error:{engine}:{model}] {exc}"


def run_mas(mas, task: str | None = None) -> dict:
    """Execute ``mas``. Returns (and prints) the machine-readable result dict."""
    providers = load_providers()
    task = task or os.environ.get("SAFEMAS_TASK") or mas.task

    # channels out of / attachments onto each agent (by object identity)
    out_channels: dict[int, list] = defaultdict(list)
    for ch in mas.channels:
        out_channels[id(ch.src)].append(ch)
    attached: dict[int, list] = defaultdict(list)
    for att in mas.attachments:
        attached[id(att.agent)].append(att.resource)

    live = sum(1 for a in mas.agents
               if providers.get(a.provider, {}).get("api_key"))
    log(f"{BOLD}SafeMAS runner{RESET}  ::  architecture '{mas.name}'")
    log(f"{GREY}agents={len(mas.agents)} channels={len(mas.channels)} "
        f"live-llm={live}/{len(mas.agents)} task={task!r}{RESET}")
    log("=" * 64)

    attacks: list[dict] = []

    def resource_value(res) -> str:
        kind = "memory" if hasattr(res, "backend") else "tool"
        m = res.malicious
        if m.enabled:
            attacks.append({"element": res.id, "type": m.attack})
            attack(f"{kind} '{res.label}' is poisoned -> returns attacker "
                   f"payload: {m.payload!r}")
            return m.payload
        if kind == "memory":
            return f"[memory:{res.label}] (clean, empty)"
        return f"[tool:{res.label}] returned a normal result"

    # ---- control-flow execution (message-driven scheduler) -------------------
    # The system runs as a work queue of (agent, message) activations rather than
    # a one-pass DFS, so the constructs the canvas draws are real: loop edges
    # actually re-run their target (bounded), routers select one branch by guard,
    # and join="all" agents wait for every inbound channel and aggregate them.
    DEFAULT_MAX_ITERS = 3   # loop edges with no explicit bound
    STEP_BUDGET = 256       # global cap on activations (runaway backstop)
    PER_AGENT_CAP = 64      # cap on activations of a single agent

    def matches(text: str, phrase: str) -> bool:
        return bool(phrase) and phrase.lower() in (text or "").lower()

    # Inbound forward (non-loop) channels per agent — what a join="all" waits for.
    in_channels: dict[int, list] = defaultdict(list)
    for ch in mas.channels:
        if not ch.loop:
            in_channels[id(ch.tgt)].append(ch)

    outputs: dict[int, str] = {}
    runs: dict[int, int] = defaultdict(int)         # activations per agent
    loop_iters: dict[int, int] = defaultdict(int)   # firings per loop edge
    join_buf: dict[int, dict[int, str]] = defaultdict(dict)  # join="all" inboxes

    def think(agent, incoming: str) -> str:
        """One activation of an agent on ``incoming``; returns its output."""
        provider = providers.get(agent.provider)
        model = agent.model or (provider or {}).get("models", [None])[0] or "gpt-4o-mini"
        backend = (provider or {}).get("kind", "mock")
        step(f"agent '{agent.label}' ({backend}:{model}) receives message")

        parts = [incoming]
        for res in attached.get(id(agent), []):
            parts.append(resource_value(res))
        user_input = "\n".join(parts)

        m = agent.malicious
        if m.enabled and m.attack == "prompt-injection":
            attacks.append({"element": agent.id, "type": "prompt-injection"})
            attack(f"agent '{agent.label}' compromised -> injected directive appended")
            user_input += f"\n\n[INJECTED]: {m.payload}"

        system = agent.prompt or f"You are {agent.role or agent.label}."
        output = call_llm(provider, model, system, user_input,
                          agent.temperature, agent.max_tokens)
        outputs[id(agent)] = output
        log(f"{GREY}    -> {output}{RESET}")
        return output

    def chosen_edges(agent, output: str) -> list:
        """Which outgoing channels fire after ``agent`` produced ``output``.

        A node with guarded or loop out-edges *selects* the first takeable edge
        (router / bounded loop, ordered like xstate transitions); any other node
        *broadcasts* to every out-edge (fan-out / parallel)."""
        outs = out_channels.get(id(agent), [])
        if not outs:
            return []
        if not any(ch.when or ch.loop for ch in outs):
            return outs  # broadcast

        def takeable(ch) -> bool:
            if ch.loop:
                cap = ch.max_iters if ch.max_iters is not None else DEFAULT_MAX_ITERS
                return loop_iters[id(ch)] < cap and not matches(output, ch.until)
            return (not ch.when) or matches(output, ch.when)

        pick = next((ch for ch in outs if takeable(ch)), None)
        if pick is None:
            # guards all failed / loops exhausted → fall through to a default
            # forward edge so a router still picks a branch (and a finished loop
            # hands off downstream); if only spent loops remain, the path ends.
            forwards = [ch for ch in outs if not ch.loop]
            pick = next((ch for ch in forwards if not ch.when),
                        forwards[0] if forwards else None)
        if pick is not None and pick.loop:
            loop_iters[id(pick)] += 1
        return [pick] if pick is not None else []

    queue: deque = deque()

    def enqueue_delivery(ch, msg: str) -> None:
        """Send a message along channel ``ch`` (applying any AiTM rewrite), gating
        on the target's join policy."""
        cm = ch.malicious
        if cm.enabled and cm.attack == "aitm":
            attacks.append({"element": f"{ch.src.id}->{ch.tgt.id}", "type": "aitm"})
            attack(f"channel {ch.src.label} -> {ch.tgt.label} intercepted (AiTM) "
                   f"-> message rewritten to: {cm.payload!r}")
            msg = cm.payload
        tgt = ch.tgt
        if (getattr(tgt, "join", "any") or "any") == "all":
            needed = in_channels.get(id(tgt), [])
            buf = join_buf[id(tgt)]
            buf[id(ch)] = msg
            if needed and all(id(c) in buf for c in needed):
                agg = "\n\n".join(buf[id(c)] for c in needed)
                join_buf[id(tgt)] = {}
                queue.append((tgt, agg))
            else:
                waiting = len(needed) - len(buf)
                log(f"{GREY}    … '{tgt.label}' joins, waiting for {waiting} more input(s){RESET}")
        else:
            queue.append((tgt, msg))

    # Entry agents: declared, else agents with no inbound channel, else the first.
    entries = list(dict.fromkeys(mas.entries))
    if not entries:
        targets = {id(ch.tgt) for ch in mas.channels if not ch.loop}
        entries = [a for a in mas.agents if id(a) not in targets] or mas.agents[:1]
    for entry in entries:
        queue.append((entry, task))

    steps = 0
    last = ""
    while queue:
        if steps >= STEP_BUDGET:
            log(f"{YELLOW}[guard] step budget ({STEP_BUDGET}) reached — stopping run{RESET}")
            break
        agent, incoming = queue.popleft()
        if runs[id(agent)] >= PER_AGENT_CAP:
            log(f"{YELLOW}[guard] '{agent.label}' hit per-agent activation cap{RESET}")
            continue
        runs[id(agent)] += 1
        steps += 1
        last = think(agent, incoming)
        for ch in chosen_edges(agent, last):
            enqueue_delivery(ch, last)

    exits = list(dict.fromkeys(mas.exits))
    if exits:
        final_answer = "\n".join(
            outputs[id(a)] for a in exits if id(a) in outputs
        ) or last
    else:
        final_answer = last

    log("=" * 64)
    if exits:
        log(f"{GREY}exit agent(s): {', '.join(a.label for a in exits)}{RESET}")
    log(f"{BOLD}final answer:{RESET} {GREEN}{final_answer}{RESET}")
    if attacks:
        log(f"{RED}{BOLD}{len(attacks)} attack(s) fired during execution.{RESET}")
    else:
        log(f"{GREY}no malicious elements triggered.{RESET}")

    result = {
        "name": mas.name,
        "final_answer": final_answer,
        "attacks": attacks,
        "attack_count": len(attacks),
        "agents": len(mas.agents),
    }
    print("__RESULT__ " + json.dumps(result), flush=True)
    return result
