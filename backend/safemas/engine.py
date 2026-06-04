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
import re
import time
from collections import defaultdict, deque

# Reasoning models (MiniMax-M2, DeepSeek-R1, QwQ, …) wrap their chain-of-thought
# in <think>…</think> inline in the reply. We keep the full text as the agent's
# output, but split the scratchpad out for the structured scenario log so PCAP can
# show "think" and "say" separately (as it does for sa_bridge captures).
_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)


def split_reasoning(s: str) -> tuple[str | None, str]:
    s = s or ""
    m = _THINK_RE.search(s)
    if not m:
        return None, s
    reasoning = m.group(1).strip()
    content = (s[: m.start()] + s[m.end():]).strip()
    return reasoning, content

RESET, RED, YELLOW, CYAN, GREY, GREEN, BOLD = (
    "\033[0m", "\033[91m", "\033[93m", "\033[96m", "\033[90m", "\033[92m", "\033[1m",
)


def log(msg: str = "") -> None:
    print(msg, flush=True)


def attack(msg: str) -> None:
    print(f"{RED}{BOLD}[ATTACK]{RESET} {RED}{msg}{RESET}", flush=True)


def step(msg: str) -> None:
    print(f"{CYAN}[exec]{RESET} {msg}", flush=True)


def clip(s: str, n: int = 240) -> str:
    """One-line, length-capped view of a message for the trace."""
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


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
             temperature: float | None, max_tokens: int | None,
             on_delta=None) -> str:
    """Call the agent's LLM and return its full reply.

    Responses are *streamed*: as each token arrives it is handed to ``on_delta``
    (when provided) so the trace grows live instead of blocking until the whole
    answer — important for reasoning models that emit a long hidden think pass
    before any visible content. The accumulated text is still returned in full.
    """
    engine = provider_engine(provider)
    key = (provider or {}).get("api_key", "")
    base_url = (provider or {}).get("base_url", "") or None

    if engine == "mock" or not key:
        # No live LLM → a short, honest placeholder. The real message flow is
        # visible in the trace via the per-agent `in ◂` / `out ▸` lines (the
        # incoming message is logged in full-ish there, injected payloads included);
        # the placeholder deliberately does not echo it, to avoid nesting it across
        # every hop. Register a keyed provider for real responses.
        tag = model or (provider or {}).get("kind") or "mock"
        reason = "no API key" if (engine != "mock" and not key) else "mock provider"
        out = f"[mock:{tag} · {reason}] placeholder reply (no live LLM)"
        if on_delta:
            on_delta(out)
        return out

    try:
        if engine == "anthropic":
            import anthropic

            client = anthropic.Anthropic(api_key=key, base_url=base_url)
            with client.messages.stream(
                model=model or "claude-haiku-4-5",
                system=system,
                max_tokens=max_tokens or 1024,
                temperature=temperature if temperature is not None else 1.0,
                messages=[{"role": "user", "content": user}],
            ) as stream:
                parts = []
                for piece in stream.text_stream:
                    parts.append(piece)
                    if on_delta:
                        on_delta(piece)
                return "".join(parts)

        from openai import OpenAI

        client = OpenAI(api_key=key, base_url=base_url)
        kwargs: dict = {
            "model": model or "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": True,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        content_parts: list[str] = []
        reasoning_parts: list[str] = []
        for chunk in client.chat.completions.create(**kwargs):
            if not chunk.choices:
                continue
            d = chunk.choices[0].delta
            # Some OpenAI-compatible reasoning endpoints stream the think pass in a
            # separate `reasoning_content` channel rather than inline <think> tags.
            rc = getattr(d, "reasoning_content", None)
            if rc:
                reasoning_parts.append(rc)
                if on_delta:
                    on_delta(rc)
            c = getattr(d, "content", None)
            if c:
                content_parts.append(c)
                if on_delta:
                    on_delta(c)
        content = "".join(content_parts)
        reasoning = "".join(reasoning_parts)
        # Fold a separate reasoning channel back into the returned text as a
        # <think> block so the rest of the pipeline (and the scn log) see it.
        if reasoning and "<think>" not in content:
            content = f"<think>{reasoning}</think>\n{content}"
        return content
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
    if not live and mas.agents:
        log(f"{YELLOW}{BOLD}⚠ no live LLM{RESET} {YELLOW}— no agent has a provider with an API "
            f"key, so every agent uses the deterministic mock. The outputs below are "
            f"placeholders, not real answers (the messages each agent sends/receives are "
            f"still shown). Register a provider (🔑) and assign it to the agents for real "
            f"responses.{RESET}")
    elif live < len(mas.agents):
        log(f"{YELLOW}note: {len(mas.agents) - live} of {len(mas.agents)} agents have no "
            f"keyed provider and will run on the mock.{RESET}")
    log("=" * 64)

    attacks: list[dict] = []

    # ---- structured scenario log (consumed by the PCAP analyzer) -------------
    # Mirrors the sa_bridge scn_*.json shape: a timed, sequenced event stream the
    # frontend replays as flow + per-node internals. Emitted as one __SCN__ line.
    _t0 = time.monotonic()
    events: list[dict] = []
    _seq = [0]

    def emit(kind: str, **fields) -> None:
        _seq[0] += 1
        events.append({"seq": _seq[0], "t": round(time.monotonic() - _t0, 3),
                       "kind": kind, **fields})

    # Configured-adversarial elements (known up front, before anything fires).
    compromised: list[dict] = []
    for _a in mas.agents:
        if _a.malicious.enabled:
            compromised.append({"element": _a.id, "type": _a.malicious.attack})
    for _ch in mas.channels:
        if _ch.malicious.enabled:
            compromised.append({"element": f"{_ch.src.id}->{_ch.tgt.id}",
                                "type": _ch.malicious.attack})
    for _att in mas.attachments:
        _r = _att.resource
        if getattr(_r, "malicious", None) and _r.malicious.enabled:
            compromised.append({"element": _r.id, "type": _r.malicious.attack})

    def resource_value(res) -> str:
        kind = "memory" if hasattr(res, "backend") else "tool"
        m = res.malicious
        if m.enabled:
            attacks.append({"element": res.id, "type": m.attack})
            emit("attack", element=res.id, type=m.attack, vector=kind, payload=m.payload)
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
        step(f"agent '{agent.label}' ({backend}:{model})")

        system = agent.prompt or f"You are {agent.role or agent.label}."
        m = agent.malicious
        injected = m.payload if (m.enabled and m.attack == "prompt-injection") else None
        res_list = attached.get(id(agent), [])
        emit("node_enter", agent=agent.label, role=getattr(agent, "role", None),
             system=system, incoming=incoming, injected=injected,
             tools=[getattr(r, "label", "") for r in res_list])

        parts = [incoming]
        for res in res_list:
            val = resource_value(res)
            parts.append(val)
            emit("tool_call", agent=agent.label, function=getattr(res, "label", ""),
                 args={}, result=val, poisoned=res.malicious.enabled, error=False)
        user_input = "\n".join(parts)

        if injected is not None:
            attacks.append({"element": agent.id, "type": "prompt-injection"})
            emit("attack", element=agent.id, type="prompt-injection",
                 vector="agent", payload=m.payload)
            attack(f"agent '{agent.label}' compromised -> injected directive appended")
            user_input += f"\n\n[INJECTED]: {m.payload}"

        log(f"{GREY}    in  ◂ {clip(user_input)}{RESET}")
        # Stream the reply live so the trace fills in token-by-token instead of
        # blocking on the whole (often long) reasoning pass.
        print(f"{GREY}    out ▸ {RESET}", end="", flush=True)
        output = call_llm(provider, model, system, user_input,
                          agent.temperature, agent.max_tokens,
                          on_delta=lambda piece: print(piece, end="", flush=True))
        print("", flush=True)  # close the streamed line
        outputs[id(agent)] = output
        reasoning, content = split_reasoning(output)
        emit("llm_call", agent=agent.label, iter=runs[id(agent)] - 1,
             reasoning=reasoning, content=content, tool_calls=[])
        emit("node_exit", agent=agent.label, output=output)
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
        original = None
        aitm = bool(cm.enabled and cm.attack == "aitm")
        if aitm:
            attacks.append({"element": f"{ch.src.id}->{ch.tgt.id}", "type": "aitm"})
            emit("attack", element=f"{ch.src.id}->{ch.tgt.id}", type="aitm",
                 vector="channel", payload=cm.payload)
            attack(f"channel {ch.src.label} -> {ch.tgt.label} intercepted (AiTM) "
                   f"-> message rewritten to: {cm.payload!r}")
            original, msg = msg, cm.payload
        emit("channel", src=ch.src.label, tgt=ch.tgt.label, label=ch.label or "",
             message=msg, aitm=aitm, original=original)
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

    exits = list(dict.fromkeys(mas.exits))
    emit("run_start", arch=mas.name, task=task, compromised=compromised,
         entries=[a.label for a in entries], exits=[a.label for a in exits],
         poison_mode=None)
    for entry in entries:
        emit("seed", agent=entry.label, message=task)
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

    if exits:
        final_answer = "\n".join(
            outputs[id(a)] for a in exits if id(a) in outputs
        ) or last
    else:
        final_answer = last

    emit("final", answer=final_answer, exits=[a.label for a in exits])

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

    first_model = next((a.model for a in mas.agents if a.model), None) \
        or next((providers.get(a.provider, {}).get("models", [None])[0]
                 for a in mas.agents), None)
    scn = {
        "config": {
            "arch": mas.name,
            "user_task": None,
            "user_prompt": task,
            "injection_task": None,
            "condition": "compromised" if compromised else "clean",
            "compromise": compromised[0]["element"] if compromised else None,
            "poison_mode": None,
            "model": first_model,
            "injection_goal": None,
            "env_injection_vectors": [],
        },
        "compromised": compromised,
        "verdict": {
            "utility": None,
            "security": len(attacks) == 0,
            "attack_succeeded": True if attacks else None,
        },
        "trace": {"events": events},
    }
    print("__SCN__ " + json.dumps(scn), flush=True)
    return result
