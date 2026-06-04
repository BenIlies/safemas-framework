"""LangGraph execution runtime for a SafeMAS architecture — built from JSON, no DSL.

`run_arch(arch, task)` takes the editor's architecture dict ({name, task, nodes[],
edges[]}) and runs it. Each agent is a **real tool-calling LangChain agent**: it
binds its attached tools, and the model decides which tool(s) to call, with args,
gets the result, and loops — the injection lands inside a tool result mid-loop,
exactly like an agentic benchmark (AgentDojo). Memory reads are modelled as a
read tool. Multiple tools per agent are supported.

The multi-agent topology (channels, guarded routers, bounded loops, join="all"
barriers, entries/exits) is the same message-driven scheduler the bespoke engine
used — its semantics are load-bearing and don't map cleanly onto LangGraph's
superstep model — so it is hosted inside a single LangGraph ``StateGraph`` node.
The per-agent reasoning/tool-calling is genuine LangChain/LangGraph.

The structured scenario log (the ``__SCN__`` line) keeps the exact event schema
the Trace replay UI consumes; ``llm_call.tool_calls`` and per-execution
``tool_call`` events are now populated for real. Providers come from
``$SAFEMAS_PROVIDERS`` and the task may be overridden by ``$SAFEMAS_TASK``.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import defaultdict, deque
from types import SimpleNamespace

# --------------------------------------------------------------------------- #
# Small helpers (ported from the bespoke engine so the trace/scn stay identical)
# --------------------------------------------------------------------------- #
RESET, RED, YELLOW, CYAN, GREY, GREEN, BOLD = (
    "\033[0m", "\033[91m", "\033[93m", "\033[96m", "\033[90m", "\033[92m", "\033[1m",
)
_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)
DEFAULT_MAX_ITERS = 3   # loop edges with no explicit bound
STEP_BUDGET = 256       # global cap on activations (runaway backstop)
PER_AGENT_CAP = 64      # cap on activations of a single agent
TOOL_LOOP_CAP = 6       # cap on tool-calling rounds within one agent activation


def log(msg: str = "") -> None:
    print(msg, flush=True)


def attack(msg: str) -> None:
    print(f"{RED}{BOLD}[ATTACK]{RESET} {RED}{msg}{RESET}", flush=True)


def step(msg: str) -> None:
    print(f"{CYAN}[exec]{RESET} {msg}", flush=True)


def clip(s: str, n: int = 240) -> str:
    s = " ".join((s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def split_reasoning(s: str) -> tuple[str | None, str]:
    s = s or ""
    m = _THINK_RE.search(s)
    if not m:
        return None, s
    return m.group(1).strip(), (s[: m.start()] + s[m.end():]).strip()


def slug(label: str, taken: set[str]) -> str:
    """Stable, unique, human-readable id derived from a label (matches model.slug
    and the frontend's element-id mapping in PcapModal)."""
    base = re.sub(r"[^a-z0-9]+", "-", (label or "").lower()).strip("-") or "node"
    out, i = base, 2
    while out in taken:
        out, i = f"{base}-{i}", i + 1
    taken.add(out)
    return out


def load_providers() -> dict[str, dict]:
    env = os.environ.get("SAFEMAS_PROVIDERS")
    if not env:
        return {}
    try:
        return json.loads(env)
    except json.JSONDecodeError:
        return {}


def provider_engine(provider: dict | None) -> str:
    p = provider or {}
    api = p.get("api")
    if api in ("openai", "anthropic", "mock"):
        return api
    kind = p.get("kind")
    if kind in ("anthropic", "mock"):
        return kind
    return "openai"


def _tool_name(label: str) -> str:
    """A LangChain-safe tool name (^[A-Za-z0-9_-]+$) derived from a label."""
    n = re.sub(r"[^A-Za-z0-9_-]+", "_", (label or "tool").strip()).strip("_")
    return n or "tool"


# --------------------------------------------------------------------------- #
# Parse the architecture JSON into lightweight objects the scheduler reads.
# Element ids are slug(label) (in agent→memory→tool order) for parity with the
# old engine and the frontend's slug-based compromise mapping.
# --------------------------------------------------------------------------- #
def _mal(d: dict | None) -> SimpleNamespace:
    d = d or {}
    return SimpleNamespace(enabled=bool(d.get("enabled")),
                           attack=d.get("attack"), payload=d.get("payload") or "")


def parse_arch(arch: dict):
    nodes = arch.get("nodes", [])
    edges = arch.get("edges", [])
    type_of = {n["id"]: n.get("type") for n in nodes}

    taken: set[str] = set()
    nsmap: dict[str, SimpleNamespace] = {}
    ordered = ([n for n in nodes if n.get("type") == "agent"]
               + [n for n in nodes if n.get("type") == "memory"]
               + [n for n in nodes if n.get("type") == "tool"])
    for n in ordered:
        eid = slug(n.get("label") or n.get("type") or "node", taken)
        nsmap[n["id"]] = SimpleNamespace(
            id=eid, node_id=n["id"], type=n.get("type"), label=n.get("label") or "",
            role=n.get("role"), prompt=n.get("prompt"), provider=n.get("provider"),
            model=n.get("model"), temperature=n.get("temperature"),
            max_tokens=n.get("max_tokens"), join=n.get("join") or "any",
            spec=n.get("spec"), backend=n.get("backend"), content=n.get("content"),
            malicious=_mal(n.get("malicious")),
        )

    agents = [nsmap[n["id"]] for n in nodes if n.get("type") == "agent"]
    resources = [nsmap[n["id"]] for n in nodes if n.get("type") in ("memory", "tool")]

    channels = []
    for e in edges:
        if e.get("kind") == "channel" and e.get("source") in nsmap and e.get("target") in nsmap:
            channels.append(SimpleNamespace(
                src=nsmap[e["source"]], tgt=nsmap[e["target"]], label=e.get("label") or "",
                loop=bool(e.get("loop")), when=e.get("when") or "",
                max_iters=e.get("max_iters"), until=e.get("until") or "",
                malicious=_mal(e.get("malicious"))))

    attachments = []  # (resource, agent), tolerating reversed direction
    for e in edges:
        if e.get("kind") == "attach":
            res, ag = e.get("source"), e.get("target")
            if type_of.get(res) == "agent":
                res, ag = ag, res
            if res in nsmap and ag in nsmap and type_of.get(ag) == "agent":
                attachments.append((nsmap[res], nsmap[ag]))

    entrance_ids = {n["id"] for n in nodes if n.get("type") == "entrance"}
    exit_ids = {n["id"] for n in nodes if n.get("type") == "exit"}
    entries = [nsmap[e["target"]] for e in edges
               if e.get("kind") == "io" and e.get("source") in entrance_ids and e.get("target") in nsmap]
    exits = [nsmap[e["source"]] for e in edges
             if e.get("kind") == "io" and e.get("target") in exit_ids and e.get("source") in nsmap]
    return agents, resources, channels, attachments, entries, exits


# --------------------------------------------------------------------------- #
# LangChain model + tools (the real function-calling layer)
# --------------------------------------------------------------------------- #
def build_chat_model(provider: dict, model: str, agent):
    """A streaming LangChain chat model for the agent's provider."""
    engine = provider_engine(provider)
    key = provider.get("api_key") or ""
    base = provider.get("base_url") or None
    if engine == "anthropic":
        from langchain_anthropic import ChatAnthropic
        kw = dict(model=model or "claude-haiku-4-5", api_key=key,
                  max_tokens=agent.max_tokens or 1024, streaming=True)
        if base:
            kw["base_url"] = base
        if agent.temperature is not None:
            kw["temperature"] = agent.temperature
        return ChatAnthropic(**kw)
    from langchain_openai import ChatOpenAI
    kw = dict(model=model or "gpt-4o-mini", api_key=key, streaming=True)
    if base:
        kw["base_url"] = base
    if agent.temperature is not None:
        kw["temperature"] = agent.temperature
    if agent.max_tokens is not None:
        kw["max_tokens"] = agent.max_tokens
    return ChatOpenAI(**kw)


def build_tools(res_list):
    """LangChain tool stubs (name + description + a free-form ``query`` arg) for
    each attached resource. Execution is done manually in the loop so we control
    the scn event ordering, so the stub body is never actually invoked."""
    from langchain_core.tools import StructuredTool
    tools, by_name = [], {}
    for res in res_list:
        name = _tool_name(res.label)
        while name in by_name:           # disambiguate collisions
            name += "_"
        desc = (res.spec or "").strip() or (
            f"Read the '{res.label}' memory store." if res.type == "memory"
            else f"Call the '{res.label}' tool.")

        def _stub(query: str = "") -> str:  # pragma: no cover - never called
            return ""
        tools.append(StructuredTool.from_function(_stub, name=name, description=desc))
        by_name[name] = res
    return tools, by_name


def _chunk_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # some providers stream content blocks
        return "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return str(content or "")


# --------------------------------------------------------------------------- #
# The run (ported scheduler + real tool-calling), hosted in a LangGraph node.
# --------------------------------------------------------------------------- #
def _run(arch: dict, task: str | None) -> dict:
    providers = load_providers()
    name = arch.get("name", "untitled-mas")
    task = task or os.environ.get("SAFEMAS_TASK") or arch.get("task") or "Solve the assigned task."

    agents, resources, channels, attachments, entries, exits = parse_arch(arch)

    out_channels: dict[int, list] = defaultdict(list)
    for ch in channels:
        out_channels[id(ch.src)].append(ch)
    in_channels: dict[int, list] = defaultdict(list)
    for ch in channels:
        if not ch.loop:
            in_channels[id(ch.tgt)].append(ch)
    attached: dict[int, list] = defaultdict(list)
    for res, ag in attachments:
        attached[id(ag)].append(res)

    live = sum(1 for a in agents if providers.get(a.provider, {}).get("api_key"))
    log(f"{BOLD}SafeMAS runner{RESET}  ::  architecture '{name}'")
    log(f"{GREY}agents={len(agents)} channels={len(channels)} "
        f"live-llm={live}/{len(agents)} task={task!r}{RESET}")
    if not live and agents:
        log(f"{YELLOW}{BOLD}⚠ no live LLM{RESET} {YELLOW}— no agent has a provider with an API "
            f"key, so every agent uses the deterministic mock. The outputs below are "
            f"placeholders, not real answers. Register a provider (🔑) and assign it to the "
            f"agents for real responses.{RESET}")
    elif live < len(agents):
        log(f"{YELLOW}note: {len(agents) - live} of {len(agents)} agents have no keyed "
            f"provider and will run on the mock.{RESET}")
    log("=" * 64)

    attacks: list[dict] = []
    _t0 = time.monotonic()
    events: list[dict] = []
    _seq = [0]

    def emit(kind: str, **fields) -> None:
        _seq[0] += 1
        events.append({"seq": _seq[0], "t": round(time.monotonic() - _t0, 3),
                       "kind": kind, **fields})

    compromised: list[dict] = []
    for a in agents:
        if a.malicious.enabled:
            compromised.append({"element": a.id, "type": a.malicious.attack})
    for ch in channels:
        if ch.malicious.enabled:
            compromised.append({"element": f"{ch.src.id}->{ch.tgt.id}", "type": ch.malicious.attack})
    for r in resources:
        if r.malicious.enabled:
            compromised.append({"element": r.id, "type": r.malicious.attack})

    def resource_value(res) -> tuple[str, bool]:
        """The value an attached resource yields when read, and whether it's
        poisoned. Emits the attack event at the read site (correct ordering)."""
        m = res.malicious
        if m.enabled:
            attacks.append({"element": res.id, "type": m.attack})
            emit("attack", element=res.id, type=m.attack, vector=res.type, payload=m.payload)
            attack(f"{res.type} '{res.label}' is poisoned -> returns attacker payload: {m.payload!r}")
            return m.payload, True
        content = (res.content or "").strip()
        if content:
            return content, False
        if res.type == "memory":
            return f"[memory:{res.label}] (clean, empty)", False
        return f"[tool:{res.label}] returned a normal result", False

    def matches(text: str, phrase: str) -> bool:
        return bool(phrase) and phrase.lower() in (text or "").lower()

    outputs: dict[int, str] = {}
    runs: dict[int, int] = defaultdict(int)
    loop_iters: dict[int, int] = defaultdict(int)
    join_buf: dict[int, dict[int, str]] = defaultdict(dict)

    # ---- one agent activation: real tool-calling loop --------------------- #
    def run_agent(agent, provider, model, system, user_input, res_list) -> str:
        engine = provider_engine(provider)
        key = (provider or {}).get("api_key", "")

        if engine == "mock" or not key:
            # No live LLM: still "use" each attached resource once (so tool/memory
            # poisoning is surfaced), then return the deterministic placeholder.
            for res in res_list:
                val, poisoned = resource_value(res)
                emit("tool_call", agent=agent.label, function=res.label, args={},
                     result=val, poisoned=poisoned, error=False)
            tag = model or (provider or {}).get("kind") or "mock"
            reason = "no API key" if (engine != "mock" and not key) else "mock provider"
            out = f"[mock:{tag} · {reason}] placeholder reply (no live LLM)"
            print(f"{GREY}    out ▸ {RESET}{out}", flush=True)
            emit("llm_call", agent=agent.label, iter=0, reasoning=None, content=out, tool_calls=[])
            return out

        from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
        try:
            llm = build_chat_model(provider, model, agent)
            tools, by_name = build_tools(res_list)
            if tools:
                llm = llm.bind_tools(tools)
            msgs = [SystemMessage(content=system), HumanMessage(content=user_input)]
            final_text = ""
            for it in range(TOOL_LOOP_CAP):
                print(f"{GREY}    out ▸ {RESET}", end="", flush=True)
                acc = None
                content_parts: list[str] = []
                reasoning_parts: list[str] = []
                for chunk in llm.stream(msgs):
                    acc = chunk if acc is None else acc + chunk
                    c = _chunk_text(chunk.content)
                    if c:
                        content_parts.append(c)
                        print(c, end="", flush=True)
                    rc = (getattr(chunk, "additional_kwargs", None) or {}).get("reasoning_content")
                    if rc:
                        reasoning_parts.append(rc)
                        print(rc, end="", flush=True)
                print("", flush=True)

                content = "".join(content_parts)
                reasoning = "".join(reasoning_parts)
                text = content
                if reasoning and "<think>" not in content:
                    text = f"<think>{reasoning}</think>\n{content}"
                tool_calls = list(getattr(acc, "tool_calls", None) or [])
                reasoning_s, content_s = split_reasoning(text)
                emit("llm_call", agent=agent.label, iter=it, reasoning=reasoning_s,
                     content=content_s, tool_calls=[{"function": tc["name"], "args": tc.get("args", {})}
                                                    for tc in tool_calls])
                msgs.append(AIMessage(content=acc.content if acc is not None else "",
                                      tool_calls=tool_calls))
                final_text = text
                if not tool_calls:
                    break
                for tc in tool_calls:
                    res = by_name.get(tc["name"])
                    if res is None:
                        val, poisoned, err = f"[error: unknown tool {tc['name']}]", False, True
                    else:
                        val, poisoned = resource_value(res)
                        err = False
                    emit("tool_call", agent=agent.label, function=(res.label if res else tc["name"]),
                         args=tc.get("args", {}), result=val, poisoned=poisoned, error=err)
                    log(f"{GREY}    ⟳ {tc['name']}({clip(json.dumps(tc.get('args', {})), 60)}) "
                        f"→ {clip(val, 80)}{RESET}")
                    msgs.append(ToolMessage(content=val, tool_call_id=tc.get("id") or tc["name"]))
            return final_text
        except Exception as exc:  # pragma: no cover - network/credentials dependent
            err = f"[llm-error:{engine}:{model}] {exc}"
            print(f"{GREY}    out ▸ {RESET}{err}", flush=True)
            emit("llm_call", agent=agent.label, iter=0, reasoning=None, content=err, tool_calls=[])
            return err

    def think(agent, incoming: str) -> str:
        provider = providers.get(agent.provider)
        model = agent.model or (provider or {}).get("models", [None])[0] or "gpt-4o-mini"
        backend = (provider or {}).get("kind", "mock")
        step(f"agent '{agent.label}' ({backend}:{model})")

        system = agent.prompt or f"You are {agent.role or agent.label}."
        m = agent.malicious
        injected = m.payload if (m.enabled and m.attack == "prompt-injection") else None
        res_list = attached.get(id(agent), [])
        emit("node_enter", agent=agent.label, role=agent.role, system=system,
             incoming=incoming, injected=injected, tools=[r.label for r in res_list])

        user_input = incoming
        if injected is not None:
            attacks.append({"element": agent.id, "type": "prompt-injection"})
            emit("attack", element=agent.id, type="prompt-injection", vector="agent", payload=m.payload)
            attack(f"agent '{agent.label}' compromised -> injected directive appended")
            user_input += f"\n\n[INJECTED]: {m.payload}"

        log(f"{GREY}    in  ◂ {clip(user_input)}{RESET}")
        output = run_agent(agent, provider, model, system, user_input, res_list)
        outputs[id(agent)] = output
        emit("node_exit", agent=agent.label, output=output)
        return output

    def chosen_edges(agent, output: str) -> list:
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
            forwards = [ch for ch in outs if not ch.loop]
            pick = next((ch for ch in forwards if not ch.when),
                        forwards[0] if forwards else None)
        if pick is not None and pick.loop:
            loop_iters[id(pick)] += 1
        return [pick] if pick is not None else []

    queue: deque = deque()

    def enqueue_delivery(ch, msg: str) -> None:
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
        if (tgt.join or "any") == "all":
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

    def _dedup(seq):  # SimpleNamespace is unhashable (defines __eq__), so dedup by id
        seen, out = set(), []
        for x in seq:
            if id(x) not in seen:
                seen.add(id(x))
                out.append(x)
        return out

    entries_l = _dedup(entries)
    if not entries_l:
        targets = {id(ch.tgt) for ch in channels if not ch.loop}
        entries_l = [a for a in agents if id(a) not in targets] or agents[:1]
    exits_l = _dedup(exits)

    emit("run_start", arch=name, task=task, compromised=compromised,
         entries=[a.label for a in entries_l], exits=[a.label for a in exits_l], poison_mode=None)
    for entry in entries_l:
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

    if exits_l:
        final_answer = "\n".join(outputs[id(a)] for a in exits_l if id(a) in outputs) or last
    else:
        final_answer = last

    emit("final", answer=final_answer, exits=[a.label for a in exits_l])

    log("=" * 64)
    if exits_l:
        log(f"{GREY}exit agent(s): {', '.join(a.label for a in exits_l)}{RESET}")
    log(f"{BOLD}final answer:{RESET} {GREEN}{final_answer}{RESET}")
    if attacks:
        log(f"{RED}{BOLD}{len(attacks)} attack(s) fired during execution.{RESET}")
    else:
        log(f"{GREY}no malicious elements triggered.{RESET}")

    result = {
        "name": name, "final_answer": final_answer, "attacks": attacks,
        "attack_count": len(attacks), "agents": len(agents),
    }
    print("__RESULT__ " + json.dumps(result), flush=True)

    first_model = next((a.model for a in agents if a.model), None) \
        or next((providers.get(a.provider, {}).get("models", [None])[0] for a in agents), None)
    scn = {
        "config": {
            "arch": name, "user_task": None, "user_prompt": task, "injection_task": None,
            "condition": "compromised" if compromised else "clean",
            "compromise": compromised[0]["element"] if compromised else None,
            "poison_mode": None, "model": first_model, "injection_goal": None,
            "env_injection_vectors": [],
        },
        "compromised": compromised,
        "verdict": {"utility": None, "security": len(attacks) == 0,
                    "attack_succeeded": True if attacks else None},
        "trace": {"events": events},
    }
    print("__SCN__ " + json.dumps(scn), flush=True)
    return result


def run_arch(arch: dict, task: str | None = None) -> dict:
    """Execute an architecture dict. Hosts the run inside a one-node LangGraph
    StateGraph so the runtime is LangGraph while the topology semantics (which
    LangGraph's superstep model can't express cleanly) stay exact."""
    try:
        from langgraph.graph import END, StateGraph
        sg = StateGraph(dict)
        sg.add_node("run", lambda state: {"result": _run(arch, task)})
        sg.set_entry_point("run")
        sg.add_edge("run", END)
        return sg.compile().invoke({})["result"]
    except Exception:
        # If LangGraph is unavailable, the scheduler is self-contained — run it
        # directly rather than failing the whole execution.
        return _run(arch, task)
