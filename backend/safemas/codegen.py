"""Generate SafeMAS DSL source from an architecture dict, and read it back.

The architecture dict is the editor's wire format (the shape of
``schema.Architecture``): ``{name, task, group?, title?, nodes[], edges[]}`` with
structural ``entrance``/``exit`` nodes joined to agents by ``io`` edges.

``arch_to_code`` emits a clean native-LangGraph ``StateGraph`` script;
``code_to_arch`` executes such a file (building the graph without running it) and
serialises it back to a dict. Together they let the visual editor and the
runtime treat *code* as the source of truth, while the runtime keeps consuming
the dict.
"""
from __future__ import annotations

from typing import Any


def _pos(node: dict) -> str:
    p = node.get("position") or {}
    return f"({round(p.get('x', 0))}, {round(p.get('y', 0))})"


def _kw(name: str, value: Any) -> str | None:
    """Render one keyword argument, or None if it should be omitted (default)."""
    if value in (None, "", [], {}):
        return None
    return f"{name}={value!r}"


def arch_to_code(arch: dict) -> str:
    """Emit a native ``StateGraph`` script for an architecture dict.

    Nodes are addressed by label (the graph's address space). Agents are emitted
    before memory/tool resources so the runtime's slug ordering is preserved;
    channels keep their original order so a router's first-match branch is exact.
    """
    nodes = arch.get("nodes", [])
    edges = arch.get("edges", [])
    by_id = {n["id"]: n for n in nodes}

    agents = [n for n in nodes if n.get("type") == "agent"]
    memories = [n for n in nodes if n.get("type") == "memory"]
    tools = [n for n in nodes if n.get("type") == "tool"]
    label = {n["id"]: (n.get("label") or "") for n in [*agents, *memories, *tools]}

    L: list[str] = ["from safemas import StateGraph", ""]
    head = [repr(arch.get("name", "untitled-mas"))]
    head.append(f"task={arch.get('task', 'Solve the assigned task.')!r}")
    for extra in ("group", "title"):
        if arch.get(extra):
            head.append(f"{extra}={arch[extra]!r}")
    L.append(f"g = StateGraph({', '.join(head)})")

    def node_line(node: dict, type_kw: str | None, extra: list[str | None]) -> str:
        parts = [repr(node.get("label") or "")]
        if type_kw:
            parts.append(f"type={type_kw!r}")
        parts += [k for k in extra if k]
        parts.append(f"at={_pos(node)}")
        return f"g.add_node({', '.join(parts)})"

    if agents:
        L.append("")
        L.append("# agents")
        for n in agents:
            L.append(node_line(n, None, [
                _kw("role", n.get("role")),
                _kw("prompt", n.get("prompt")),
                _kw("provider", n.get("provider")),
                _kw("model", n.get("model")),
                _kw("temperature", n.get("temperature")),
                _kw("max_tokens", n.get("max_tokens")),
                _kw("join", n.get("join")) if n.get("join") not in (None, "", "any") else None,
                _kw("group", n.get("group")),
            ]))
    if memories or tools:
        L.append("")
        L.append("# resources")
        for n in memories:
            L.append(node_line(n, "memory", [_kw("backend", n.get("backend")),
                                             _kw("content", n.get("content"))]))
        for n in tools:
            L.append(node_line(n, "tool", [_kw("spec", n.get("spec")),
                                           _kw("content", n.get("content"))]))

    channels = [e for e in edges if e.get("kind") == "channel"]
    attaches = [e for e in edges if e.get("kind") == "attach"]
    evil_channels: list[dict] = []
    if channels or attaches:
        L.append("")
        L.append("# edges")
        for e in channels:
            if e["source"] not in label or e["target"] not in label:
                continue
            args = [repr(label[e["source"]]), repr(label[e["target"]])]
            if e.get("label"):
                args.append(f"label={e['label']!r}")
            conditional = bool(e.get("when") or e.get("loop"))
            if e.get("when"):
                args.append(f"when={e['when']!r}")
            if e.get("loop"):
                args.append("loop=True")
            if e.get("max_iters") is not None:
                args.append(f"max_iters={int(e['max_iters'])}")
            if e.get("until"):
                args.append(f"until={e['until']!r}")
            call = "add_conditional_edge" if conditional else "add_edge"
            L.append(f"g.{call}({', '.join(args)})")
            if (e.get("malicious") or {}).get("enabled"):
                evil_channels.append(e)
        for e in attaches:
            # canonical attach is resource -> agent; tolerate a reversed edge.
            res, agent = e["source"], e["target"]
            if by_id.get(res, {}).get("type") == "agent":
                res, agent = agent, res
            if res in label and agent in label:
                L.append(f"g.add_edge({label[res]!r}, {label[agent]!r})")

    # adversarial elements: malicious nodes, then malicious channels (by endpoints)
    evil_nodes = [n for n in [*agents, *memories, *tools]
                  if (n.get("malicious") or {}).get("enabled")]
    if evil_nodes or evil_channels:
        L.append("")
        L.append("# adversarial")
        for n in evil_nodes:
            payload = (n.get("malicious") or {}).get("payload", "")
            L.append(f"g.compromise({n.get('label') or ''!r}, {payload!r})")
        for e in evil_channels:
            payload = (e.get("malicious") or {}).get("payload", "")
            L.append(f"g.compromise({label[e['source']]!r}, to={label[e['target']]!r}, "
                     f"payload={payload!r})")

    # entry / exit (from structural nodes + io edges; fall back to legacy flags)
    entrance = next((n for n in nodes if n.get("type") == "entrance"), None)
    exit_node = next((n for n in nodes if n.get("type") == "exit"), None)
    entry_ids = [e["target"] for e in edges
                 if e.get("kind") == "io" and by_id.get(e["source"], {}).get("type") == "entrance"]
    exit_ids = [e["source"] for e in edges
                if e.get("kind") == "io" and by_id.get(e["target"], {}).get("type") == "exit"]
    entry_ids = entry_ids or [n["id"] for n in agents if n.get("entry")]
    exit_ids = exit_ids or [n["id"] for n in agents if n.get("exit")]

    L.append("")
    L.append("# entry / exit")
    if entry_ids:
        args = [repr(label[i]) for i in entry_ids if i in label]
        if entrance:
            args.append(f"at={_pos(entrance)}")
        L.append(f"g.set_entry({', '.join(args)})")
    if exit_ids:
        args = [repr(label[i]) for i in exit_ids if i in label]
        if exit_node:
            args.append(f"at={_pos(exit_node)}")
        L.append(f"g.set_finish({', '.join(args)})")

    L.append("")
    return "\n".join(L)


def _default_io_pos(agents: list, side: str) -> tuple[float, float]:
    if not agents:
        return (-160, 160) if side == "entry" else (560, 160)
    xs = [a.x for a in agents]
    ys = [a.y for a in agents]
    avg_y = sum(ys) / len(ys)
    return (min(xs) - 220, avg_y) if side == "entry" else (max(xs) + 220, avg_y)


def mas_to_arch(mas) -> dict:
    """Serialise a built MAS to the editor's architecture dict (adds the
    structural entrance/exit nodes + io edges the canvas needs)."""
    nodes: list[dict] = []
    edges: list[dict] = []

    def mal(el) -> dict:
        m = el.malicious
        return {"enabled": m.enabled, "attack": m.attack, "payload": m.payload}

    entry_at = mas.entry_at or _default_io_pos(mas.entries or mas.agents, "entry")
    exit_at = mas.exit_at or _default_io_pos(mas.exits or mas.agents, "exit")
    nodes.append({"id": "in-1", "type": "entrance", "label": "Entrance",
                  "position": {"x": entry_at[0], "y": entry_at[1]}})

    for a in mas.agents:
        nodes.append({
            "id": a.id, "type": "agent", "label": a.label,
            "position": {"x": a.x, "y": a.y},
            "provider": a.provider, "model": a.model, "role": a.role,
            "prompt": a.prompt, "temperature": a.temperature,
            "max_tokens": a.max_tokens, "join": getattr(a, "join", "any"),
            "group": getattr(a, "group", None),
            "malicious": mal(a),
        })
    for m in mas.memories:
        nodes.append({"id": m.id, "type": "memory", "label": m.label,
                      "position": {"x": m.x, "y": m.y},
                      "backend": m.backend, "content": getattr(m, "content", ""),
                      "malicious": mal(m)})
    for t in mas.tools:
        nodes.append({"id": t.id, "type": "tool", "label": t.label,
                      "position": {"x": t.x, "y": t.y},
                      "spec": t.spec, "content": getattr(t, "content", ""),
                      "malicious": mal(t)})

    nodes.append({"id": "out-1", "type": "exit", "label": "Exit",
                  "position": {"x": exit_at[0], "y": exit_at[1]}})

    n = 0

    def eid() -> str:
        nonlocal n
        n += 1
        return f"e{n}"

    for i, a in enumerate(mas.entries):
        edges.append({"id": f"io-in-{i + 1}", "source": "in-1", "target": a.id, "kind": "io"})
    for ch in mas.channels:
        edges.append({"id": eid(), "source": ch.src.id, "target": ch.tgt.id,
                      "kind": "channel", "label": ch.label, "loop": ch.loop,
                      "when": getattr(ch, "when", ""),
                      "max_iters": getattr(ch, "max_iters", None),
                      "until": getattr(ch, "until", ""),
                      "malicious": mal(ch)})
    for att in mas.attachments:
        edges.append({"id": eid(), "source": att.resource.id, "target": att.agent.id,
                      "kind": "attach"})
    for i, a in enumerate(mas.exits):
        edges.append({"id": f"io-out-{i + 1}", "source": a.id, "target": "out-1", "kind": "io"})

    return {
        "name": mas.name, "version": 1, "task": mas.task,
        "group": mas.group, "title": mas.title,
        "nodes": nodes, "edges": edges,
    }


# Builders are the only names a template/config file legitimately needs. We run
# user code through ``exec`` (this is a local single-user tool — the same trust
# boundary as the rest of the backend), but keep the namespace tight as a guard
# rail: no ``open``/``os``/``eval`` reachable through injected globals. A curated
# ``__builtins__`` still lets templates use plain literals and the odd helper.
_SAFE_BUILTINS = {
    k: getattr(__builtins__, k, None) if not isinstance(__builtins__, dict)
    else __builtins__.get(k)
    for k in (
        "True", "False", "None", "len", "range", "min", "max", "sum", "sorted",
        "list", "dict", "tuple", "set", "str", "int", "float", "bool",
        "enumerate", "zip", "round", "abs", "print", "__import__",
    )
}


def code_to_mas(src: str):
    """Execute DSL source and return the built graph's MAS (without running it)."""
    from .model import MAS as _MAS, StateGraph as _SG

    g: dict[str, Any] = {"__name__": "__safemas_loaded__", "__builtins__": _SAFE_BUILTINS}
    try:
        exec(compile(src, "architecture.py", "exec"), g)
    except Exception as exc:  # surface a clean message to the API layer
        raise ValueError(f"could not load architecture code: {exc}") from exc

    # Prefer the conventional `g = StateGraph(...)`, then any builder instance.
    obj = g.get("g") or g.get("mas")
    if not isinstance(obj, (_SG, _MAS)):
        obj = next((v for v in g.values() if isinstance(v, (_SG, _MAS))), None)
    if obj is None:
        raise ValueError("no graph defined (expected a `g = StateGraph(...)`)")
    return obj.mas if isinstance(obj, _SG) else obj


def code_to_arch(src: str) -> dict:
    return mas_to_arch(code_to_mas(src))
