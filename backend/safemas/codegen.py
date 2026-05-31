"""Generate SafeMAS DSL source from an architecture dict, and read it back.

The architecture dict is the editor's wire format (the shape of
``schema.Architecture``): ``{name, task, group?, title?, nodes[], edges[]}`` with
structural ``entrance``/``exit`` nodes joined to agents by ``io`` edges.

``arch_to_code`` emits a clean, self-executing ``.py``; ``code_to_arch`` executes
such a file (building the MAS without running it) and serialises it back to a
dict. Together they let the visual editor treat *code* as the source of truth.
"""
from __future__ import annotations

import keyword
import re
from typing import Any

_KW = set(keyword.kwlist)


def _ident(label: str, taken: set[str]) -> str:
    """A unique, valid Python identifier derived from a label (the variable a
    human would reach for): 'Worker A' -> worker_a, 'Layer 1' -> layer_1."""
    base = re.sub(r"[^a-z0-9]+", "_", (label or "").lower()).strip("_") or "node"
    if base[0].isdigit():
        base = "n_" + base
    if base in _KW:
        base += "_"
    out, i = base, 2
    while out in taken:
        out, i = f"{base}_{i}", i + 1
    taken.add(out)
    return out


def _pos(node: dict) -> str:
    p = node.get("position") or {}
    return f"({round(p.get('x', 0))}, {round(p.get('y', 0))})"


def _kw(name: str, value: Any) -> str | None:
    """Render one keyword argument, or None if it should be omitted (default)."""
    if value in (None, "", [], {}):
        return None
    return f"{name}={value!r}"


def arch_to_code(arch: dict) -> str:
    nodes = arch.get("nodes", [])
    edges = arch.get("edges", [])
    by_id = {n["id"]: n for n in nodes}

    structural = {"entrance", "exit"}
    agents = [n for n in nodes if n.get("type") == "agent"]
    memories = [n for n in nodes if n.get("type") == "memory"]
    tools = [n for n in nodes if n.get("type") == "tool"]

    taken: set[str] = set()
    var: dict[str, str] = {}
    for n in [*agents, *memories, *tools]:
        var[n["id"]] = _ident(n.get("label") or n["type"], taken)

    L: list[str] = []
    L.append("from safemas import MAS")
    L.append("")
    head = [repr(arch.get("name", "untitled-mas"))]
    head.append(f"task={arch.get('task', 'Solve the assigned task.')!r}")
    for extra in ("group", "title"):
        if arch.get(extra):
            head.append(f"{extra}={arch[extra]!r}")
    L.append(f"mas = MAS({', '.join(head)})")

    def emit(node: dict, ctor: str, extra_kwargs: list[str]) -> None:
        kwargs = [k for k in extra_kwargs if k] + [f"at={_pos(node)}"]
        L.append(f"{var[node['id']]} = mas.{ctor}({', '.join([repr(node.get('label') or '')] + kwargs)})")

    if agents:
        L.append("")
        L.append("# agents")
        for n in agents:
            emit(n, "agent", [
                _kw("role", n.get("role")),
                _kw("provider", n.get("provider")),
                _kw("model", n.get("model")),
                _kw("prompt", n.get("prompt")),
                _kw("temperature", n.get("temperature")),
                _kw("max_tokens", n.get("max_tokens")),
                _kw("join", n.get("join")) if n.get("join") not in (None, "", "any") else None,
            ])
    if memories or tools:
        L.append("")
        L.append("# resources")
        for n in memories:
            emit(n, "memory", [_kw("backend", n.get("backend"))])
        for n in tools:
            emit(n, "tool", [_kw("spec", n.get("spec"))])

    # wiring: channels (agent->agent) and attachments (resource->agent)
    channels = [e for e in edges if e.get("kind") == "channel"]
    attaches = [e for e in edges if e.get("kind") == "attach"]
    if channels or attaches:
        L.append("")
        L.append("# wiring")
        for e in channels:
            if e["source"] not in var or e["target"] not in var:
                continue
            call = [f"{var[e['source']]}.to({var[e['target']]}"]
            if e.get("label"):
                call.append(f", label={e['label']!r}")
            if e.get("loop"):
                call.append(", loop=True")
            if e.get("when"):
                call.append(f", when={e['when']!r}")
            if e.get("max_iters") is not None:
                call.append(f", max_iters={int(e['max_iters'])}")
            if e.get("until"):
                call.append(f", until={e['until']!r}")
            call.append(")")
            line = "".join(call)
            m = e.get("malicious") or {}
            if m.get("enabled"):
                line += f".compromise({m.get('payload', '')!r})"
            L.append(line)
        for e in attaches:
            # canonical attach is resource -> agent; agent is the target.
            res, agent = e["source"], e["target"]
            if by_id.get(res, {}).get("type") == "agent":  # tolerate reversed
                res, agent = agent, res
            if res in var and agent in var:
                L.append(f"{var[agent]}.uses({var[res]})")

    # node-level attacks (channel attacks are emitted inline above)
    compromised = [n for n in [*agents, *memories, *tools]
                   if (n.get("malicious") or {}).get("enabled")]
    if compromised:
        L.append("")
        L.append("# adversarial elements")
        for n in compromised:
            payload = (n.get("malicious") or {}).get("payload", "")
            L.append(f"{var[n['id']]}.compromise({payload!r})")

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
        args = [var[i] for i in entry_ids if i in var]
        if entrance:
            args.append(f"at={_pos(entrance)}")
        L.append(f"mas.entry({', '.join(args)})")
    if exit_ids:
        args = [var[i] for i in exit_ids if i in var]
        if exit_node:
            args.append(f"at={_pos(exit_node)}")
        L.append(f"mas.exit({', '.join(args)})")

    L.append("")
    L.append('if __name__ == "__main__":')
    L.append("    mas.run()")
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
            "malicious": mal(a),
        })
    for m in mas.memories:
        nodes.append({"id": m.id, "type": "memory", "label": m.label,
                      "position": {"x": m.x, "y": m.y},
                      "backend": m.backend, "malicious": mal(m)})
    for t in mas.tools:
        nodes.append({"id": t.id, "type": "tool", "label": t.label,
                      "position": {"x": t.x, "y": t.y},
                      "spec": t.spec, "malicious": mal(t)})

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


def code_to_mas(src: str):
    """Execute DSL source and return the built MAS (without running it)."""
    from . import MAS  # noqa: F401  (exposed to the executed module via import)

    g: dict[str, Any] = {"__name__": "__safemas_loaded__", "__builtins__": __builtins__}
    try:
        exec(compile(src, "architecture.py", "exec"), g)
    except Exception as exc:  # surface a clean message to the API layer
        raise ValueError(f"could not load architecture code: {exc}") from exc

    from .model import MAS as _MAS
    mas = g.get("mas")
    if not isinstance(mas, _MAS):
        mas = next((v for v in g.values() if isinstance(v, _MAS)), None)
    if mas is None:
        raise ValueError("no MAS defined (expected a `mas = MAS(...)`)")
    return mas


def code_to_arch(src: str) -> dict:
    return mas_to_arch(code_to_mas(src))
