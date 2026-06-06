"""The SafeMAS DSL — *a multi-agent system, as code*, in the LangGraph idiom.

A MAS is built with a :class:`StateGraph` that reads like LangGraph:

    from safemas import StateGraph

    g = StateGraph("linear-pipeline", task="Write a config reader.")
    g.add_node("Planner", role="planner")
    g.add_node("Coder",   role="worker")
    g.add_node("Search",  type="tool", spec="def search(q: str) -> str")
    g.add_edge("Planner", "Coder", label="plan")
    g.add_edge("Search",  "Coder")              # resource attach
    g.set_entry("Planner")
    g.set_finish("Coder")

The ``StateGraph`` is a thin façade over the underlying :class:`MAS` builder
(nodes are addressed by label). It produces the editor/runtime **architecture
dict** (see :mod:`safemas.codegen`); execution itself lives in
``safemas.graph_runtime`` and consumes that dict — the builder never imports the
runtime, so merely *loading* a template stays lightweight.

Every element can be turned adversarial with ``compromise(...)``; the attack type
is implied by the element (agent→prompt-injection, channel→aitm,
memory→memory-poisoning, tool→tool-poisoning), mirroring the SafeMAS threat
model.

``at=(x, y)`` carries the editor layout so the visual canvas round-trips
losslessly; it has no effect on execution (the runtime re-derives ids from labels
and ignores positions).
"""
from __future__ import annotations

import re
from dataclasses import dataclass


def slug(label: str, taken: set[str]) -> str:
    """A stable, unique, human-readable id derived from a label."""
    base = re.sub(r"[^a-z0-9]+", "-", (label or "").lower()).strip("-") or "node"
    out, i = base, 2
    while out in taken:
        out, i = f"{base}-{i}", i + 1
    taken.add(out)
    return out


@dataclass
class Malicious:
    """An adversarial flag on an element. ``payload`` is the injected/poisoned
    content (for a channel, the AiTM rewrite applied to passing messages)."""

    enabled: bool = False
    attack: str | None = None
    payload: str = ""


class Element:
    """Base for the canvas nodes: agents, memory stores and tools."""

    attack: str | None = None  # the attack this element type carries

    def __init__(self, mas: "MAS", label: str, at: tuple[float, float] = (0, 0)):
        self.mas = mas
        self.label = label
        self.x, self.y = at
        self.malicious = Malicious()
        self.id = slug(label, mas._ids)

    def compromise(self, payload: str = "", attack: str | None = None) -> "Element":
        """Mark this element adversarial. The attack defaults to the one its type
        carries (prompt-injection / memory-poisoning / tool-poisoning)."""
        self.malicious = Malicious(True, attack or self.attack, payload)
        return self


class Agent(Element):
    attack = "prompt-injection"

    def __init__(self, mas, label, *, provider=None, model=None, role=None,
                 prompt=None, temperature=None, max_tokens=None, join="any",
                 at=(0, 0)):
        super().__init__(mas, label, at)
        self.provider = provider
        self.model = model
        self.role = role
        self.prompt = prompt
        self.temperature = temperature
        self.max_tokens = max_tokens
        # How this agent consumes multiple inbound channels: "any" runs as soon as
        # one message arrives (a relay); "all" waits for every inbound channel and
        # aggregates them in one call (a real join / aggregator).
        self.join = join or "any"

    def to(self, other: "Agent", label: str = "", loop: bool = False, *,
           when: str = "", max_iters: int | None = None, until: str = "") -> "Channel":
        """Open a message channel from this agent to ``other`` (agent → agent).

        Control flow (all optional, all backward compatible):
          * ``when``      – a guard: the transition is taken only when the source
                            output contains this phrase. A node with guarded edges
                            becomes a *router* (it selects one branch, in order).
          * ``loop``      – a feedback edge that re-runs its target. Bounded by
                            ``max_iters`` (default 3) and short-circuited when the
                            source output contains ``until``.
          * ``max_iters`` – cap on how many times a ``loop`` edge fires.
          * ``until``     – stop the loop early once the source output matches.
        """
        ch = Channel(self, other, label, loop, when=when, max_iters=max_iters, until=until)
        self.mas.channels.append(ch)
        return ch

    def uses(self, resource: "Element") -> "Attach":
        """Give this agent access to a memory store or tool (resource ⇒ agent)."""
        att = Attach(resource, self)
        self.mas.attachments.append(att)
        return att


class Memory(Element):
    attack = "memory-poisoning"

    def __init__(self, mas, label, *, backend="in-memory", content="", at=(0, 0)):
        super().__init__(mas, label, at)
        self.backend = backend
        # What the store yields when an agent reads it (e.g. an AgentDojo dump).
        # Empty => the runtime's neutral placeholder.
        self.content = content


class Tool(Element):
    attack = "tool-poisoning"

    def __init__(self, mas, label, *, spec="", content="", at=(0, 0)):
        super().__init__(mas, label, at)
        self.spec = spec
        # What the tool returns when called. Empty => neutral placeholder.
        self.content = content


class Channel:
    """A directed message link, agent → agent.

    ``loop=True`` marks a feedback / revision edge (rendered as an amber ↺ loop),
    bounded by ``max_iters`` and ``until``. ``when`` is a guard that turns the
    source agent into a router (it takes the first edge whose guard matches)."""

    attack = "aitm"

    def __init__(self, src: Agent, tgt: Agent, label: str = "", loop: bool = False,
                 *, when: str = "", max_iters: int | None = None, until: str = ""):
        self.src = src
        self.tgt = tgt
        self.label = label
        self.loop = loop
        self.when = when            # guard phrase ("" = unconditional)
        self.max_iters = max_iters  # loop bound (None = engine default)
        self.until = until          # loop stop phrase ("" = run to max_iters)
        self.malicious = Malicious()

    def compromise(self, payload: str = "", attack: str | None = None) -> "Channel":
        self.malicious = Malicious(True, attack or self.attack, payload)
        return self


class Attach:
    """A resource (memory/tool) wired to an agent. Undirected by intent; stored
    canonically as resource → agent."""

    def __init__(self, resource: Element, agent: Agent):
        self.resource = resource
        self.agent = agent


class MAS:
    """A multi-agent system. Build it with :meth:`agent` / :meth:`memory` /
    :meth:`tool`, wire it with ``a.to(b)`` and ``a.uses(resource)``, mark the
    entry/exit agents. Serialise it to the architecture dict via
    :func:`safemas.codegen.mas_to_arch`; execution is the runtime's job."""

    def __init__(self, name: str = "untitled-mas",
                 task: str = "Solve the assigned task.", *,
                 group: str = "", title: str = ""):
        self.name = name
        self.task = task
        self.group = group   # editor-only: Templates menu grouping
        self.title = title   # editor-only: Templates menu display label
        self._ids: set[str] = set()
        self.agents: list[Agent] = []
        self.memories: list[Memory] = []
        self.tools: list[Tool] = []
        self.channels: list[Channel] = []
        self.attachments: list[Attach] = []
        self.entries: list[Agent] = []
        self.exits: list[Agent] = []
        self.entry_at: tuple[float, float] | None = None
        self.exit_at: tuple[float, float] | None = None

    def agent(self, label: str, **kw) -> Agent:
        a = Agent(self, label, **kw)
        self.agents.append(a)
        return a

    def memory(self, label: str, **kw) -> Memory:
        m = Memory(self, label, **kw)
        self.memories.append(m)
        return m

    def tool(self, label: str, **kw) -> Tool:
        t = Tool(self, label, **kw)
        self.tools.append(t)
        return t

    def entry(self, *agents: Agent, at: tuple[float, float] | None = None) -> None:
        """Mark the agent(s) the entrance feeds the task to. ``at`` positions the
        entrance node on the canvas."""
        self.entries.extend(agents)
        if at is not None:
            self.entry_at = tuple(at)

    def exit(self, *agents: Agent, at: tuple[float, float] | None = None) -> None:
        """Mark the agent(s) whose output the exit collects. ``at`` positions the
        exit node on the canvas."""
        self.exits.extend(agents)
        if at is not None:
            self.exit_at = tuple(at)

    @property
    def elements(self) -> list[Element]:
        return [*self.agents, *self.memories, *self.tools]


# --------------------------------------------------------------------------- #
# StateGraph — the LangGraph-idiom façade over MAS
# --------------------------------------------------------------------------- #
_RESOURCE_TYPES = {"memory", "tool"}


class StateGraph:
    """Build a SafeMAS architecture in the native LangGraph idiom.

    Nodes are addressed by **label**::

        g = StateGraph("debate", task="...")
        g.add_node("Pro", role="debater")
        g.add_node("Con", role="debater")
        g.add_node("Judge", role="judge", join="all")
        g.add_edge("Pro", "Judge", label="argument")
        g.add_conditional_edge("Judge", "Pro", loop=True, max_iters=3, until="verdict")
        g.set_entry("Pro"); g.set_finish("Judge")

    It is a thin wrapper over :class:`MAS`: every SafeMAS field rides as a kwarg,
    while loops / routers / joins / attachments map onto the underlying topology.
    The produced architecture is consumed by ``safemas.graph_runtime``.
    """

    def __init__(self, name: str = "untitled-mas", *,
                 task: str = "Solve the assigned task.",
                 group: str = "", title: str = ""):
        self._mas = MAS(name, task=task, group=group, title=title)
        self._by_label: dict[str, Element] = {}
        self._n_agents = 0
        self._n_resources = 0

    # -- internals ---------------------------------------------------------- #
    @property
    def mas(self) -> MAS:
        return self._mas

    def _resolve(self, label) -> Element:
        if isinstance(label, Element):
            return label
        el = self._by_label.get(label)
        if el is None:
            raise ValueError(f"unknown node {label!r} (add it with add_node first)")
        return el

    def _auto_pos(self, type: str) -> tuple[float, float]:
        """A deterministic fallback layout for code that omits ``at=``. Positions
        never affect execution; this only keeps the canvas readable."""
        if type == "agent":
            x = 120 + 240 * self._n_agents
            self._n_agents += 1
            return (x, 160)
        x = 120 + 240 * self._n_resources
        self._n_resources += 1
        return (x, 340 if type == "memory" else -20)

    # -- nodes -------------------------------------------------------------- #
    def add_node(self, label: str, *, type: str = "agent",
                 role=None, prompt=None, provider=None, model=None,
                 temperature=None, max_tokens=None, join="any",
                 backend="in-memory", spec="", content="",
                 at: tuple[float, float] | None = None) -> Element:
        if label in self._by_label:
            raise ValueError(f"duplicate node label {label!r}")
        pos = tuple(at) if at is not None else self._auto_pos(type)
        if type == "agent":
            el: Element = self._mas.agent(
                label, role=role, prompt=prompt, provider=provider, model=model,
                temperature=temperature, max_tokens=max_tokens, join=join, at=pos)
        elif type == "memory":
            el = self._mas.memory(label, backend=backend, content=content, at=pos)
        elif type == "tool":
            el = self._mas.tool(label, spec=spec, content=content, at=pos)
        else:
            raise ValueError(f"unknown node type {type!r}")
        self._by_label[label] = el
        return el

    # -- edges -------------------------------------------------------------- #
    def add_edge(self, source, target, *, label: str = "") -> None:
        """A plain edge: an agent→agent channel, or — when either endpoint is a
        memory/tool — a resource attachment (canonicalised resource→agent)."""
        s, t = self._resolve(source), self._resolve(target)
        s_res = isinstance(s, (Memory, Tool))
        t_res = isinstance(t, (Memory, Tool))
        if s_res or t_res:
            if s_res and t_res:
                raise ValueError("cannot wire two resources together")
            resource, agent = (s, t) if s_res else (t, s)
            agent.uses(resource)
            return
        s.to(t, label=label)

    def add_conditional_edge(self, source, target, *, label: str = "",
                             when: str = "", loop: bool = False,
                             max_iters: int | None = None, until: str = "") -> None:
        """A control-flow channel: a router branch (``when=`` guard) and/or a
        feedback loop (``loop=True`` with ``max_iters``/``until``)."""
        s, t = self._resolve(source), self._resolve(target)
        s.to(t, label=label, loop=loop, when=when, max_iters=max_iters, until=until)

    # LangGraph spells it add_conditional_edges; accept both.
    add_conditional_edges = add_conditional_edge

    # -- entry / exit ------------------------------------------------------- #
    def set_entry(self, *labels, at: tuple[float, float] | None = None) -> None:
        self._mas.entry(*[self._resolve(l) for l in labels], at=at)

    def set_finish(self, *labels, at: tuple[float, float] | None = None) -> None:
        self._mas.exit(*[self._resolve(l) for l in labels], at=at)

    # LangGraph familiar aliases.
    set_entry_point = set_entry
    set_finish_point = set_finish

    # -- adversarial -------------------------------------------------------- #
    def compromise(self, target, payload: str = "", attack: str | None = None,
                   *, to=None) -> None:
        """Mark a node adversarial, or — when ``to=`` is given — the channel from
        ``target`` to ``to``."""
        if to is not None:
            s, t = self._resolve(target), self._resolve(to)
            ch = next((c for c in self._mas.channels if c.src is s and c.tgt is t), None)
            if ch is None:
                raise ValueError(f"no channel {getattr(s, 'label', s)!r} -> "
                                 f"{getattr(t, 'label', t)!r} to compromise")
            ch.compromise(payload, attack)
        else:
            self._resolve(target).compromise(payload, attack)
