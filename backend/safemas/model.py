"""The SafeMAS DSL — *a multi-agent system, as code*.

A MAS is built fluently and is **self-executing**: the file that defines it can be
run directly (``python architecture.py "task"``) and ``mas.run()`` will execute
the agents, channels and attachments, applying any adversarial elements.

    from safemas import MAS

    mas = MAS("linear-pipeline", task="Write a config reader.")
    planner = mas.agent("Planner", role="planner", at=(100, 150))
    coder   = mas.agent("Coder",   role="worker",  at=(360, 150))
    planner.to(coder, label="plan")
    coder.uses(mas.tool("Search", at=(360, -30)))
    mas.entry(planner, at=(-120, 150))
    mas.exit(coder, at=(620, 150))

    if __name__ == "__main__":
        mas.run()

Every element can be turned adversarial with ``.compromise(payload)``; the attack
type is implied by the element (agent→prompt-injection, channel→aitm,
memory→memory-poisoning, tool→tool-poisoning), mirroring the SafeMAS threat model.

`at=(x, y)` carries the editor layout so the visual canvas round-trips losslessly;
it has no effect on execution.
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

    def __init__(self, mas, label, *, backend="in-memory", at=(0, 0)):
        super().__init__(mas, label, at)
        self.backend = backend


class Tool(Element):
    attack = "tool-poisoning"

    def __init__(self, mas, label, *, spec="", at=(0, 0)):
        super().__init__(mas, label, at)
        self.spec = spec


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
    entry/exit agents, then :meth:`run` it."""

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

    def run(self, task: str | None = None) -> dict:
        """Execute the system. Lazily imports the engine so merely *building* a MAS
        (e.g. to load it into the editor) never pulls the execution dependencies."""
        from .engine import run_mas
        return run_mas(self, task)
