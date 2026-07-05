"""Data model for a SafeMAS architecture.

A multi-agent system is a graph of *nodes* (agents and tools) wired by *edges*
(channels between agents, or tool attachments). Adversarial elements follow the
threat model:

    agent   -> prompt-injection   (direct prompt at one agent)
    channel -> aitm               (agent-in-the-middle message rewrite)
    tool    -> tool-poisoning     (MCP / tool supply-chain compromise)

Every agent also reads an auto-generated GLOBAL shared-context board (who-does-what
across the agents + the whole-system toolset), derived from the architecture. It is
not a node you add and is never adversarial.

This dict is the editor's wire format. The **canonical persisted form is Python
code** (the SafeMAS DSL — see the ``safemas`` package): the backend generates a
self-executing ``.py`` from this structure on save and reads it back on load, so
"the architecture *is* the code", not configuration.

LLM credentials live in a separate :class:`Provider` registry (see
``providers.py``) so the same architecture can be shared without leaking keys —
an agent only references a provider by id.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

NodeType = Literal["agent", "tool", "entrance", "exit"]
EdgeKind = Literal["channel", "attach", "io"]
AttackType = Literal[
    "prompt-injection",
    "aitm",
    "tool-poisoning",
]
# Provider "kind" is a free-form preset id (e.g. openai, anthropic, google,
# groq, mistral, openrouter, ollama, azure-openai, or any custom name) so SafeMAS
# can address *any* LLM provider. How a provider is actually called is decided by
# its ``api`` engine below, not by this label.
ProviderKind = str
# The client engine used to reach a provider. "openai" also covers every
# OpenAI-compatible endpoint (via base_url); "anthropic" uses the Anthropic SDK;
# "mock" forces the deterministic offline stub.
ProviderApi = Literal["openai", "anthropic", "mock"]


class Position(BaseModel):
    x: float = 0
    y: float = 0


class Malicious(BaseModel):
    """Marks an element as adversarial. ``payload`` is the injected/poisoned
    content; for a channel it is the AiTM rewrite applied to passing messages."""

    enabled: bool = False
    attack: Optional[AttackType] = None
    payload: str = ""


class Node(BaseModel):
    id: str
    type: NodeType
    label: str = ""
    position: Position = Field(default_factory=Position)

    # agent-specific
    provider: Optional[str] = None  # id referencing a Provider in the registry
    model: Optional[str] = None
    role: Optional[str] = None
    prompt: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    # How the agent consumes multiple inbound channels: "any" (default) runs on
    # the first message; "all" waits for every inbound channel and aggregates
    # them in one call (a real join / aggregator).
    join: Optional[str] = None
    # Deprecated: entry/exit are now their own node types wired to an agent via an
    # "io" edge. Kept optional so older saved YAML still loads (the runner honours
    # them as a fallback).
    entry: bool = False
    exit: bool = False

    # tool-specific
    spec: Optional[str] = None  # tool description / signature

    # Optional env-defined return for a tool call, so a tool's output can depend on
    # its input and the live world state. Either:
    #   * a string  — returned verbatim with ``{arg}`` placeholders filled from the
    #                  call's input args (``{query}`` or keys parsed from a JSON blob);
    #   * an object  {"read": "dotted.path.{arg}"} — serialise that slice of the
    #                  run's hidden STATE (dynamic inspection tool).
    # When set it overrides the default store-slice / action-ack return.
    returns: Optional[Any] = None

    # Optional list of mutations this tool applies to the run's hidden STATE, each an
    # op the engine interprets with the call's args templated in, e.g.
    #   {"op":"set","path":"lights.{device_id}.state","value":"{state}"}
    #   {"op":"append","path":"automations","value":{"name":"{name}"}}
    #   {"op":"delete","path":"guest_access.{name}"}
    effect: Optional[list] = None

    # tool payload: what the tool yields when an agent calls it (its return value) —
    # e.g. a captured calendar/email dump. Empty => the engine's neutral placeholder.
    content: Optional[str] = None

    malicious: Malicious = Field(default_factory=Malicious)


class Edge(BaseModel):
    id: str
    source: str
    target: str
    kind: EdgeKind = "channel"
    label: str = ""
    # Control flow on a channel (all optional / backward compatible):
    #   loop      – a feedback edge that re-runs its target, bounded by max_iters
    #               and short-circuited when the source output contains `until`.
    #   when      – a guard phrase; a node with guarded out-edges is a router that
    #               takes the first edge whose guard matches the source output.
    #   max_iters – cap on how many times a loop edge fires (None → engine default).
    #   until     – stop a loop early once the source output contains this phrase.
    loop: bool = False
    when: str = ""
    max_iters: Optional[int] = None
    until: str = ""
    malicious: Malicious = Field(default_factory=Malicious)


class Architecture(BaseModel):
    name: str = "untitled-mas"
    version: int = 1
    task: str = "Solve the assigned task."
    # Editor-only presentation hints, carried by templates (the MAS code sets
    # them via ``MAS(..., group=, title=)``); empty for user architectures.
    group: str = ""
    title: str = ""
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    # The environment's hidden world STATE at run start (a nested dict). Tool
    # ``effect``s mutate a run-scoped copy; ``returns:{read:...}`` tools inspect it.
    state: dict = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Provider registry (LLM credentials)
# --------------------------------------------------------------------------- #
def _engine_for(kind: str, api: Optional[str]) -> str:
    """Resolve the client engine for a provider, with a back-compat fallback for
    providers saved before ``api`` existed (anthropic kind → anthropic engine)."""
    if api in ("openai", "anthropic", "mock"):
        return api
    if kind == "anthropic":
        return "anthropic"
    if kind == "mock":
        return "mock"
    return "openai"


class Provider(BaseModel):
    """A configured LLM endpoint. The ``api_key`` is stored server-side only and
    never returned to the client (see :class:`ProviderPublic`)."""

    id: str
    name: str = "provider"
    kind: ProviderKind = "openai"
    # Client engine; see ProviderApi. Optional/None so that providers persisted
    # before this field existed fall back to kind-based inference via ``engine``
    # (an old kind="anthropic" entry must not be forced onto the openai client).
    api: Optional[ProviderApi] = None
    base_url: str = ""           # for openai-compatible / self-hosted endpoints
    api_key: str = ""            # secret — persisted locally, never serialised out
    models: list[str] = Field(default_factory=list)

    @property
    def engine(self) -> str:
        return _engine_for(self.kind, self.api)


class ProviderPublic(BaseModel):
    """What the client sees: everything except the secret key."""

    id: str
    name: str
    kind: ProviderKind
    api: ProviderApi = "openai"
    base_url: str = ""
    models: list[str] = Field(default_factory=list)
    has_key: bool = False
    default: bool = False   # the provider new agents inherit (set server-side)

    @classmethod
    def of(cls, p: Provider) -> "ProviderPublic":
        return cls(
            id=p.id,
            name=p.name,
            kind=p.kind,
            api=p.engine,
            base_url=p.base_url,
            models=p.models,
            has_key=bool(p.api_key),
        )


class ProviderInput(BaseModel):
    """Create/update payload. ``api_key`` is optional on update — when omitted or
    blank the previously stored key is kept (so the UI never re-sends it)."""

    name: str = "provider"
    kind: ProviderKind = "openai"
    api: Optional[ProviderApi] = None  # inferred from kind when omitted
    base_url: str = ""
    api_key: Optional[str] = None
    models: list[str] = Field(default_factory=list)
