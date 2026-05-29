"""Data model for a SafeMAS architecture.

A multi-agent system is a graph of *nodes* (agents, memory stores, tools) wired
together by *edges* (channels between agents, or attachments of memory/tools to
an agent). Any element may be flagged ``malicious`` to test the safety of the
architecture, following the threat model:

    agent   -> prompt-injection   (direct prompt at one agent)
    channel -> aitm               (agent-in-the-middle message rewrite)
    memory  -> memory-poisoning   (poisoned knowledge/long-term memory)
    tool    -> tool-poisoning     (MCP / tool supply-chain compromise)

The canonical persisted form is YAML. The same structure round-trips to the
React Flow graph the frontend renders, so "the architecture is the code".

LLM credentials live in a separate :class:`Provider` registry (see
``providers.py``) so the same architecture can be shared without leaking keys —
an agent only references a provider by id.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

NodeType = Literal["agent", "memory", "tool"]
EdgeKind = Literal["channel", "attach"]
AttackType = Literal[
    "prompt-injection",
    "aitm",
    "memory-poisoning",
    "tool-poisoning",
]
ProviderKind = Literal["openai", "anthropic", "openai-compatible", "mock"]


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
    entry: bool = False  # is this an entry agent (receives the task)?

    # memory-specific
    backend: Optional[str] = None  # e.g. in-memory, vector, redis

    # tool-specific
    spec: Optional[str] = None  # tool description / signature

    malicious: Malicious = Field(default_factory=Malicious)


class Edge(BaseModel):
    id: str
    source: str
    target: str
    kind: EdgeKind = "channel"
    label: str = ""
    malicious: Malicious = Field(default_factory=Malicious)


class Architecture(BaseModel):
    name: str = "untitled-mas"
    version: int = 1
    task: str = "Solve the assigned task."
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)

    def to_yaml_dict(self) -> dict[str, Any]:
        """Compact dict for YAML: drop empty/false fields for readability."""

        def clean(d: dict[str, Any]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for k, v in d.items():
                if v in (None, "", [], {}):
                    continue
                if k == "malicious" and not v.get("enabled"):
                    continue
                if k == "entry" and v is False:
                    continue
                out[k] = v
            return out

        return {
            "name": self.name,
            "version": self.version,
            "task": self.task,
            "nodes": [clean(n.model_dump()) for n in self.nodes],
            "edges": [clean(e.model_dump()) for e in self.edges],
        }


# --------------------------------------------------------------------------- #
# Provider registry (LLM credentials)
# --------------------------------------------------------------------------- #
class Provider(BaseModel):
    """A configured LLM endpoint. The ``api_key`` is stored server-side only and
    never returned to the client (see :class:`ProviderPublic`)."""

    id: str
    name: str = "provider"
    kind: ProviderKind = "openai"
    base_url: str = ""           # for openai-compatible / self-hosted endpoints
    api_key: str = ""            # secret — persisted locally, never serialised out
    models: list[str] = Field(default_factory=list)


class ProviderPublic(BaseModel):
    """What the client sees: everything except the secret key."""

    id: str
    name: str
    kind: ProviderKind
    base_url: str = ""
    models: list[str] = Field(default_factory=list)
    has_key: bool = False

    @classmethod
    def of(cls, p: Provider) -> "ProviderPublic":
        return cls(
            id=p.id,
            name=p.name,
            kind=p.kind,
            base_url=p.base_url,
            models=p.models,
            has_key=bool(p.api_key),
        )


class ProviderInput(BaseModel):
    """Create/update payload. ``api_key`` is optional on update — when omitted or
    blank the previously stored key is kept (so the UI never re-sends it)."""

    name: str = "provider"
    kind: ProviderKind = "openai"
    base_url: str = ""
    api_key: Optional[str] = None
    models: list[str] = Field(default_factory=list)
