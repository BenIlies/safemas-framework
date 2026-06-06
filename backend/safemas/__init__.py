"""SafeMAS — a multi-agent system, expressed as code in the LangGraph idiom.

    from safemas import StateGraph

The visual editor is one view onto a graph; the canonical artifact is the Python
file the DSL produces (see :mod:`safemas.model`). Importing this package pulls
only the lightweight model + builder — the execution runtime
(``safemas.graph_runtime``), codegen and loader are imported lazily / explicitly
so the sandboxed runner stays minimal.
"""
from .model import (
    MAS, StateGraph, Agent, Memory, Tool, Element, Channel, Attach, Malicious,
)

__all__ = [
    "StateGraph", "MAS", "Agent", "Memory", "Tool", "Element",
    "Channel", "Attach", "Malicious",
]
