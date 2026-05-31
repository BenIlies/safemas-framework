"""SafeMAS — a multi-agent system, expressed and executed as code.

    from safemas import MAS

The visual editor is one view onto a MAS; the canonical artifact is the Python
file the DSL produces (see :mod:`safemas.model`). Importing this package pulls
only the lightweight model + builder — the execution engine, codegen and loader
are imported lazily / explicitly so the sandboxed runner stays minimal.
"""
from .model import MAS, Agent, Memory, Tool, Element, Channel, Attach, Malicious

__all__ = ["MAS", "Agent", "Memory", "Tool", "Element", "Channel", "Attach", "Malicious"]
