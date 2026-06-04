"""SafeMAS — multi-agent systems described as JSON and executed on LangGraph.

The canonical artifact is the architecture JSON (the editor's wire format). The
execution runtime is :mod:`safemas.graph_runtime`, imported explicitly by the
runner so the package import stays light.
"""

__all__ = ["graph_runtime"]
