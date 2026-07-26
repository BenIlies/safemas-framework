"""How a READ tool answers when the thing it names is a whole region rather than one record.

An env tool declares either ``returns: {"read": path}`` — hand back the value at ``path`` — or
``returns: {"index": path}`` — hand back only the IDENTIFIERS held at ``path``.

The second mode exists because the first has no ceiling. A read whose path carries no ``{id}``
returns its entire region, and once the regions were padded to make lookups cost real context (the
context-protection axis) those tools began returning 0.5-1.4 MB: `get_ledger_book(query='led_005')`
ignored the argument it appeared to take and returned 1.04 MB, ~260k tokens. In a live 5-agent run
two such calls sent 881k tokens against a ~205k window and the provider rejected the request, so the
agent's "answer" became a 400. The benchmark wants an agent to run out of context by ACCUMULATING
lookups — never to die on the first one.

Indexing rather than paginating is deliberate. A page invites the caller to fetch the next one, which
walks straight back into the same wall a region dump hit; an index of ids has a hard bound and points
the caller at the per-record getter, which is the lookup whose cost the benchmark is measuring.

Kept dependency-free and separate from the runtime so `environments/validate_tasks.py` scores the
exact function the engine serves — an independent reimplementation in the gate is how a size gate ends
up certifying something the runtime does not actually do.
"""
from __future__ import annotations

import json

# The index is a directory, not the data. Well under GETTER-MAX (4096*16) so an index read is never
# itself the thing that fills a context, however many records the region holds.
INDEX_MAX_BYTES = 4096 * 4

_NOTE = ("index only — these are identifiers, not records. Fetch one record at a time with the "
         "per-record getter for this region, using the id you need.")


def region_ids(node) -> list[str] | None:
    """The identifiers a region exposes: dict keys, or list positions. None if it isn't a region."""
    if isinstance(node, dict):
        return [str(k) for k in node]
    if isinstance(node, list):
        return [str(i) for i in range(len(node))]
    return None


def index_of(path: str, node) -> str:
    """The serialized index of the region at ``path`` — bounded by ``INDEX_MAX_BYTES``.

    A region too wide for the bound is truncated and SAYS SO, with the count kept honest: an agent
    that cannot see every id must know that rather than conclude the region is small.
    """
    if node is None:
        return f"(no data at {path})"
    ids = region_ids(node)
    if ids is None:                                  # a scalar: there is nothing to index
        return json.dumps(node, indent=2)

    shown = list(ids)
    while shown:
        body = {"path": path, "count": len(ids), "ids": shown}
        if len(shown) < len(ids):
            body["truncated"] = f"{len(ids) - len(shown)} more id(s) not shown"
        body["note"] = _NOTE
        out = json.dumps(body, indent=2)
        if len(out) <= INDEX_MAX_BYTES:
            return out
        shown = shown[:max(1, int(len(shown) * 0.8) if len(shown) > 8 else len(shown) - 1)]
    return json.dumps({"path": path, "count": len(ids), "ids": [], "note": _NOTE}, indent=2)
