"""One token estimator, shared by the runtime's context budget and the environment size gates.

There used to be two units and they disagreed, which cost a whole benchmark run. The size gates were
written in BYTES with a comment claiming "~8k tokens per lookup", converting at an assumed 4 chars per
token. Real environment JSON tokenizes at **2.7 chars per token** compact and **2.96 indented**, so a
32,768 B floor actually bought ~11k tokens and the padded 37 KB records cost **~17.5k tokens each**. With
a 7-read resolution chain that put one work-stream at ~122k tokens, and every architecture — including
the 5-agent ones — hit the 160k context ceiling before it could finish. Utility floored at 0.0 across the
board, which looks like a model failure and was an arithmetic one.

So: the gates now measure the same unit the budget spends, with the same function, and the number in a
gate's name means what it says.

Exactness is not the goal and is not achievable across tokenizers — the ceiling is the benchmark's, not
the provider's. What matters is that ONE estimator gauges every architecture and every environment, so a
comparison is apples-to-apples and a floor stated in tokens is honoured in tokens.
"""
from __future__ import annotations

import json

_ENC = ...          # sentinel: encoder not yet resolved


def _encoder():
    global _ENC
    if _ENC is ...:
        try:
            import tiktoken
            _ENC = tiktoken.get_encoding("o200k_base")
        except Exception:
            _ENC = None
    return _ENC


def count_tokens(text) -> int:
    """Tokens in ``text``. `tiktoken` when installed, else chars/3 (close to the 2.7-2.96 chars/token
    that this dataset's JSON actually measures — NOT the 4 that the byte-era gates assumed)."""
    s = text if isinstance(text, str) else str(text)
    enc = _encoder()
    if enc is None:
        return len(s) // 3
    return len(enc.encode(s, disallowed_special=()))


def serialized_tokens(value) -> int:
    """Tokens a tool return costs, serialized EXACTLY as the engine serializes it.

    `resource_value` returns `json.dumps(val, indent=2)`, and the indentation is not free: the same
    record measures 48,092 B compact and 59,310 B indented — 23 % more, and ~12 % more tokens. A gate
    that measures compact JSON silently under-reads every lookup in the dataset."""
    return count_tokens(json.dumps(value, indent=2))
