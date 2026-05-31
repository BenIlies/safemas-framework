#!/usr/bin/env python3
"""Execute a SafeMAS architecture by *running its code*.

The architecture is SafeMAS DSL Python (see the ``safemas`` package). This thin
runner takes that source and executes it as ``__main__`` — so the file's
``if __name__ == "__main__": mas.run()`` fires and the multi-agent system runs,
exactly as if you had typed ``python architecture.py``.

Designed to run *inside* a Docker container (see Dockerfile), but also runnable
directly as a subprocess when Docker is unavailable.

Inputs (in priority order, so the same image works mounted or socket-spawned):
    * code:       $SAFEMAS_CODE  ->  argv[1] file  ->  /mas/architecture.py  ->  stdin
    * providers:  $SAFEMAS_PROVIDERS (JSON: {id: {api, kind, base_url, api_key, models}})
    * task:       $SAFEMAS_TASK (optional override; otherwise the code's task)

The engine prints a human-readable trace plus a machine-readable ``__RESULT__``
JSON line the backend parses.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the `safemas` library importable both in the container (it sits beside this
# file) and as a local subprocess (it lives in the parent backend/ directory).
HERE = Path(__file__).resolve().parent
for candidate in (HERE, HERE.parent):
    if (candidate / "safemas").is_dir():
        sys.path.insert(0, str(candidate))
        break


def load_code() -> str:
    env = os.environ.get("SAFEMAS_CODE")
    if env:
        return env
    path = sys.argv[1] if len(sys.argv) > 1 else "/mas/architecture.py"
    if os.path.exists(path):
        return Path(path).read_text()
    return sys.stdin.read()


def main() -> int:
    code = load_code()
    if not code.strip():
        print("[error] no architecture code provided", flush=True)
        return 1
    # Execute as a real program so `if __name__ == '__main__': mas.run()` fires.
    g = {"__name__": "__main__", "__builtins__": __builtins__}
    exec(compile(code, "architecture.py", "exec"), g)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
