#!/usr/bin/env python3
"""Execute a SafeMAS architecture on the LangGraph runtime.

The architecture is the editor's JSON ({name, task, nodes[], edges[]}). This thin
runner hands it to ``safemas.graph_runtime.run_arch``, which builds the run
(real tool-calling agents + the multi-agent topology) and prints the trace.

Designed to run *inside* a Docker container (see Dockerfile), but also runnable
directly as a subprocess when Docker is unavailable.

Inputs:
    * arch:       $SAFEMAS_ARCH  (JSON)  ->  argv[1] .json file  ->  stdin
    * providers:  $SAFEMAS_PROVIDERS (JSON: {id: {api, kind, base_url, api_key, models}})
    * task:       $SAFEMAS_TASK (optional override; otherwise the arch's task)

The runtime prints a human-readable trace plus machine-readable ``__RESULT__``
and ``__SCN__`` JSON lines the backend parses.
"""
from __future__ import annotations

import json
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


def load_arch() -> dict | None:
    env = os.environ.get("SAFEMAS_ARCH")
    if env:
        return json.loads(env)
    path = sys.argv[1] if len(sys.argv) > 1 else "/mas/architecture.json"
    if os.path.exists(path):
        return json.loads(Path(path).read_text())
    data = sys.stdin.read()
    return json.loads(data) if data.strip() else None


def main() -> int:
    try:
        arch = load_arch()
    except json.JSONDecodeError as exc:
        print(f"[error] invalid architecture JSON: {exc}", flush=True)
        return 1
    if not arch or not arch.get("nodes"):
        print("[error] no architecture provided", flush=True)
        return 1
    from safemas.graph_runtime import run_arch
    run_arch(arch, os.environ.get("SAFEMAS_TASK"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
