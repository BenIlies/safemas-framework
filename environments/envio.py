#!/usr/bin/env python3
"""Environment dataset I/O — the single source of truth for the on-disk LAYOUT.

An environment is a FOLDER, one FILE per component, so a 200 kB blob becomes
reviewable, diffable pieces:

    environments/banking/
      env.json                  identity + tool_groups + worklist_payable + the
                                ordered `components` manifest (the index of the env)
      tools/get_iban.json       one tool per file      (name, description, parameters,
                                                        returns, effect)
      state/bank_account.json   one hidden-state store per file (top-level `state` key)
      tasks/user_task_0.json    one graded user task per file (prompt + success spec)
      attacks/direct_injection_task_0.json   one injection task per file

`env.json`'s `components` block lists every component NAME in its canonical
ORDER; the loader resolves each name to `<subdir>/<name>.json`. That keeps the
assembled dict byte-identical to the old flat file (tool order is load-bearing —
`backend/scenario.py` assigns ungrouped write tools to capability slots in tool
order) and gives one place to read off "what is in this environment".

Drift between the manifest and the files is a HARD error (same fail-loud ethos as
`validate_tasks.py`): a component file with no manifest entry, a manifest entry
with no file, or a file whose `name`/`id` disagrees with its filename all raise.
`save_env` rewrites the manifest and prunes orphaned files, so writers
(`validate_tasks.py --rederive`, the harness authoring scripts) stay in sync for
free.

Every consumer (the backend, `validate_tasks.py`, the report harness and analyzer)
loads environments through here instead of globbing the dataset::

    import sys; sys.path.insert(0, "<repo>/environments")
    from envio import env_names, load_env, save_env, iter_envs

CLI::

    python environments/envio.py --check              # round-trip every env
    python environments/envio.py --explode            # flat <name>.json -> folder
    python environments/envio.py --collapse banking   # folder -> flat JSON on stdout
"""
from __future__ import annotations

import json
import os
import re
import sys

ENV_DIR = os.path.dirname(os.path.abspath(__file__))

# Generated artefacts that live in environments/ but are NOT environments.
RESERVED = {"scenarios", "task_flows"}

# Top-level key order of an assembled environment (kept stable so a save never
# reshuffles the file for readers diffing it).
KEY_ORDER = ["name", "title", "note", "tools", "user_tasks", "injection_tasks",
             "state", "tool_groups", "indirection", "worklist_payable", "worklist_tiers"]

# The components split out into their own files: (env key, subdir, identity field).
# identity field None => the value is a dict and each of its top-level keys is a file.
COMPONENTS = [
    ("tools",           "tools",   "name"),
    ("user_tasks",      "tasks",   "id"),
    ("injection_tasks", "attacks", "id"),
    ("state",           "state",   None),
]
_SUBDIRS = [c[1] for c in COMPONENTS]

_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class EnvLayoutError(Exception):
    """The folder on disk does not match the manifest (fail loud, never guess)."""


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #
def env_dir(name: str) -> str:
    return os.path.join(ENV_DIR, name)


def _flat_path(name: str) -> str:
    return os.path.join(ENV_DIR, f"{name}.json")


def is_env_dir(name: str) -> bool:
    return os.path.isfile(os.path.join(env_dir(name), "env.json"))


def env_names() -> list[str]:
    """Every environment in the dataset, sorted. Folder layout plus any legacy
    flat `<name>.json` still lying around (so a hand-dropped file still loads)."""
    names = set()
    for entry in os.listdir(ENV_DIR):
        if entry in RESERVED or entry.startswith("."):
            continue
        if is_env_dir(entry):
            names.add(entry)
        elif entry.endswith(".json") and os.path.isfile(os.path.join(ENV_DIR, entry)):
            stem = entry[:-5]
            if stem not in RESERVED:
                names.add(stem)
    return sorted(names)


def iter_envs():
    """Yield ``(name, env_dict)`` for every environment, in name order."""
    for name in env_names():
        yield name, load_env(name)


# --------------------------------------------------------------------------- #
# load
# --------------------------------------------------------------------------- #
def _read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _component_files(root: str, subdir: str) -> set[str]:
    d = os.path.join(root, subdir)
    if not os.path.isdir(d):
        return set()
    return {f[:-5] for f in os.listdir(d) if f.endswith(".json")}


def load_env(name: str) -> dict | None:
    """Assemble one environment into the flat dict every consumer expects."""
    if is_env_dir(name):
        return _load_exploded(env_dir(name))
    path = _flat_path(name)
    if os.path.isfile(path):
        return _read_json(path)
    return None


def _load_exploded(root: str) -> dict:
    env = _read_json(os.path.join(root, "env.json"))
    manifest = env.pop("components", None)
    if not isinstance(manifest, dict):
        raise EnvLayoutError(f"{root}/env.json: missing the `components` manifest")

    for key, subdir, id_field in COMPONENTS:
        listed = manifest.get(key)
        if listed is None:
            raise EnvLayoutError(f"{root}/env.json: components.{key} is absent")
        if len(set(listed)) != len(listed):
            raise EnvLayoutError(f"{root}/env.json: components.{key} has duplicate entries")

        on_disk = _component_files(root, subdir)
        missing = [n for n in listed if n not in on_disk]
        orphan = sorted(on_disk - set(listed))
        if missing:
            raise EnvLayoutError(f"{root}: components.{key} lists {missing} but "
                                 f"{subdir}/<name>.json is missing")
        if orphan:
            raise EnvLayoutError(f"{root}/{subdir}: {orphan} not listed in "
                                 f"env.json components.{key} (manifest drift)")

        if id_field is None:                       # dict-valued component (state)
            env[key] = {n: _read_json(os.path.join(root, subdir, f"{n}.json")) for n in listed}
        else:                                      # list-valued component
            items = []
            for n in listed:
                item = _read_json(os.path.join(root, subdir, f"{n}.json"))
                if item.get(id_field) != n:
                    raise EnvLayoutError(
                        f"{root}/{subdir}/{n}.json: {id_field}={item.get(id_field)!r} "
                        f"does not match its filename")
                items.append(item)
            env[key] = items

    return {k: env[k] for k in KEY_ORDER if k in env} | {
        k: v for k, v in env.items() if k not in KEY_ORDER}


# --------------------------------------------------------------------------- #
# save
# --------------------------------------------------------------------------- #
def _write_json(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def save_env(name: str, env: dict) -> None:
    """Write an environment back in the layout it currently uses (folder unless
    only a legacy flat file exists). Rewrites the manifest and prunes orphans."""
    if not is_env_dir(name) and os.path.isfile(_flat_path(name)):
        _write_json(_flat_path(name), env)
        return
    explode(env, env_dir(name))


def explode(env: dict, root: str) -> None:
    """Write ``env`` as a folder: env.json + one file per component."""
    os.makedirs(root, exist_ok=True)
    head, manifest = {}, {}
    split = {key: (subdir, id_field) for key, subdir, id_field in COMPONENTS}

    for key, value in env.items():
        if key not in split:
            head[key] = value
            continue
        subdir, id_field = split[key]
        d = os.path.join(root, subdir)
        os.makedirs(d, exist_ok=True)
        if id_field is None:
            items = list(value.items())
        else:
            items = [(item[id_field], item) for item in value]
        names = []
        for cname, body in items:
            if not _SAFE.match(str(cname)):
                raise EnvLayoutError(f"{root}/{subdir}: {cname!r} is not a safe filename")
            names.append(cname)
            _write_json(os.path.join(d, f"{cname}.json"), body)
        manifest[key] = names
        for stale in _component_files(root, subdir) - set(names):
            os.remove(os.path.join(d, f"{stale}.json"))

    for key, subdir, _ in COMPONENTS:
        if key not in manifest:
            raise EnvLayoutError(f"cannot explode {root}: environment has no `{key}`")

    ordered = {k: head[k] for k in KEY_ORDER if k in head}
    ordered.update({k: v for k, v in head.items() if k not in ordered})
    ordered["components"] = manifest
    _write_json(os.path.join(root, "env.json"), ordered)


# --------------------------------------------------------------------------- #
# CLI — migration + round-trip check
# --------------------------------------------------------------------------- #
def _cli(argv: list[str]) -> int:
    if "--collapse" in argv:
        name = argv[argv.index("--collapse") + 1]
        env = load_env(name)
        if env is None:
            print(f"no such environment: {name}", file=sys.stderr)
            return 1
        print(json.dumps(env, indent=2, ensure_ascii=False))
        return 0

    if "--explode" in argv:
        flats = sorted(f for f in os.listdir(ENV_DIR)
                       if f.endswith(".json") and f[:-5] not in RESERVED
                       and os.path.isfile(os.path.join(ENV_DIR, f)))
        if not flats:
            print("nothing to explode — every environment is already a folder")
        for f in flats:
            name = f[:-5]
            before = _read_json(os.path.join(ENV_DIR, f))
            explode(before, env_dir(name))
            after = _load_exploded(env_dir(name))
            if after != before:
                raise EnvLayoutError(f"{name}: round-trip mismatch, refusing to drop {f}")
            os.remove(os.path.join(ENV_DIR, f))
            print(f"{name:<12} -> {name}/  ({len(before['tools'])} tools, "
                  f"{len(before['state'])} stores, {len(before['user_tasks'])} tasks, "
                  f"{len(before['injection_tasks'])} attacks)")
        return 0

    # --check (default): load every env and prove save -> load is identity.
    import tempfile
    bad = 0
    for name in env_names():
        env = load_env(name)
        with tempfile.TemporaryDirectory() as tmp:
            explode(env, os.path.join(tmp, name))
            again = _load_exploded(os.path.join(tmp, name))
        ok = again == env
        bad += not ok
        print(f"{name:<12} {'OK ' if ok else 'MISMATCH'} "
              f"tools={len(env['tools'])} stores={len(env['state'])} "
              f"tasks={len(env['user_tasks'])} attacks={len(env['injection_tasks'])}")
    print(f"\n{len(env_names())} environments, {bad} broken")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
