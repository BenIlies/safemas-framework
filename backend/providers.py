"""Local registry of LLM providers (endpoints + API keys).

Keys are persisted to ``secrets.json`` next to this file. That file is
gitignored and the keys are *never* returned over the API — clients only ever
see :class:`ProviderPublic` (name, kind, base_url, models, has_key). This is the
"select a recorded provider without re-typing the key" feature: the UI stores a
provider once, then agents reference it by id.

Storage is plaintext-on-disk, which is appropriate for a local single-user dev
tool. Do not point this at a shared/multi-tenant deployment without adding
encryption-at-rest and auth.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path

from schema import Provider, ProviderInput

BASE = Path(__file__).resolve().parent
# Override with SAFEMAS_SECRETS (e.g. a mounted volume path) for persistence.
STORE = Path(os.environ.get("SAFEMAS_SECRETS", str(BASE / "secrets.json")))
STORE.parent.mkdir(parents=True, exist_ok=True)
_LOCK = threading.Lock()


def _load() -> dict[str, Provider]:
    if not STORE.exists():
        return {}
    try:
        raw = json.loads(STORE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    out: dict[str, Provider] = {}
    for item in raw.get("providers", []):
        try:
            p = Provider(**item)
            out[p.id] = p
        except Exception:
            continue
    return out


def _save(providers: dict[str, Provider]) -> None:
    payload = {"providers": [p.model_dump() for p in providers.values()]}
    tmp = STORE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(STORE)
    try:
        STORE.chmod(0o600)  # keys are sensitive
    except OSError:
        pass


def all_providers() -> list[Provider]:
    with _LOCK:
        return list(_load().values())


def get(provider_id: str) -> Provider | None:
    with _LOCK:
        return _load().get(provider_id)


def create(data: ProviderInput) -> Provider:
    with _LOCK:
        providers = _load()
        pid = f"prov-{uuid.uuid4().hex[:8]}"
        p = Provider(
            id=pid,
            name=data.name,
            kind=data.kind,
            base_url=data.base_url,
            api_key=data.api_key or "",
            models=data.models,
        )
        providers[pid] = p
        _save(providers)
        return p


def update(provider_id: str, data: ProviderInput) -> Provider | None:
    with _LOCK:
        providers = _load()
        existing = providers.get(provider_id)
        if not existing:
            return None
        # Blank/omitted api_key => keep the stored one (UI never re-sends it).
        key = data.api_key if (data.api_key not in (None, "")) else existing.api_key
        updated = Provider(
            id=provider_id,
            name=data.name,
            kind=data.kind,
            base_url=data.base_url,
            api_key=key,
            models=data.models,
        )
        providers[provider_id] = updated
        _save(providers)
        return updated


def delete(provider_id: str) -> bool:
    with _LOCK:
        providers = _load()
        if provider_id in providers:
            del providers[provider_id]
            _save(providers)
            return True
        return False


def resolved_map() -> dict[str, dict]:
    """Provider map (including keys) for handing to the runner at execution time.

    Shape: ``{id: {kind, base_url, api_key, models}}``. Stays server-side; only
    crosses into the sandboxed runner via env.
    """
    with _LOCK:
        return {
            p.id: {
                "kind": p.kind,
                "base_url": p.base_url,
                "api_key": p.api_key,
                "models": p.models,
            }
            for p in _load().values()
        }
